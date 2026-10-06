"""Paired discrete-event cost models for four consensus mechanisms."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from math import log
from random import Random

from .consensus import RSU, elect_hybrid_leader, make_rsus, run_pbft_round


class ConsensusMethod(str, Enum):
    POW = "pow"
    POS = "pos"
    POW_PBFT = "pow_pbft"
    HYBRID_POS_PBFT = "hybrid_pos_pbft"


@dataclass(frozen=True)
class ConsensusSimulationConfig:
    num_rsus: int = 10
    actual_byzantine_rsus: int = 0
    payload_bytes_per_message: int = 512
    block_header_bytes: int = 1024
    signature_bytes: int = 64
    audit_message_bytes: int = 128
    confirmation_message_bytes: int = 96
    bandwidth_bps: float = 20_000_000.0
    one_way_latency_ms: float = 5.0
    link_jitter_ms: float = 1.0
    serialization_ms_per_message: float = 0.25
    hash_ms_per_message: float = 0.02
    validation_ms_per_message: float = 0.45
    signature_sign_ms: float = 0.20
    signature_verify_ms: float = 0.40
    election_ms_per_rsu: float = 0.10
    pow_expected_hashes: int = 2**22
    pow_hash_rate_per_rsu: float = 250_000.0

    def __post_init__(self) -> None:
        if self.num_rsus < 4:
            raise ValueError("num_rsus must be at least four")
        if not 0 <= self.actual_byzantine_rsus <= self.max_byzantine:
            raise ValueError("actual_byzantine_rsus must not exceed f")
        positive = (
            self.payload_bytes_per_message,
            self.block_header_bytes,
            self.signature_bytes,
            self.audit_message_bytes,
            self.confirmation_message_bytes,
            self.bandwidth_bps,
            self.pow_expected_hashes,
            self.pow_hash_rate_per_rsu,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("size, bandwidth, work and hash-rate values must be positive")

    @property
    def max_byzantine(self) -> int:
        return (self.num_rsus - 1) // 3

    def to_dict(self) -> dict:
        output = asdict(self)
        output["max_byzantine"] = self.max_byzantine
        return output


@dataclass(frozen=True)
class TrialFactors:
    bandwidth_multiplier: float
    cpu_multiplier: float
    link_latency_ms: float


@dataclass(frozen=True)
class ConsensusRunResult:
    method: str
    message_count: int
    run: int
    seed: int
    broadcast_time_s: float
    consensus_time_s: float
    total_confirmation_time_s: float
    committed: int
    leader_id: int
    leader_state_before: str
    max_byzantine: int
    actual_byzantine: int
    protocol_message_count: int
    protocol_bytes: int
    block_bytes: int
    mining_time_s: float
    election_time_s: float
    validation_time_s: float
    protocol_network_time_s: float


class ConsensusBenchmark:
    """Fair paired simulator with shared workload/network/CPU trial factors."""

    def __init__(self, config: ConsensusSimulationConfig | None = None) -> None:
        self.config = config or ConsensusSimulationConfig()

    @staticmethod
    def _clamp(value: float, low: float, high: float) -> float:
        return min(high, max(low, value))

    def trial_factors(self, seed: int) -> TrialFactors:
        rng = Random(seed)
        return TrialFactors(
            bandwidth_multiplier=self._clamp(rng.gauss(1.0, 0.03), 0.85, 1.15),
            cpu_multiplier=self._clamp(rng.gauss(1.0, 0.03), 0.85, 1.15),
            link_latency_ms=max(
                0.0,
                rng.gauss(self.config.one_way_latency_ms, self.config.link_jitter_ms),
            ),
        )

    def block_bytes(self, message_count: int) -> int:
        if message_count < 1:
            raise ValueError("message_count must be positive")
        return (
            message_count * self.config.payload_bytes_per_message
            + self.config.block_header_bytes
        )

    def broadcast_time(self, message_count: int, factors: TrialFactors) -> float:
        block_bytes = self.block_bytes(message_count)
        serialization_s = (
            message_count
            * self.config.serialization_ms_per_message
            * factors.cpu_multiplier
            / 1000.0
        )
        transfer_s = (
            block_bytes
            * 8.0
            / (self.config.bandwidth_bps * factors.bandwidth_multiplier)
        )
        return serialization_s + transfer_s + factors.link_latency_ms / 1000.0

    def _validation_time(self, message_count: int, factors: TrialFactors) -> float:
        per_message_ms = (
            self.config.hash_ms_per_message
            + self.config.validation_ms_per_message
        )
        return message_count * per_message_ms * factors.cpu_multiplier / 1000.0

    def _pow_draw(self, seed: int) -> tuple[float, int]:
        # Identical stream for PoW and PoW+PBFT in a paired trial.
        rng = Random(seed + 911_003)
        aggregate_rate = self.config.num_rsus * self.config.pow_hash_rate_per_rsu
        mean_time = self.config.pow_expected_hashes / aggregate_rate
        mining_time = -log(max(1e-15, 1.0 - rng.random())) * mean_time
        return mining_time, rng.randrange(self.config.num_rsus)

    def _pos_leader(self, seed: int) -> int:
        # Equal preregistered nominal stakes make this a uniform draw.
        return Random(seed + 271_003).randrange(self.config.num_rsus)

    def _hybrid_leader(self, seed: int) -> tuple[RSU, list[RSU]]:
        rng = Random(seed + 613_003)
        waiting = list(range(1, self.config.num_rsus + 1))
        rng.shuffle(waiting)
        rsus = make_rsus(
            self.config.num_rsus,
            byzantine_ids=range(self.config.actual_byzantine_rsus),
            waiting_order=waiting,
        )
        return elect_hybrid_leader(rsus, rng), rsus

    def _plain_rsus(self) -> list[RSU]:
        return make_rsus(
            self.config.num_rsus,
            byzantine_ids=range(self.config.actual_byzantine_rsus),
        )

    def _protocol_costs(
        self,
        method: ConsensusMethod,
        block_bytes: int,
        factors: TrialFactors,
    ) -> tuple[int, int, float, float]:
        n = self.config.num_rsus
        followers = n - 1
        signed_block_bytes = block_bytes + self.config.signature_bytes
        if method in (ConsensusMethod.POW, ConsensusMethod.POS):
            message_count = followers
            protocol_bytes = followers * signed_block_bytes
            phases = 1
            crypto_ms = (
                self.config.signature_sign_ms + self.config.signature_verify_ms
            ) * factors.cpu_multiplier
        else:
            audit_transmissions = followers * (followers - 1)
            confirmation_transmissions = followers
            message_count = (
                followers
                + audit_transmissions
                + confirmation_transmissions
                + followers
            )
            protocol_bytes = (
                2 * followers * signed_block_bytes
                + audit_transmissions * self.config.audit_message_bytes
                + confirmation_transmissions * self.config.confirmation_message_bytes
            )
            phases = 4
            follower_crypto_ms = (
                self.config.signature_verify_ms
                + (followers - 1) * self.config.signature_verify_ms
                + self.config.signature_sign_ms
            )
            leader_crypto_ms = (
                2 * self.config.signature_sign_ms
                + followers * self.config.signature_verify_ms
            )
            crypto_ms = max(follower_crypto_ms, leader_crypto_ms) * factors.cpu_multiplier
        network_s = (
            protocol_bytes
            * 8.0
            / (self.config.bandwidth_bps * factors.bandwidth_multiplier)
            + phases * factors.link_latency_ms / 1000.0
        )
        return message_count, protocol_bytes, network_s, crypto_ms / 1000.0

    def run(
        self,
        method: ConsensusMethod | str,
        message_count: int,
        *,
        run: int,
        seed: int,
    ) -> ConsensusRunResult:
        method = ConsensusMethod(method)
        factors = self.trial_factors(seed)
        block_bytes = self.block_bytes(message_count)
        broadcast_s = self.broadcast_time(message_count, factors)
        validation_s = self._validation_time(message_count, factors)
        protocol_count, protocol_bytes, protocol_network_s, crypto_s = (
            self._protocol_costs(method, block_bytes, factors)
        )

        mining_s = 0.0
        election_s = 0.0
        leader_state = "NORMAL"
        if method in (ConsensusMethod.POW, ConsensusMethod.POW_PBFT):
            mining_s, leader_id = self._pow_draw(seed)
        elif method is ConsensusMethod.POS:
            leader_id = self._pos_leader(seed)
            election_s = (
                self.config.election_ms_per_rsu
                * self.config.num_rsus
                * factors.cpu_multiplier
                / 1000.0
            )
        else:
            leader, rsus = self._hybrid_leader(seed)
            leader_id = leader.rsu_id
            leader_state = leader.state.value
            election_s = (
                self.config.election_ms_per_rsu
                * self.config.num_rsus
                * factors.cpu_multiplier
                / 1000.0
            )

        if method in (ConsensusMethod.POW, ConsensusMethod.POS):
            rsus = self._plain_rsus()
            leader = rsus[leader_id]
            committed = not leader.is_byzantine
            leader.record_leader_result(committed)
        else:
            if method is ConsensusMethod.POW_PBFT:
                rsus = self._plain_rsus()
                leader = rsus[leader_id]
            outcome = run_pbft_round(rsus, leader, self.config.max_byzantine)
            committed = outcome.committed

        consensus_s = (
            mining_s
            + election_s
            + validation_s
            + protocol_network_s
            + crypto_s
        )
        total_s = broadcast_s + consensus_s
        return ConsensusRunResult(
            method=method.value,
            message_count=message_count,
            run=run,
            seed=seed,
            broadcast_time_s=broadcast_s,
            consensus_time_s=consensus_s,
            total_confirmation_time_s=total_s,
            committed=int(committed),
            leader_id=leader_id,
            leader_state_before=leader_state,
            max_byzantine=self.config.max_byzantine,
            actual_byzantine=self.config.actual_byzantine_rsus,
            protocol_message_count=protocol_count,
            protocol_bytes=protocol_bytes,
            block_bytes=block_bytes,
            mining_time_s=mining_s,
            election_time_s=election_s,
            validation_time_s=validation_s,
            protocol_network_time_s=protocol_network_s,
        )
