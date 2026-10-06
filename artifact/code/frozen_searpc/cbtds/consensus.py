"""Paper-aligned CBTDS hybrid PoS-PBFT state-machine primitives.

This module models protocol decisions, not wall-clock deployment behavior.
Undisclosed choices are frozen in ``CONSENSUS_IMPLEMENTATION_ASSUMPTIONS.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from random import Random
from typing import Iterable, Sequence


class RSUState(str, Enum):
    GOOD = "GOOD"
    NORMAL = "NORMAL"
    EXCEPTION = "EXCEPTION"
    ERROR = "ERROR"


STATE_WEIGHTS = {
    RSUState.GOOD: 1.0,
    RSUState.NORMAL: 0.5,
    RSUState.EXCEPTION: 0.1,
    RSUState.ERROR: 0.0,
}


@dataclass
class RSU:
    """Authorized roadside unit and its consensus-performance label."""

    rsu_id: int
    state: RSUState = RSUState.NORMAL
    waiting_rounds: int = 1
    consecutive_valid_blocks: int = 0
    consecutive_failures: int = 0
    is_byzantine: bool = False

    def __post_init__(self) -> None:
        if self.rsu_id < 0:
            raise ValueError("rsu_id cannot be negative")
        if self.waiting_rounds < 1:
            raise ValueError("waiting_rounds must be positive")

    @property
    def state_weight(self) -> float:
        return STATE_WEIGHTS[self.state]

    @property
    def election_stake(self) -> float:
        return self.state_weight * self.waiting_rounds

    @property
    def eligible(self) -> bool:
        return self.state is not RSUState.ERROR and self.state_weight > 0.0

    def record_leader_result(
        self,
        valid: bool,
        promotion_threshold: int = 3,
        error_threshold: int = 2,
    ) -> None:
        if promotion_threshold < 1 or error_threshold < 1:
            raise ValueError("state thresholds must be positive")
        if valid:
            self.consecutive_failures = 0
            self.consecutive_valid_blocks += 1
            if self.state is RSUState.EXCEPTION:
                self.state = RSUState.NORMAL
            if self.consecutive_valid_blocks >= promotion_threshold:
                self.state = RSUState.GOOD
        else:
            self.consecutive_valid_blocks = 0
            self.consecutive_failures += 1
            self.state = (
                RSUState.ERROR
                if self.consecutive_failures >= error_threshold
                else RSUState.EXCEPTION
            )

    def inspect_and_repair(self) -> None:
        """Implement the explicit ERROR-to-NORMAL repair arrow in Figure 3."""

        if self.state is RSUState.ERROR:
            self.state = RSUState.NORMAL
            self.consecutive_failures = 0
            self.consecutive_valid_blocks = 0


def elect_hybrid_leader(rsus: Sequence[RSU], rng: Random) -> RSU:
    """Select the largest ``state_weight * waiting_rounds`` stake."""

    eligible = [rsu for rsu in rsus if rsu.eligible]
    if not eligible:
        raise ValueError("at least one non-ERROR RSU is required")
    best_stake = max(rsu.election_stake for rsu in eligible)
    tied = sorted(
        (rsu for rsu in eligible if rsu.election_stake == best_stake),
        key=lambda rsu: rsu.rsu_id,
    )
    winner = rng.choice(tied)
    for rsu in eligible:
        rsu.waiting_rounds = 1 if rsu is winner else rsu.waiting_rounds + 1
    return winner


@dataclass(frozen=True)
class PBFTOutcome:
    committed: bool
    leader_valid: bool
    audit_consents: int
    confirmations: int
    audit_threshold: int
    commit_threshold: int


def evaluate_pbft_counts(
    *,
    num_rsus: int,
    max_byzantine: int,
    audit_consents: int,
    confirmations: int,
    leader_valid: bool = True,
) -> PBFTOutcome:
    """Apply Algorithm 2's literal strict integer quorum comparisons."""

    if num_rsus < 1:
        raise ValueError("num_rsus must be positive")
    if not 0 <= max_byzantine < num_rsus:
        raise ValueError("max_byzantine must be in [0, num_rsus)")
    if audit_consents < 0 or confirmations < 0:
        raise ValueError("message counts cannot be negative")
    audit_threshold = 2 * max_byzantine + 1
    commit_threshold = 2 * max_byzantine + 2
    audit_passed = audit_consents >= audit_threshold
    committed = leader_valid and audit_passed and confirmations >= commit_threshold
    return PBFTOutcome(
        committed=committed,
        leader_valid=leader_valid,
        audit_consents=audit_consents,
        confirmations=confirmations,
        audit_threshold=audit_threshold,
        commit_threshold=commit_threshold,
    )


def run_pbft_round(
    rsus: Sequence[RSU], leader: RSU, max_byzantine: int
) -> PBFTOutcome:
    """Run a deterministic audit/confirmation decision for one block."""

    if leader not in rsus:
        raise ValueError("leader must be an element of rsus")
    honest_count = sum(not rsu.is_byzantine for rsu in rsus)
    leader_valid = not leader.is_byzantine
    audit_consents = honest_count if leader_valid else sum(
        rsu.is_byzantine for rsu in rsus
    )
    audit_threshold = 2 * max_byzantine + 1
    confirmations = (
        max(0, honest_count - 1)
        if leader_valid and audit_consents >= audit_threshold
        else 0
    )
    outcome = evaluate_pbft_counts(
        num_rsus=len(rsus),
        max_byzantine=max_byzantine,
        audit_consents=audit_consents,
        confirmations=confirmations,
        leader_valid=leader_valid,
    )
    leader.record_leader_result(outcome.committed)
    return outcome


def make_rsus(
    num_rsus: int,
    *,
    byzantine_ids: Iterable[int] = (),
    waiting_order: Sequence[int] | None = None,
) -> list[RSU]:
    if num_rsus < 1:
        raise ValueError("num_rsus must be positive")
    malicious = set(byzantine_ids)
    if any(item < 0 or item >= num_rsus for item in malicious):
        raise ValueError("byzantine id outside RSU range")
    if waiting_order is None:
        waiting_order = list(range(1, num_rsus + 1))
    if sorted(waiting_order) != list(range(1, num_rsus + 1)):
        raise ValueError("waiting_order must be a permutation of 1..num_rsus")
    return [
        RSU(
            rsu_id=index,
            waiting_rounds=waiting_order[index],
            is_byzantine=index in malicious,
        )
        for index in range(num_rsus)
    ]
