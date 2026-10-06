"""Registered Basic HotStuff cost proxy for the detector baselines strong baseline."""

from __future__ import annotations

from dataclasses import dataclass

from .certified import basic_hotstuff_message_count


@dataclass(frozen=True)
class BasicHotStuffCost:
    message_count: int
    protocol_bytes: int
    network_time_s: float
    crypto_time_s: float
    validation_time_s: float

    @property
    def total_time_s(self) -> float:
        return self.network_time_s + self.crypto_time_s + self.validation_time_s


def basic_hotstuff_cost(
    *,
    num_validators: int,
    certificate_size: int,
    block_bytes: int,
    signature_bytes: int,
    vote_message_bytes: int,
    qc_header_bytes: int,
    bandwidth_bps: float,
    bandwidth_multiplier: float,
    link_latency_ms: float,
    cpu_multiplier: float,
    signature_sign_ms: float,
    signature_verify_ms: float,
    validation_time_s: float,
    failed_leader_views: int = 0,
) -> BasicHotStuffCost:
    if num_validators < 1:
        raise ValueError("num_validators must be positive")
    if not 1 <= certificate_size <= num_validators:
        raise ValueError("certificate_size must be within the validator set")
    if min(block_bytes, signature_bytes, vote_message_bytes, qc_header_bytes) <= 0:
        raise ValueError("message sizes must be positive")
    if bandwidth_bps <= 0.0 or bandwidth_multiplier <= 0.0:
        raise ValueError("bandwidth values must be positive")
    if link_latency_ms < 0.0 or validation_time_s < 0.0:
        raise ValueError("time values must be non-negative")
    if cpu_multiplier <= 0.0 or failed_leader_views < 0:
        raise ValueError("invalid multiplier or failed view count")
    if signature_sign_ms < 0.0 or signature_verify_ms < 0.0:
        raise ValueError("signature costs must be non-negative")

    followers = num_validators - 1
    signed_block_bytes = block_bytes + signature_bytes
    qc_bytes = qc_header_bytes + certificate_size * signature_bytes
    healthy_bytes = followers * (
        signed_block_bytes + 3 * vote_message_bytes + 3 * qc_bytes
    )
    failed_view_bytes = followers * (signed_block_bytes + vote_message_bytes)
    protocol_bytes = healthy_bytes + failed_leader_views * failed_view_bytes
    phases = 7 + 2 * failed_leader_views
    network_time_s = (
        protocol_bytes * 8.0 / (bandwidth_bps * bandwidth_multiplier)
        + phases * link_latency_ms / 1000.0
    )
    replica_ms = 3 * (signature_verify_ms + signature_sign_ms)
    leader_ms = 4 * signature_sign_ms + 3 * certificate_size * signature_verify_ms
    failed_view_ms = failed_leader_views * (
        signature_verify_ms + signature_sign_ms
    )
    crypto_time_s = (
        max(replica_ms, leader_ms) + failed_view_ms
    ) * cpu_multiplier / 1000.0
    return BasicHotStuffCost(
        message_count=basic_hotstuff_message_count(
            num_validators, failed_leader_views=failed_leader_views
        ),
        protocol_bytes=protocol_bytes,
        network_time_s=network_time_s,
        crypto_time_s=crypto_time_s,
        validation_time_s=validation_time_s * (1 + failed_leader_views),
    )
