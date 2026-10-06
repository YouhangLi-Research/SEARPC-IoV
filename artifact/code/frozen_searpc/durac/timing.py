"""Registered cost model for the DURAC v2 full-set finality certificate."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FinalityCertificateCost:
    message_count: int
    protocol_bytes: int
    network_time_s: float
    crypto_time_s: float
    validation_time_s: float

    @property
    def total_time_s(self) -> float:
        return self.network_time_s + self.crypto_time_s + self.validation_time_s


def full_set_finality_cost(
    *,
    num_registered: int,
    certificate_size: int,
    digest_message_bytes: int,
    vote_message_bytes: int,
    bandwidth_bps: float,
    bandwidth_multiplier: float,
    link_latency_ms: float,
    cpu_multiplier: float,
    signature_sign_ms: float,
    signature_verify_ms: float,
    validation_time_s: float,
) -> FinalityCertificateCost:
    if num_registered < 1:
        raise ValueError("num_registered must be positive")
    if not 1 <= certificate_size <= num_registered:
        raise ValueError("certificate_size must be within the registered set")
    if digest_message_bytes <= 0 or vote_message_bytes <= 0:
        raise ValueError("message sizes must be positive")
    if bandwidth_bps <= 0.0 or bandwidth_multiplier <= 0.0:
        raise ValueError("bandwidth values must be positive")
    if link_latency_ms < 0.0 or validation_time_s < 0.0:
        raise ValueError("time values must be non-negative")
    if cpu_multiplier <= 0.0:
        raise ValueError("cpu_multiplier must be positive")
    if signature_sign_ms < 0.0 or signature_verify_ms < 0.0:
        raise ValueError("signature costs must be non-negative")

    messages = 2 * num_registered
    protocol_bytes = num_registered * (
        digest_message_bytes + vote_message_bytes
    )
    network_time_s = (
        protocol_bytes * 8.0 / (bandwidth_bps * bandwidth_multiplier)
        + 2.0 * link_latency_ms / 1000.0
    )
    # Collector request signing + parallel validator verify/sign + collector
    # verification of the final certificate signatures.
    crypto_ms = (
        2.0 * signature_sign_ms
        + (certificate_size + 1) * signature_verify_ms
    ) * cpu_multiplier
    return FinalityCertificateCost(
        message_count=messages,
        protocol_bytes=protocol_bytes,
        network_time_s=network_time_s,
        crypto_time_s=crypto_ms / 1000.0,
        validation_time_s=validation_time_s,
    )
