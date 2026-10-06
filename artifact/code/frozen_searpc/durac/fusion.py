"""Robust, administrative-domain-capped recommendation fusion."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import isfinite
from typing import Hashable, Iterable, Sequence

from .reputation import Role, RoleReputationBook


@dataclass(frozen=True)
class Opinion:
    recommender_id: Hashable
    value: float
    domain: Hashable
    context_similarity: float = 1.0
    freshness: float = 1.0

    def __post_init__(self) -> None:
        for name, value in (
            ("value", self.value),
            ("context_similarity", self.context_similarity),
            ("freshness", self.freshness),
        ):
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be finite and in [0, 1]")


@dataclass(frozen=True)
class FusionResult:
    value: float
    disagreement: float
    accepted_opinions: int
    represented_domains: int
    effective_weight: float


def _weighted_median(values: Sequence[tuple[float, float]]) -> float:
    if not values:
        raise ValueError("at least one positive-weight value is required")
    ordered = sorted(values, key=lambda item: item[0])
    total = sum(weight for _, weight in ordered)
    if total <= 0.0:
        raise ValueError("total weight must be positive")
    midpoint = total / 2.0
    cumulative = 0.0
    for value, weight in ordered:
        cumulative += weight
        if cumulative >= midpoint:
            return value
    return ordered[-1][0]


def robust_opinion_fusion(
    opinions: Iterable[Opinion],
    reputation_book: RoleReputationBook,
    *,
    lcb_quantile: float = 0.05,
    evidence_reliability: float = 1.0,
) -> FusionResult | None:
    if not 0.0 <= evidence_reliability <= 1.0:
        raise ValueError("evidence_reliability must be in [0, 1]")

    grouped: dict[Hashable, list[tuple[float, float]]] = defaultdict(list)
    accepted = 0
    for opinion in opinions:
        role_lcb = reputation_book.lower_bound(
            opinion.recommender_id, Role.OPINION_PROVIDER, lcb_quantile
        )
        weight = (
            role_lcb
            * opinion.context_similarity
            * opinion.freshness
            * evidence_reliability
        )
        if weight <= 0.0:
            continue
        grouped[opinion.domain].append((opinion.value, weight))
        accepted += 1

    if not grouped:
        return None

    # Each administrative domain contributes one robust location and at most
    # its strongest member's weight.  Duplicating identities inside one domain
    # therefore cannot multiply that domain's cross-domain voting power.
    domain_points: list[tuple[float, float]] = []
    for values in grouped.values():
        domain_value = _weighted_median(values)
        domain_weight = max(weight for _, weight in values)
        domain_points.append((domain_value, domain_weight))

    fused = _weighted_median(domain_points)
    total_weight = sum(weight for _, weight in domain_points)
    disagreement = sum(
        weight * abs(value - fused) for value, weight in domain_points
    ) / total_weight
    return FusionResult(
        value=fused,
        disagreement=disagreement,
        accepted_opinions=accepted,
        represented_domains=len(domain_points),
        effective_weight=total_weight,
    )

