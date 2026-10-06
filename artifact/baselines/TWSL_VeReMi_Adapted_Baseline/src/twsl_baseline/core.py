from __future__ import annotations

from collections.abc import Iterable, Sequence

from .models import LocalOpinionRecord, Opinion, TWSLConfig


_EPS = 1e-12


def local_opinion(
    positive_events: float,
    negative_events: float,
    communication_quality: float,
    gamma: float = 0.5,
) -> Opinion:
    """Implement Eqs. (1)-(2) of Kang et al.

    With no observed event, Eq. (1) has a zero denominator. We return the
    standard vacuous opinion (0, 0, 1), an explicit edge-case completion that
    leaves the expectation equal to gamma.
    """

    if positive_events < 0.0 or negative_events < 0.0:
        raise ValueError("event counts must be non-negative")
    if not 0.0 <= communication_quality <= 1.0:
        raise ValueError("communication_quality must lie in [0, 1]")
    total = positive_events + negative_events
    if total <= _EPS:
        return Opinion(0.0, 0.0, 1.0, gamma)
    uncertainty = 1.0 - communication_quality
    committed_mass = 1.0 - uncertainty
    belief = committed_mass * positive_events / total
    distrust = committed_mass * negative_events / total
    return Opinion(belief, distrust, uncertainty, gamma)


def paper_weighted_event_count(
    positive_recent: int,
    positive_past: int,
    negative_recent: int,
    negative_past: int,
    config: TWSLConfig,
) -> float:
    """Numerator of Eq. (4), preserving the published parameterization."""

    counts = (positive_recent, positive_past, negative_recent, negative_past)
    if any(value < 0 for value in counts):
        raise ValueError("event counts must be non-negative")
    positive = config.theta_positive * (
        config.zeta_recent * positive_recent + config.sigma_past * positive_past
    )
    negative = config.tau_negative * (
        config.zeta_recent * negative_recent + config.sigma_past * negative_past
    )
    return positive + negative


def interaction_frequency(weighted_pair_count: float, mean_raw_requestor_count: float) -> float:
    """Implement Eq. (4): weighted pair evidence divided by mean raw count."""

    if weighted_pair_count < 0.0 or mean_raw_requestor_count < 0.0:
        raise ValueError("interaction counts must be non-negative")
    if mean_raw_requestor_count <= _EPS:
        return 0.0
    return weighted_pair_count / mean_raw_requestor_count


def opinion_weight(
    interaction_frequency_value: float,
    trajectory_similarity_value: float,
    config: TWSLConfig,
) -> float:
    """Implement Eq. (10). The paper does not require clipping delta to one."""

    if interaction_frequency_value < 0.0:
        raise ValueError("interaction frequency must be non-negative")
    if not 0.0 <= trajectory_similarity_value <= 1.0:
        raise ValueError("trajectory similarity must lie in [0, 1]")
    return (
        config.rho_frequency * interaction_frequency_value
        + config.rho_similarity * trajectory_similarity_value
    )


def recommended_opinion(records: Sequence[LocalOpinionRecord], gamma: float = 0.5) -> Opinion | None:
    """Implement Eq. (11), the delta-weighted arithmetic mean of opinions."""

    if not records:
        return None
    denominator = sum(record.weight for record in records)
    if denominator <= _EPS:
        return Opinion(0.0, 0.0, 1.0, gamma)
    belief = sum(record.weight * record.opinion.belief for record in records) / denominator
    distrust = sum(record.weight * record.opinion.distrust for record in records) / denominator
    uncertainty = sum(record.weight * record.opinion.uncertainty for record in records) / denominator
    total = belief + distrust + uncertainty
    return Opinion(belief / total, distrust / total, uncertainty / total, gamma)


def combine_local_and_recommended(local: Opinion, recommended: Opinion | None) -> Opinion:
    """Implement the consensus operator in Eq. (12), then Eq. (13)."""

    if recommended is None:
        return local
    denominator = (
        local.uncertainty
        + recommended.uncertainty
        - local.uncertainty * recommended.uncertainty
    )
    if denominator <= _EPS:
        raise ValueError(
            "Eq. (12) is undefined for two dogmatic opinions; preserve non-zero "
            "communication uncertainty or declare a dataset-specific policy"
        )
    belief = (
        local.belief * recommended.uncertainty
        + recommended.belief * local.uncertainty
    ) / denominator
    distrust = (
        local.distrust * recommended.uncertainty
        + recommended.distrust * local.uncertainty
    ) / denominator
    uncertainty = local.uncertainty * recommended.uncertainty / denominator
    total = belief + distrust + uncertainty
    return Opinion(
        belief / total,
        distrust / total,
        uncertainty / total,
        local.base_rate,
    )


def weighted_opinion_from_rows(
    rows: Iterable[tuple[Opinion, float]], gamma: float = 0.5
) -> Opinion | None:
    """Small public helper for adapters that already have opinion vectors."""

    records = [
        LocalOpinionRecord("source", str(index), opinion, 0.0, 0.0, weight)
        for index, (opinion, weight) in enumerate(rows)
    ]
    return recommended_opinion(records, gamma)

