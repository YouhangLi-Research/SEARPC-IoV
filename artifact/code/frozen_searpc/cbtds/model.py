"""CBTDS trust-management equations expressed as small testable functions."""

from __future__ import annotations

from dataclasses import dataclass
from math import exp, tanh
from typing import Iterable, Optional, Sequence

from .config import CBTDSConfig


def _clip01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


@dataclass
class PairwiseEvidence:
    """Direct interaction history maintained by one requester for one provider."""

    alpha: float = 1.0
    beta: float = 1.0
    interactions: int = 0
    recent_malicious_events: int = 0

    def observe(self, quality: float, threshold: float) -> None:
        quality = _clip01(quality)
        self.interactions += 1
        if quality >= threshold:
            self.alpha += 1.0
            # Good behavior slowly cools the recent attack counter, but does
            # not erase it immediately.  This instantiates the paper's verbal
            # description of slow recovery after a swing attack.
            self.recent_malicious_events = max(
                0, self.recent_malicious_events - 1
            )
        else:
            self.beta += 1.0
            self.recent_malicious_events += 1


@dataclass(frozen=True)
class Recommendation:
    """A recommendation about a provider, supplied by another vehicle."""

    value: float
    recommender_global_trust: float
    requester_recommender_trust: float
    is_pretrusted: bool = False


class TrustModel:
    """Numerically stable implementation of CBTDS equations (3)-(17)."""

    def __init__(self, config: CBTDSConfig) -> None:
        self.config = config

    @staticmethod
    def beta_reputation(alpha: float, beta: float) -> float:
        if alpha <= 0.0 or beta <= 0.0:
            raise ValueError("alpha and beta must be positive")
        return alpha / (alpha + beta)

    def penalty_eta(
        self, recent_malicious_events: int, delta_intervals: float = 1.0
    ) -> float:
        """Instantiate equation (6) and the exponential repeated-offence rule."""

        if recent_malicious_events < 0:
            raise ValueError("recent_malicious_events cannot be negative")
        escalation = 2 ** max(0, recent_malicious_events - 2)
        effective_gamma = self.config.penalty_gamma * escalation
        return exp(-effective_gamma * max(0.0, delta_intervals))

    def direct_interaction_trust(self, evidence: PairwiseEvidence) -> float:
        eta = self.penalty_eta(evidence.recent_malicious_events)
        numerator = eta * evidence.alpha
        return numerator / (numerator + evidence.beta)

    @staticmethod
    def interaction_frequency(
        pair_interactions: int, requester_total_interactions: int
    ) -> float:
        if pair_interactions < 0 or requester_total_interactions < 0:
            raise ValueError("interaction counts cannot be negative")
        if requester_total_interactions == 0:
            return 0.0
        return _clip01(pair_interactions / requester_total_interactions)

    def direct_trust(
        self, evidence: PairwiseEvidence, requester_total_interactions: int
    ) -> Optional[float]:
        if evidence.interactions == 0:
            return None
        interaction_trust = self.direct_interaction_trust(evidence)
        frequency = self.interaction_frequency(
            evidence.interactions, requester_total_interactions
        )
        return _clip01((interaction_trust + frequency) / 2.0)

    def indirect_trust(
        self, recommendations: Iterable[Recommendation]
    ) -> Optional[float]:
        """Filter malicious recommenders and compute bounded indirect trust.

        Equation (10) in the manuscript is not guaranteed to remain in [0, 1]
        when read literally.  We therefore use its intended convex form:
        ``xi * pretrusted_mean + (1-xi) * confidence_weighted_common``.
        """

        filtered = [
            recommendation
            for recommendation in recommendations
            if recommendation.recommender_global_trust
            >= self.config.trust_threshold
        ]
        if not filtered:
            return None

        pretrusted = [item for item in filtered if item.is_pretrusted]
        common = [item for item in filtered if not item.is_pretrusted]

        pretrusted_mean: Optional[float] = None
        if pretrusted:
            pretrusted_mean = sum(_clip01(item.value) for item in pretrusted) / len(
                pretrusted
            )

        common_mean: Optional[float] = None
        if common:
            raw_confidence = [
                max(
                    0.0,
                    item.recommender_global_trust
                    + item.requester_recommender_trust,
                )
                for item in common
            ]
            confidence_sum = sum(raw_confidence)
            if confidence_sum <= 0.0:
                common_mean = sum(_clip01(item.value) for item in common) / len(
                    common
                )
            else:
                common_mean = sum(
                    confidence * _clip01(item.value)
                    for confidence, item in zip(raw_confidence, common)
                ) / confidence_sum

        if pretrusted_mean is None:
            return _clip01(common_mean if common_mean is not None else 0.0)
        if common_mean is None:
            return _clip01(pretrusted_mean)

        xi = self.config.pretrusted_weight
        return _clip01(xi * pretrusted_mean + (1.0 - xi) * common_mean)

    @staticmethod
    def recommendation_rate(
        recommendation_count: int, neighbor_count: int
    ) -> float:
        if recommendation_count < 0 or neighbor_count < 0:
            raise ValueError("counts cannot be negative")
        if neighbor_count == 0:
            return 0.0
        ratio = recommendation_count / neighbor_count
        return 1.0 / (1.0 + exp(-ratio))

    def final_trust(
        self,
        data_quality: float,
        direct_trust: Optional[float],
        indirect_trust: Optional[float],
        recommendation_count: int,
        neighbor_count: int,
    ) -> float:
        """Implement the four evidence-availability cases in equation (11)."""

        quality = _clip01(data_quality)
        if direct_trust is None and indirect_trust is None:
            return quality
        if direct_trust is None:
            recommendation_rate = self.recommendation_rate(
                recommendation_count, neighbor_count
            )
            return _clip01(
                (1.0 - recommendation_rate) * quality
                + recommendation_rate * _clip01(indirect_trust)
            )
        if indirect_trust is None:
            rho = self.config.direct_weight
            return _clip01((1.0 - rho) * quality + rho * _clip01(direct_trust))
        return _clip01(
            self.config.data_quality_weight * quality
            + self.config.direct_final_weight * _clip01(direct_trust)
            + self.config.indirect_final_weight * _clip01(indirect_trust)
        )

    def aggregate_current_trust(
        self,
        common_reports: Sequence[float],
        pretrusted_reports: Sequence[float],
    ) -> float:
        if not common_reports and not pretrusted_reports:
            raise ValueError("at least one trust report is required")
        common_mean = (
            sum(_clip01(value) for value in common_reports) / len(common_reports)
            if common_reports
            else None
        )
        pretrusted_mean = (
            sum(_clip01(value) for value in pretrusted_reports)
            / len(pretrusted_reports)
            if pretrusted_reports
            else None
        )
        if common_mean is None:
            return _clip01(pretrusted_mean)
        if pretrusted_mean is None:
            return _clip01(common_mean)
        xi = self.config.pretrusted_weight
        return _clip01((1.0 - xi) * common_mean + xi * pretrusted_mean)

    def forgetting_factor(self, current: float, previous: float) -> float:
        """Implement equations (15)-(16) as a bounded historical weight."""

        change = _clip01(current) - _clip01(previous)
        if change < 0.0:
            return self.config.history_floor
        historical_weight = (
            tanh(self.config.recovery_regulator * change)
            + self.config.history_floor
        )
        return min(0.95, max(self.config.history_floor, historical_weight))

    def update_global_trust(self, current: float, previous: float) -> float:
        delta = self.forgetting_factor(current, previous)
        return _clip01((1.0 - delta) * current + delta * previous)

    def is_malicious(self, global_trust: float) -> bool:
        return _clip01(global_trust) < self.config.trust_threshold
