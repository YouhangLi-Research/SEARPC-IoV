"""Uncertainty-preserving event assessment used by DURAC-IoV."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite

from scipy.stats import beta as beta_distribution

from .fusion import FusionResult


@dataclass(frozen=True)
class EventAssessment:
    credibility_mean: float
    credibility_lcb: float
    credibility_ucb: float
    credible_decision: bool
    decision_error_upper: float
    expected_loss_upper: float
    evidence_strength: float


def assess_event(
    *,
    message_probability: float,
    epistemic_uncertainty: float,
    provider_lcb: float,
    opinion: FusionResult | None,
    criticality: float,
    decision_threshold: float = 0.5,
    bound_quantile: float = 0.05,
) -> EventAssessment:
    for name, value in (
        ("message_probability", message_probability),
        ("epistemic_uncertainty", epistemic_uncertainty),
        ("provider_lcb", provider_lcb),
        ("criticality", criticality),
        ("decision_threshold", decision_threshold),
    ):
        if not isfinite(value):
            raise ValueError(f"{name} must be finite")
    if not 0.0 <= message_probability <= 1.0:
        raise ValueError("message_probability must be in [0, 1]")
    if not 0.0 <= epistemic_uncertainty <= 1.0:
        raise ValueError("epistemic_uncertainty must be in [0, 1]")
    if not 0.0 <= provider_lcb <= 1.0:
        raise ValueError("provider_lcb must be in [0, 1]")
    if criticality < 0.0:
        raise ValueError("criticality must be non-negative")
    if not 0.0 < decision_threshold < 1.0:
        raise ValueError("decision_threshold must be in (0, 1)")
    if not 0.0 < bound_quantile < 0.5:
        raise ValueError("bound_quantile must be in (0, 0.5)")

    alpha = 1.0
    beta = 1.0
    evidence_strength = 0.0

    message_weight = 1.0 - epistemic_uncertainty
    alpha += message_weight * message_probability
    beta += message_weight * (1.0 - message_probability)
    evidence_strength += message_weight

    # One bounded contribution prevents a long reputation history from
    # overwhelming contradictory event-level physical evidence.
    alpha += provider_lcb
    beta += 1.0 - provider_lcb
    evidence_strength += 1.0

    if opinion is not None:
        mean_domain_weight = opinion.effective_weight / opinion.represented_domains
        opinion_weight = min(1.0, mean_domain_weight) * (1.0 - opinion.disagreement)
        alpha += opinion_weight * opinion.value
        beta += opinion_weight * (1.0 - opinion.value)
        evidence_strength += opinion_weight

    mean = alpha / (alpha + beta)
    lower = float(beta_distribution.ppf(bound_quantile, alpha, beta))
    upper = float(beta_distribution.ppf(1.0 - bound_quantile, alpha, beta))
    decision = mean >= decision_threshold
    error_upper = 1.0 - lower if decision else upper
    return EventAssessment(
        credibility_mean=mean,
        credibility_lcb=lower,
        credibility_ucb=upper,
        credible_decision=decision,
        decision_error_upper=error_upper,
        expected_loss_upper=criticality * error_upper,
        evidence_strength=evidence_strength,
    )

