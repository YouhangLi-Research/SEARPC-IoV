"""Validator-role posterior tracking with an auditable change-point reset."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Hashable, Mapping

from .consensus import ValidatorCandidate
from .reputation import BetaRolePosterior


@dataclass(frozen=True)
class ValidatorUpdate:
    entity_id: Hashable
    success: float
    failure_streak: int
    change_detected: bool
    quarantined: bool
    recovered: bool
    posterior_mean: float
    posterior_lcb: float


class ValidatorReputationTracker:
    """Independent validator posteriors updated only by external adjudication."""

    def __init__(
        self,
        initial_means: Mapping[Hashable, float],
        *,
        initial_evidence: float,
        bound_quantile: float = 0.05,
        failure_trigger: int | None = 3,
        quarantine_on_change: bool = False,
        recovery_successes: int = 5,
    ) -> None:
        if initial_evidence < 0.0:
            raise ValueError("initial_evidence must be non-negative")
        if not 0.0 < bound_quantile < 0.5:
            raise ValueError("bound_quantile must be in (0, 0.5)")
        if failure_trigger is not None and failure_trigger < 1:
            raise ValueError("failure_trigger must be positive or None")
        if recovery_successes < 1:
            raise ValueError("recovery_successes must be positive")
        if not initial_means:
            raise ValueError("at least one validator is required")
        if any(not 0.0 <= value <= 1.0 for value in initial_means.values()):
            raise ValueError("initial means must be in [0, 1]")
        self.bound_quantile = bound_quantile
        self.failure_trigger = failure_trigger
        self.quarantine_on_change = quarantine_on_change
        self.recovery_successes = recovery_successes
        self._posteriors = {
            entity_id: BetaRolePosterior(
                alpha=1.0 + initial_evidence * value,
                beta=1.0 + initial_evidence * (1.0 - value),
            )
            for entity_id, value in initial_means.items()
        }
        self._failure_streak = {entity_id: 0 for entity_id in initial_means}
        self._change_latched = {entity_id: False for entity_id in initial_means}
        self._quarantined = {entity_id: False for entity_id in initial_means}
        self._recovery_streak = {entity_id: 0 for entity_id in initial_means}
        self._lower_bounds = {
            entity_id: posterior.lower_credible_bound(bound_quantile)
            for entity_id, posterior in self._posteriors.items()
        }

    def posterior(self, entity_id: Hashable) -> BetaRolePosterior:
        try:
            return self._posteriors[entity_id]
        except KeyError as error:
            raise KeyError(f"unknown validator {entity_id!r}") from error

    def lower_bound(self, entity_id: Hashable) -> float:
        self.posterior(entity_id)
        return self._lower_bounds[entity_id]

    def is_quarantined(self, entity_id: Hashable) -> bool:
        self.posterior(entity_id)
        return self._quarantined[entity_id]

    @property
    def quarantined_ids(self) -> frozenset[Hashable]:
        return frozenset(
            entity_id
            for entity_id, quarantined in self._quarantined.items()
            if quarantined
        )

    def update(self, entity_id: Hashable, success: float) -> ValidatorUpdate:
        posterior = self.posterior(entity_id)
        if not 0.0 <= success <= 1.0:
            raise ValueError("success must be in [0, 1]")
        detected = False
        recovered = False

        if self._quarantined[entity_id]:
            if success >= 0.5:
                self._recovery_streak[entity_id] += 1
            else:
                self._recovery_streak[entity_id] = 0
            posterior.update(success)
            if self._recovery_streak[entity_id] >= self.recovery_successes:
                posterior = BetaRolePosterior(
                    alpha=1.0 + self.recovery_successes,
                    beta=1.0,
                )
                self._posteriors[entity_id] = posterior
                self._quarantined[entity_id] = False
                self._change_latched[entity_id] = False
                self._failure_streak[entity_id] = 0
                self._recovery_streak[entity_id] = 0
                recovered = True
        else:
            if success < 0.5:
                self._failure_streak[entity_id] += 1
            else:
                self._failure_streak[entity_id] = 0

            trigger = self.failure_trigger
            if (
                trigger is not None
                and self._failure_streak[entity_id] >= trigger
                and not self._change_latched[entity_id]
            ):
                # The trigger failures replace, rather than add to, stale history.
                posterior = BetaRolePosterior(alpha=1.0, beta=1.0 + trigger)
                self._posteriors[entity_id] = posterior
                self._change_latched[entity_id] = True
                self._quarantined[entity_id] = self.quarantine_on_change
                self._recovery_streak[entity_id] = 0
                detected = True
            else:
                posterior.update(success)
        posterior_lcb = posterior.lower_credible_bound(self.bound_quantile)
        self._lower_bounds[entity_id] = posterior_lcb
        return ValidatorUpdate(
            entity_id=entity_id,
            success=success,
            failure_streak=self._failure_streak[entity_id],
            change_detected=detected,
            quarantined=self._quarantined[entity_id],
            recovered=recovered,
            posterior_mean=posterior.mean,
            posterior_lcb=posterior_lcb,
        )

    def candidates(
        self,
        *,
        domains: Mapping[Hashable, Hashable],
        latencies_ms: Mapping[Hashable, float] | None = None,
        eligible_only: bool = False,
    ) -> list[ValidatorCandidate]:
        if set(domains) != set(self._posteriors):
            raise ValueError("domains must contain every validator exactly once")
        latencies = latencies_ms or {}
        return [
            ValidatorCandidate(
                validator_id=int(entity_id),
                honesty_lcb=self.lower_bound(entity_id),
                domain=domains[entity_id],
                latency_ms=float(latencies.get(entity_id, 0.0)),
            )
            for entity_id in sorted(self._posteriors)
            if not eligible_only or not self._quarantined[entity_id]
        ]
