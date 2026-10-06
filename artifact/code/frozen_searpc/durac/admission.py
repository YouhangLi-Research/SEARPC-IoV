"""Validator admission with separate long-term and recovery evidence."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Hashable, Iterable, Mapping

from .consensus import ValidatorCandidate
from .reputation import BetaRolePosterior


class AdmissionState(str, Enum):
    ACTIVE = "active"
    QUARANTINE = "quarantine"
    PROBATION = "probation"


@dataclass(frozen=True)
class AdmissionUpdate:
    entity_id: Hashable
    success: float
    previous_state: str
    state: str
    change_detected: bool
    entered_probation: bool
    activated: bool
    failure_streak: int
    certificate_successes: int
    certificate_domains: int
    posterior_mean: float
    posterior_lcb: float


class ValidatorAdmissionTracker:
    """Keep behavior history independent from recovery-admission evidence."""

    def __init__(
        self,
        initial_means: Mapping[Hashable, float],
        *,
        initial_evidence: float,
        bound_quantile: float = 0.05,
        failure_trigger: int = 3,
        probation_successes: int = 5,
        activation_successes: int = 5,
        minimum_audit_domains: int = 2,
    ) -> None:
        if not initial_means:
            raise ValueError("at least one validator is required")
        if initial_evidence < 0.0:
            raise ValueError("initial_evidence must be non-negative")
        if any(not 0.0 <= value <= 1.0 for value in initial_means.values()):
            raise ValueError("initial means must be in [0, 1]")
        if not 0.0 < bound_quantile < 0.5:
            raise ValueError("bound_quantile must be in (0, 0.5)")
        if failure_trigger < 1:
            raise ValueError("failure_trigger must be positive")
        if probation_successes < 1 or activation_successes < 1:
            raise ValueError("recovery thresholds must be positive")
        if minimum_audit_domains < 1:
            raise ValueError("minimum_audit_domains must be positive")

        self.bound_quantile = bound_quantile
        self.failure_trigger = failure_trigger
        self.probation_successes = probation_successes
        self.activation_successes = activation_successes
        self.minimum_audit_domains = minimum_audit_domains
        self._posteriors = {
            entity_id: BetaRolePosterior(
                alpha=1.0 + initial_evidence * value,
                beta=1.0 + initial_evidence * (1.0 - value),
            )
            for entity_id, value in initial_means.items()
        }
        self._states = {
            entity_id: AdmissionState.ACTIVE for entity_id in initial_means
        }
        self._failure_streak = {entity_id: 0 for entity_id in initial_means}
        self._certificate_successes = {
            entity_id: 0 for entity_id in initial_means
        }
        self._certificate_domains: dict[Hashable, set[Hashable]] = {
            entity_id: set() for entity_id in initial_means
        }

    def posterior(self, entity_id: Hashable) -> BetaRolePosterior:
        try:
            return self._posteriors[entity_id]
        except KeyError as error:
            raise KeyError(f"unknown validator {entity_id!r}") from error

    def state(self, entity_id: Hashable) -> AdmissionState:
        self.posterior(entity_id)
        return self._states[entity_id]

    def lower_bound(self, entity_id: Hashable) -> float:
        return self.posterior(entity_id).lower_credible_bound(self.bound_quantile)

    def _clear_certificate(self, entity_id: Hashable) -> None:
        self._certificate_successes[entity_id] = 0
        self._certificate_domains[entity_id].clear()

    def update(
        self,
        entity_id: Hashable,
        success: float,
        *,
        audit_domain: Hashable,
    ) -> AdmissionUpdate:
        posterior = self.posterior(entity_id)
        if not 0.0 <= success <= 1.0:
            raise ValueError("success must be in [0, 1]")
        previous = self._states[entity_id]
        detected = False
        entered_probation = False
        activated = False

        # Long-term behavior history is updated but never reset by admission.
        posterior.update(success)

        if previous is AdmissionState.ACTIVE:
            if success < 0.5:
                self._failure_streak[entity_id] += 1
            else:
                self._failure_streak[entity_id] = 0
            if self._failure_streak[entity_id] >= self.failure_trigger:
                self._states[entity_id] = AdmissionState.QUARANTINE
                self._failure_streak[entity_id] = 0
                self._clear_certificate(entity_id)
                detected = True
        else:
            if success < 0.5:
                self._states[entity_id] = AdmissionState.QUARANTINE
                self._clear_certificate(entity_id)
            else:
                self._certificate_successes[entity_id] += 1
                self._certificate_domains[entity_id].add(audit_domain)
                enough_domains = (
                    len(self._certificate_domains[entity_id])
                    >= self.minimum_audit_domains
                )
                threshold = (
                    self.probation_successes
                    if previous is AdmissionState.QUARANTINE
                    else self.activation_successes
                )
                if (
                    self._certificate_successes[entity_id] >= threshold
                    and enough_domains
                ):
                    if previous is AdmissionState.QUARANTINE:
                        self._states[entity_id] = AdmissionState.PROBATION
                        entered_probation = True
                    else:
                        self._states[entity_id] = AdmissionState.ACTIVE
                        activated = True
                    self._clear_certificate(entity_id)

        state = self._states[entity_id]
        return AdmissionUpdate(
            entity_id=entity_id,
            success=success,
            previous_state=previous.value,
            state=state.value,
            change_detected=detected,
            entered_probation=entered_probation,
            activated=activated,
            failure_streak=self._failure_streak[entity_id],
            certificate_successes=self._certificate_successes[entity_id],
            certificate_domains=len(self._certificate_domains[entity_id]),
            posterior_mean=posterior.mean,
            posterior_lcb=posterior.lower_credible_bound(self.bound_quantile),
        )

    def ids_in_state(self, state: AdmissionState | str) -> frozenset[Hashable]:
        state = AdmissionState(state)
        return frozenset(
            entity_id
            for entity_id, current in self._states.items()
            if current is state
        )

    @property
    def active_ids(self) -> frozenset[Hashable]:
        return self.ids_in_state(AdmissionState.ACTIVE)

    @property
    def quarantined_ids(self) -> frozenset[Hashable]:
        return self.ids_in_state(AdmissionState.QUARANTINE)

    @property
    def probation_ids(self) -> frozenset[Hashable]:
        return self.ids_in_state(AdmissionState.PROBATION)

    def candidates(
        self,
        *,
        domains: Mapping[Hashable, Hashable],
        latencies_ms: Mapping[Hashable, float] | None = None,
        states: Iterable[AdmissionState | str] | None = None,
    ) -> list[ValidatorCandidate]:
        if set(domains) != set(self._posteriors):
            raise ValueError("domains must contain every validator exactly once")
        allowed = (
            {AdmissionState(state) for state in states}
            if states is not None
            else set(AdmissionState)
        )
        latencies = latencies_ms or {}
        return [
            ValidatorCandidate(
                validator_id=int(entity_id),
                honesty_lcb=self.lower_bound(entity_id),
                domain=domains[entity_id],
                latency_ms=float(latencies.get(entity_id, 0.0)),
            )
            for entity_id in sorted(self._posteriors)
            if self._states[entity_id] in allowed
        ]
