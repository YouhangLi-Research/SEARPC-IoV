"""scoped evidence validator admission finite-state controller without Beta control state."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Hashable, Iterable, Mapping

from durac.consensus import ValidatorCandidate


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


class ValidatorAdmissionFSM:
    """Delivered-audit finite-state admission used by the scoped evidence main path.

    It deliberately has no Beta/posterior state.  Candidate honesty values are
    a constant neutral value because the main committee selection is uniform
    within the active pool and therefore must not read a validator posterior.
    """

    def __init__(self, validator_ids: Iterable[Hashable], *, failure_trigger: int = 3,
                 probation_successes: int = 5, activation_successes: int = 5,
                 minimum_audit_domains: int = 2) -> None:
        ids = tuple(sorted(validator_ids))
        if not ids:
            raise ValueError("at least one validator is required")
        self.failure_trigger = failure_trigger
        self.probation_successes = probation_successes
        self.activation_successes = activation_successes
        self.minimum_audit_domains = minimum_audit_domains
        self._states = {i: AdmissionState.ACTIVE for i in ids}
        self._failure_streak = {i: 0 for i in ids}
        self._certificate_successes = {i: 0 for i in ids}
        self._certificate_domains = {i: set() for i in ids}

    def _clear_certificate(self, entity_id):
        self._certificate_successes[entity_id] = 0
        self._certificate_domains[entity_id].clear()

    def state(self, entity_id):
        return self._states[entity_id]

    def update(self, entity_id, success: float, *, audit_domain):
        if entity_id not in self._states:
            raise KeyError(entity_id)
        if not 0.0 <= success <= 1.0:
            raise ValueError("success must be in [0,1]")
        previous = self._states[entity_id]
        detected = entered = activated = False
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
                enough_domains = len(self._certificate_domains[entity_id]) >= self.minimum_audit_domains
                threshold = self.probation_successes if previous is AdmissionState.QUARANTINE else self.activation_successes
                if self._certificate_successes[entity_id] >= threshold and enough_domains:
                    if previous is AdmissionState.QUARANTINE:
                        self._states[entity_id] = AdmissionState.PROBATION
                        entered = True
                    else:
                        self._states[entity_id] = AdmissionState.ACTIVE
                        activated = True
                    self._clear_certificate(entity_id)
        state = self._states[entity_id]
        return AdmissionUpdate(
            entity_id=entity_id, success=success, previous_state=previous.value, state=state.value,
            change_detected=detected, entered_probation=entered, activated=activated,
            failure_streak=self._failure_streak[entity_id],
            certificate_successes=self._certificate_successes[entity_id],
            certificate_domains=len(self._certificate_domains[entity_id]),
        )

    def ids_in_state(self, state: AdmissionState | str):
        state = AdmissionState(state)
        return frozenset(i for i,s in self._states.items() if s is state)

    @property
    def active_ids(self): return self.ids_in_state(AdmissionState.ACTIVE)
    @property
    def quarantined_ids(self): return self.ids_in_state(AdmissionState.QUARANTINE)
    @property
    def probation_ids(self): return self.ids_in_state(AdmissionState.PROBATION)

    def candidates(self, *, domains: Mapping[Hashable, Hashable], latencies_ms: Mapping[Hashable,float] | None = None,
                   states: Iterable[AdmissionState | str] | None = None):
        if set(domains) != set(self._states):
            raise ValueError("domains must contain every validator exactly once")
        allowed = {AdmissionState(s) for s in states} if states is not None else set(AdmissionState)
        latencies = latencies_ms or {}
        return [
            ValidatorCandidate(int(i), 0.5, domains[i], float(latencies.get(i,0.0)))
            for i in sorted(self._states) if self._states[i] in allowed
        ]
