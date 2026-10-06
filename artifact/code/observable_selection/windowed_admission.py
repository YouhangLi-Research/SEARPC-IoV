"""Delivered-audit windowed validator admission used only for the observable selection on-off check.

This module preserves the frozen Active/Quarantine/Probation recovery semantics
but replaces the ACTIVE-state *consecutive* failure detector with an m-of-W
rule over actually delivered audits.  No future or latent fault labels are
accepted by the tracker.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Hashable, Mapping

from durac.admission import AdmissionState, AdmissionUpdate, ValidatorAdmissionTracker


class WindowedValidatorAdmissionTracker(ValidatorAdmissionTracker):
    """Validator admission with an m-of-W delivered-failure trigger."""

    def __init__(
        self,
        initial_means: Mapping[Hashable, float],
        *,
        initial_evidence: float,
        bound_quantile: float = 0.05,
        failures_required: int = 3,
        window_size: int = 6,
        probation_successes: int = 5,
        activation_successes: int = 5,
        minimum_audit_domains: int = 2,
    ) -> None:
        if not 1 <= failures_required <= window_size:
            raise ValueError("failures_required must be in [1, window_size]")
        super().__init__(
            initial_means,
            initial_evidence=initial_evidence,
            bound_quantile=bound_quantile,
            failure_trigger=10**9,  # parent streak detector is not used below
            probation_successes=probation_successes,
            activation_successes=activation_successes,
            minimum_audit_domains=minimum_audit_domains,
        )
        self.failures_required = failures_required
        self.window_size = window_size
        self._delivered_windows = {
            entity_id: deque(maxlen=window_size) for entity_id in initial_means
        }

    def warning_count(self, entity_id: Hashable) -> int:
        self.posterior(entity_id)
        return int(sum(self._delivered_windows[entity_id]))

    def _clear_window(self, entity_id: Hashable) -> None:
        self._delivered_windows[entity_id].clear()

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

        # The long-term evidence update remains exactly delivered-only.
        posterior.update(success)

        if previous is AdmissionState.ACTIVE:
            self._delivered_windows[entity_id].append(int(success < 0.5))
            if self.warning_count(entity_id) >= self.failures_required:
                self._states[entity_id] = AdmissionState.QUARANTINE
                self._failure_streak[entity_id] = 0
                self._clear_window(entity_id)
                self._clear_certificate(entity_id)
                detected = True
        else:
            if success < 0.5:
                self._states[entity_id] = AdmissionState.QUARANTINE
                self._clear_window(entity_id)
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
                        self._clear_window(entity_id)
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
            failure_streak=self.warning_count(entity_id),
            certificate_successes=self._certificate_successes[entity_id],
            certificate_domains=len(self._certificate_domains[entity_id]),
            posterior_mean=posterior.mean,
            posterior_lcb=posterior.lower_credible_bound(self.bound_quantile),
        )
