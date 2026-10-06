#!/usr/bin/env python3
"""Recovered shared constructors used by the frozen validator experiments.

The earlier experiment artifact retained the admission implementation but omitted
this thin constructor module.  Reintroducing it makes closed loop--16 executable
without changing any scientific parameter.
"""

from __future__ import annotations

from durac import ValidatorAdmissionTracker
from run_durac_validator_recovery import INITIAL_EVIDENCE, _initial_means


def _v2_tracker() -> ValidatorAdmissionTracker:
    """Construct the frozen active--quarantine--probation tracker."""

    return ValidatorAdmissionTracker(
        _initial_means(),
        initial_evidence=INITIAL_EVIDENCE,
        bound_quantile=0.05,
        failure_trigger=3,
        probation_successes=5,
        activation_successes=5,
        minimum_audit_domains=2,
    )


__all__ = ["_v2_tracker"]
