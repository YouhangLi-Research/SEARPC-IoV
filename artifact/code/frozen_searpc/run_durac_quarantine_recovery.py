#!/usr/bin/env python3
"""Recovered constructor for the legacy quarantine stress runner."""

from __future__ import annotations

from durac import ValidatorReputationTracker
from run_durac_validator_recovery import INITIAL_EVIDENCE, _initial_means


def _quarantine_tracker() -> ValidatorReputationTracker:
    return ValidatorReputationTracker(
        _initial_means(),
        initial_evidence=INITIAL_EVIDENCE,
        bound_quantile=0.05,
        failure_trigger=3,
        quarantine_on_change=True,
        recovery_successes=5,
    )


__all__ = ["_quarantine_tracker"]
