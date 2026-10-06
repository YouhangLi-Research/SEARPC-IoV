#!/usr/bin/env python3
"""observable selection committee conditioned rerun with observable-only online fast-hint decisions.

The frozen base simulation runner is reused for the attack/audit/admission schedule, but its
legacy oracle-coupled consensus simulator is replaced by the observable selection simulation
adapter. The adapter converts hidden labels into an observable signature
transcript *outside* the controller, then the controller makes its path decision
without label access.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN = ROOT / "code" / "frozen_searpc"
sys.path.insert(0, str(FROZEN))
sys.path.insert(0, str(HERE))

import run_committee_conditioned as phase16
from observable_fast_path import simulate_observable_consensus

OUTPUT = ROOT / "results" / "observable_selection" / "rq4_observable"


def main() -> None:
    # Simulation harness injection only.  The online controller underneath this
    # adapter (plan_fast_path + decide_from_observation) has no label argument.
    phase16.execute_certified_committee_consensus = simulate_observable_consensus
    phase16._simulate_main(OUTPUT)


if __name__ == "__main__":
    main()
