#!/usr/bin/env python3
"""Recompute safety/coverage reports from bundled per-seed authorization counts."""

from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
import math
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "artifact" / "code" / "extensions"))
import analyze_searpc_twsl_pareto as analysis

RAW = ROOT / "artifact" / "results" / "safety_coverage" / "pareto_raw.csv"
RAW_SHA256 = "ae401d6921a887ac969d0fe0c69535cc96690ad6778715d16f2b9730d6ede02d"
FIGURE_DATA = ROOT / "figures" / "experimental" / "fig5_to_fig11" / "data"


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def compare(generated, reference):
    with generated.open(newline="") as handle:
        observed = list(csv.DictReader(handle))
    with reference.open(newline="") as handle:
        frozen = list(csv.DictReader(handle))
    if len(observed) != len(frozen):
        raise AssertionError(f"Report cardinality differs: {generated.name}")
    for index, (left, right) in enumerate(zip(observed, frozen)):
        for field, value in right.items():
            if value == left.get(field):
                continue
            try:
                actual, expected = float(left[field]), float(value)
                equal = (math.isnan(actual) and math.isnan(expected)) or math.isclose(actual, expected, rel_tol=1e-10, abs_tol=1e-12)
            except (ValueError, KeyError):
                equal = False
            if not equal:
                raise AssertionError(f"Report differs: {generated.name}, row {index}, {field}")
    return {"rows": len(frozen), "pass": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    output = args.output_dir.resolve()
    if output == ROOT or (ROOT in output.parents and ROOT / "outputs" not in output.parents):
        parser.error("Repository outputs must be below outputs/")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Refusing to overwrite a non-empty output directory")
    if digest(RAW) != RAW_SHA256:
        raise ValueError("Authorization-count input hash mismatch")
    gates = ROOT / "artifact" / "results" / "safety_coverage"
    for name in ("pareto_original5_replay.json", "pareto_readout_dynamics_gate.json"):
        if not json.loads((gates / name).read_text()).get("overall_pass"):
            raise ValueError(f"Registered replay gate did not pass: {name}")
    raw = pd.read_csv(RAW).sort_values(analysis.KEY).reset_index(drop=True)
    audit = analysis.validate(raw)
    if not audit["overall_complete"]:
        raise AssertionError(audit)
    output.mkdir(parents=True, exist_ok=True)
    summary = analysis.summarize(raw)
    products = {
        "pareto_summary.csv": summary,
        "pareto_frontier.csv": analysis.frontier(summary),
        "pareto_risk_budget.csv": analysis.risk_budget_table(summary),
        "pareto_matched_coverage.csv": analysis.matched_coverage_table(summary),
        "pareto_primary_point_seed20.csv": summary[summary.threshold == 0.50].copy(),
    }
    checked = {}
    for name, frame in products.items():
        path = output / name
        frame.to_csv(path, index=False)
        checked[name] = compare(path, FIGURE_DATA / name)
    result = {"mode": "bundled per-seed authorization-count reporting",
              "raw_sha256": RAW_SHA256, "raw_rows": len(raw), "seed_count": 20,
              "replays_trajectory_baseline": False, "validation": audit,
              "reference_comparisons": checked,
              "outputs": {name: digest(output / name) for name in products}}
    (output / "VERIFICATION.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Safety/coverage reporting: PASS (21,840 per-seed rows; five original reports checked)")


if __name__ == "__main__":
    main()
