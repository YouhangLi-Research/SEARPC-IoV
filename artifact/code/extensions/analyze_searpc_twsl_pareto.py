#!/usr/bin/env python3
"""Aggregate the preregistered SEARPC-vs-TWSL safety-coverage sweep."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
from pathlib import Path

import numpy as np
import pandas as pd
import scipy
from scipy.stats import t


SEEDS = tuple(range(260825, 260845))
ATTACKS = ("dataReplay", "timeDelayAttack")
OVERLAPS = (0.0, 0.5, 1.0)
METHODS = ("SEARPC", "TWSL")
THRESHOLDS = tuple(round(value / 100.0, 2) for value in range(5, 96))
RISK_BUDGETS = (0.0, 0.005, 0.010, 0.020)
COVERAGE_TARGETS = (0.80, 0.85, 0.90, 0.95)
COVERAGE_TOLERANCE = 0.005
KEY = ["seed", "attack", "overlap", "method", "threshold"]


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def ci(values: np.ndarray) -> tuple[float, float, float, float, float]:
    x = np.asarray(values, dtype=float)
    n = len(x)
    mean = float(np.mean(x))
    sd = float(np.std(x, ddof=1))
    critical = float(t.ppf(0.975, n - 1))
    half = critical * sd / math.sqrt(n)
    return mean, sd, mean - half, mean + half, critical


def validate(raw: pd.DataFrame) -> dict:
    expected_rows = len(SEEDS) * len(ATTACKS) * len(OVERLAPS) * len(METHODS) * len(THRESHOLDS)
    required = set(KEY) | {
        "benign_total", "benign_trusted", "benign_coverage",
        "malicious_total", "malicious_trusted", "malicious_trusted_rate",
    }
    checks = {
        "raw_rows_21840": len(raw) == expected_rows,
        "required_columns_present": required <= set(raw.columns),
        "duplicate_primary_keys_zero": int(raw.duplicated(KEY).sum()) == 0,
        "seed_set_exact": sorted(int(v) for v in raw.seed.unique()) == list(SEEDS),
        "attack_set_exact": sorted(raw.attack.unique()) == sorted(ATTACKS),
        "overlap_set_exact": sorted(float(v) for v in raw.overlap.unique()) == list(OVERLAPS),
        "method_set_exact": sorted(raw.method.unique()) == sorted(METHODS),
        "threshold_grid_exact": sorted(float(v) for v in raw.threshold.unique()) == list(THRESHOLDS),
        "counts_nonnegative": bool((raw[["benign_total", "benign_trusted", "malicious_total", "malicious_trusted"]] >= 0).all().all()),
        "trusted_counts_bounded": bool((raw.benign_trusted <= raw.benign_total).all() and (raw.malicious_trusted <= raw.malicious_total).all()),
    }
    recomputed_coverage = raw.benign_trusted / raw.benign_total
    recomputed_risk = raw.malicious_trusted / raw.malicious_total
    checks["coverage_ratio_exact"] = bool(np.allclose(raw.benign_coverage, recomputed_coverage, rtol=0, atol=1e-15))
    checks["risk_ratio_exact"] = bool(np.allclose(raw.malicious_trusted_rate, recomputed_risk, rtol=0, atol=1e-15))
    checks["overall_complete"] = all(checks.values())
    return {**checks, "raw_rows": len(raw), "expected_rows": expected_rows}


def summarize(raw: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for group, members in raw.groupby(["attack", "overlap", "method", "threshold"], sort=True):
        attack, overlap, method, threshold = group
        coverage = ci(members.benign_coverage.to_numpy(float))
        risk = ci(members.malicious_trusted_rate.to_numpy(float))
        rows.append({
            "attack": attack,
            "overlap": overlap,
            "method": method,
            "threshold": threshold,
            "n_seeds": len(members),
            "df": len(members) - 1,
            "t_critical": coverage[4],
            "benign_coverage_mean": coverage[0],
            "benign_coverage_sd": coverage[1],
            "benign_coverage_ci95_low": coverage[2],
            "benign_coverage_ci95_high": coverage[3],
            "malicious_trusted_rate_mean": risk[0],
            "malicious_trusted_rate_sd": risk[1],
            "malicious_trusted_rate_ci95_low": risk[2],
            "malicious_trusted_rate_ci95_high": risk[3],
            "benign_total_per_seed": int(members.benign_total.iloc[0]),
            "malicious_total_per_seed": int(members.malicious_total.iloc[0]),
        })
    return pd.DataFrame(rows)


def frontier(summary: pd.DataFrame) -> pd.DataFrame:
    frames = []
    tolerance = 1e-15
    for _, members in summary.groupby(["attack", "overlap", "method"], sort=True):
        coverage = members.benign_coverage_mean.to_numpy(float)
        risk = members.malicious_trusted_rate_mean.to_numpy(float)
        nondominated = []
        for index in range(len(members)):
            weak = (coverage >= coverage[index] - tolerance) & (risk <= risk[index] + tolerance)
            strict = (coverage > coverage[index] + tolerance) | (risk < risk[index] - tolerance)
            nondominated.append(not bool(np.any(weak & strict)))
        selected = members.loc[np.asarray(nondominated)].copy()
        selected["frontier_rank_by_coverage"] = selected.benign_coverage_mean.rank(method="dense").astype(int)
        frames.append(selected.sort_values(["benign_coverage_mean", "malicious_trusted_rate_mean", "threshold"]))
    return pd.concat(frames, ignore_index=True)


def risk_budget_table(summary: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for (attack, overlap, method), members in summary.groupby(["attack", "overlap", "method"], sort=True):
        for budget in RISK_BUDGETS:
            feasible = members[members.malicious_trusted_rate_mean <= budget + 1e-15]
            if feasible.empty:
                rows.append({
                    "attack": attack, "overlap": overlap, "method": method,
                    "risk_budget": budget, "feasible": False,
                    "selected_threshold": math.nan,
                    "max_benign_coverage": math.nan,
                    "malicious_trusted_rate": math.nan,
                })
                continue
            chosen = feasible.sort_values(
                ["benign_coverage_mean", "malicious_trusted_rate_mean", "threshold"],
                ascending=[False, True, False],
            ).iloc[0]
            rows.append({
                "attack": attack, "overlap": overlap, "method": method,
                "risk_budget": budget, "feasible": True,
                "selected_threshold": chosen.threshold,
                "max_benign_coverage": chosen.benign_coverage_mean,
                "malicious_trusted_rate": chosen.malicious_trusted_rate_mean,
                "coverage_ci95_low": chosen.benign_coverage_ci95_low,
                "coverage_ci95_high": chosen.benign_coverage_ci95_high,
            })
    return pd.DataFrame(rows)


def matched_coverage_table(summary: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict] = []
    for (attack, overlap, method), members in summary.groupby(["attack", "overlap", "method"], sort=True):
        for target in COVERAGE_TARGETS:
            candidates = members.copy()
            candidates["coverage_distance"] = np.abs(candidates.benign_coverage_mean - target)
            feasible = candidates[candidates.coverage_distance <= COVERAGE_TOLERANCE + 1e-15]
            if feasible.empty:
                rows.append({
                    "attack": attack, "overlap": overlap, "method": method,
                    "coverage_target": target, "tolerance": COVERAGE_TOLERANCE,
                    "available": False, "selected_threshold": math.nan,
                    "achieved_coverage": math.nan, "malicious_trusted_rate": math.nan,
                })
                continue
            chosen = feasible.sort_values(
                ["coverage_distance", "malicious_trusted_rate_mean", "threshold"],
                ascending=[True, True, False],
            ).iloc[0]
            rows.append({
                "attack": attack, "overlap": overlap, "method": method,
                "coverage_target": target, "tolerance": COVERAGE_TOLERANCE,
                "available": True, "selected_threshold": chosen.threshold,
                "achieved_coverage": chosen.benign_coverage_mean,
                "coverage_distance": chosen.coverage_distance,
                "malicious_trusted_rate": chosen.malicious_trusted_rate_mean,
                "risk_ci95_low": chosen.malicious_trusted_rate_ci95_low,
                "risk_ci95_high": chosen.malicious_trusted_rate_ci95_high,
            })
    return pd.DataFrame(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw", type=Path, nargs=4, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--original5-replay", type=Path, required=True)
    parser.add_argument("--readout-gate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    original_gate = json.loads(args.original5_replay.read_text(encoding="utf-8"))
    readout_gate = json.loads(args.readout_gate.read_text(encoding="utf-8"))
    if not original_gate.get("overall_pass") or not readout_gate.get("overall_pass"):
        raise RuntimeError("Pareto preregistered replay gates did not pass")

    raw = pd.concat([pd.read_csv(path) for path in args.raw], ignore_index=True)
    raw = raw.sort_values(KEY).reset_index(drop=True)
    audit = validate(raw)
    if not audit["overall_complete"]:
        raise RuntimeError(json.dumps(audit, indent=2))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    raw.to_csv(args.output_dir / "pareto_raw.csv", index=False)
    summary = summarize(raw)
    frontier_rows = frontier(summary)
    risk_budget = risk_budget_table(summary)
    matched_coverage = matched_coverage_table(summary)
    primary = summary[summary.threshold == 0.50].copy()
    summary.to_csv(args.output_dir / "pareto_summary.csv", index=False)
    frontier_rows.to_csv(args.output_dir / "pareto_frontier.csv", index=False)
    risk_budget.to_csv(args.output_dir / "pareto_risk_budget.csv", index=False)
    matched_coverage.to_csv(args.output_dir / "pareto_matched_coverage.csv", index=False)
    primary.to_csv(args.output_dir / "pareto_primary_point_seed20.csv", index=False)

    audit.update({
        "protocol_sha256": digest(args.protocol),
        "original5_replay_pass": True,
        "readout_dynamics_gate_pass": True,
        "summary_rows_1092": len(summary) == 1092,
        "all_six_conditions_present": summary[["attack", "overlap"]].drop_duplicates().shape[0] == 6,
        "risk_budget_rows_48": len(risk_budget) == 48,
        "matched_coverage_rows_48": len(matched_coverage) == 48,
        "primary_point_rows_12": len(primary) == 12,
        "frontier_rows": len(frontier_rows),
    })
    audit["pareto_analysis_pass"] = all(
        audit[key]
        for key in (
            "overall_complete", "original5_replay_pass", "readout_dynamics_gate_pass",
            "summary_rows_1092", "all_six_conditions_present", "risk_budget_rows_48",
            "matched_coverage_rows_48", "primary_point_rows_12",
        )
    )
    (args.output_dir / "PARETO_COMPLETENESS_AUDIT.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True), encoding="utf-8"
    )
    manifest = {
        "protocol_sha256": digest(args.protocol),
        "analysis_runner_sha256": digest(Path(__file__)),
        "original5_replay_sha256": digest(args.original5_replay),
        "readout_gate_sha256": digest(args.readout_gate),
        "input_raw": {path.name: digest(path) for path in args.raw},
        "python": platform.python_version(),
        "numpy": np.__version__,
        "pandas": pd.__version__,
        "scipy": scipy.__version__,
        "outputs": {
            path.name: digest(path)
            for path in sorted(args.output_dir.glob("*.csv"))
        },
    }
    (args.output_dir / "PARETO_ANALYSIS_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(json.dumps(audit, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
