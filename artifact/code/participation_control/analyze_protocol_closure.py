#!/usr/bin/env python3
"""Trace-paired inference for the participation control protocol-closure reruns."""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import random
from pathlib import Path
from statistics import mean


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, rows):
    if not rows:
        raise ValueError("empty output")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def trace_metrics(rows):
    groups = {}
    for row in rows:
        key = (row["audit_regime"], int(row["repeat"]), row["method"])
        groups.setdefault(key, []).append(row)
    output = {}
    for key, values in groups.items():
        risk = [float(item["risk_score"]) for item in values]
        latent = [
            int(item["latent_post_control_exceedance"])
            for item in values
        ]
        denominator = sum(risk)
        output[key] = {
            "exposure": sum(
                score * outcome
                for score, outcome in zip(risk, latent)
            )
            / denominator,
            "latent": mean(latent),
            "handoff": mean(
                int(item["actual_handoff"]) for item in values
            ),
            "wire": mean(
                float(item["total_wire_messages"]) for item in values
            ),
        }
    return output


def exact_sign_flip_pvalue(differences):
    observed = abs(mean(differences))
    exceed = 0
    total = 0
    for signs in itertools.product((-1.0, 1.0), repeat=len(differences)):
        statistic = abs(
            mean(sign * value for sign, value in zip(signs, differences))
        )
        exceed += int(statistic >= observed - 1e-15)
        total += 1
    return exceed / total


def paired_rows(
    metrics,
    *,
    regime,
    comparisons,
    draws=20000,
    bootstrap_seed=351001,
):
    output = []
    for comparison_index, (baseline, target) in enumerate(comparisons):
        for metric_index, metric in enumerate(
            ("exposure", "latent", "handoff", "wire")
        ):
            repeats = sorted({
                repeat
                for current_regime, repeat, method in metrics
                if current_regime == regime
                and method in {baseline, target}
            })
            differences = [
                metrics[(regime, repeat, target)][metric]
                - metrics[(regime, repeat, baseline)][metric]
                for repeat in repeats
            ]
            rng = random.Random(
                bootstrap_seed
                + 100 * comparison_index
                + metric_index
            )
            bootstrap = sorted(
                mean(
                    differences[rng.randrange(len(differences))]
                    for _ in differences
                )
                for _ in range(draws)
            )
            low = bootstrap[int(0.025 * draws)]
            high = bootstrap[min(draws - 1, int(0.975 * draws))]
            output.append({
                "audit_regime": regime,
                "baseline": baseline,
                "target": target,
                "metric": metric,
                "n_traces": len(repeats),
                "paired_mean_difference": mean(differences),
                "ci95_low": low,
                "ci95_high": high,
                "exact_sign_flip_p": exact_sign_flip_pvalue(differences),
                "bootstrap_draws": draws,
            })
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rq4-blocks", type=Path, required=True)
    parser.add_argument("--equal-budget-blocks", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    main_rows = read_csv(args.rq4_blocks)
    equal_rows = read_csv(args.equal_budget_blocks)
    for row in main_rows:
        row["audit_regime"] = "adaptive"
    main_metrics = trace_metrics(main_rows)
    equal_metrics = trace_metrics(
        [row for row in equal_rows if row["audit_regime"] == "equal_budget"]
    )
    adaptive = paired_rows(
        main_metrics,
        regime="adaptive",
        comparisons=(
            ("feedback_fixed", "validator_only"),
            ("feedback_fixed", "searpc"),
            ("validator_only", "searpc"),
        ),
    )
    equal = paired_rows(
        equal_metrics,
        regime="equal_budget",
        comparisons=(
            ("feedback_fixed", "validator_only"),
            ("validator_only", "searpc"),
        ),
        bootstrap_seed=351501,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        args.output_dir / "RQ4_PAIRED_TRACE_BOOTSTRAP.csv",
        adaptive,
    )
    write_csv(
        args.output_dir / "EQUAL_BUDGET_PAIRED_TRACE_BOOTSTRAP.csv",
        equal,
    )
    manifest = {
        "rq4_blocks": str(args.rq4_blocks),
        "rq4_blocks_sha256": digest(args.rq4_blocks),
        "equal_budget_blocks": str(args.equal_budget_blocks),
        "equal_budget_blocks_sha256": digest(args.equal_budget_blocks),
        "runner_sha256": digest(Path(__file__)),
        "bootstrap_draws": 20000,
        "inferential_unit": "paired trace",
    }
    (
        args.output_dir / "PAIRED_INFERENCE_manifest.json"
    ).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
