#!/usr/bin/env python3
"""Prespecified 3x3 FSM threshold sensitivity for the pure SEARPC core."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from statistics import mean

from run_participation import load_risk_stream, run_repeat, write_csv


FAILURE_TRIGGERS = (2, 3, 4)
RECOVERY_SUCCESSES = (3, 5, 10)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--risk-stream", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    streams, _ = load_risk_stream(args.risk_stream)
    raw = []
    summary = []
    for failure_trigger in FAILURE_TRIGGERS:
        for recovery_successes in RECOVERY_SUCCESSES:
            condition = []
            for repeat, attack, seed, stream in streams:
                print(
                    "fsm-sensitivity",
                    failure_trigger,
                    recovery_successes,
                    repeat,
                    flush=True,
                )
                condition.extend(
                    run_repeat(
                        repeat,
                        attack,
                        seed,
                        stream,
                        audit_regime="adaptive",
                        selected_methods=("validator_only",),
                        failure_trigger=failure_trigger,
                        recovery_successes=recovery_successes,
                    )
                )
            for row in condition:
                raw.append({
                    "failure_trigger": failure_trigger,
                    "recovery_successes": recovery_successes,
                    **row,
                })
            denominator = sum(row["risk_score"] for row in condition)
            summary.append({
                "failure_trigger": failure_trigger,
                "recovery_successes": recovery_successes,
                "traces": len({row["repeat"] for row in condition}),
                "blocks": len(condition),
                "risk_weighted_exposure": sum(
                    row["risk_score"]
                    * row["latent_post_control_exceedance"]
                    for row in condition
                )
                / denominator,
                "latent_post_control_rate": mean(
                    row["latent_post_control_exceedance"]
                    for row in condition
                ),
                "standard_path_handoff_rate": mean(
                    row["actual_handoff"] for row in condition
                ),
                "resampling_rate": mean(
                    row["resampled"] for row in condition
                ),
                "direct_standard_rate": mean(
                    row["direct_standard"] for row in condition
                ),
                "mean_active_pool": mean(
                    row["active_pool"] for row in condition
                ),
                "mean_quarantined": mean(
                    row["quarantined"] for row in condition
                ),
                "mean_audits": mean(row["audits"] for row in condition),
                "mean_wire_messages": mean(
                    row["total_wire_messages"] for row in condition
                ),
                "final_Q_min": min(row["final_Q"] for row in condition),
                "final_Q_max": max(row["final_Q"] for row in condition),
                "illegal_acceptance": sum(
                    row["final_illegal_acceptance"] for row in condition
                ),
            })
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(
        args.output_dir / "FSM_SENSITIVITY_block_level.csv",
        raw,
    )
    write_csv(
        args.output_dir / "FSM_SENSITIVITY_summary.csv",
        summary,
    )
    manifest = {
        "failure_triggers": FAILURE_TRIGGERS,
        "recovery_successes": RECOVERY_SUCCESSES,
        "risk_stream": str(args.risk_stream),
        "risk_stream_sha256": digest(args.risk_stream),
        "runner_sha256": digest(Path(__file__)),
        "rq4_runner_sha256": digest(
            Path(__file__).with_name("run_participation.py")
        ),
        "rows": len(raw),
    }
    (
        args.output_dir / "FSM_SENSITIVITY_manifest.json"
    ).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
