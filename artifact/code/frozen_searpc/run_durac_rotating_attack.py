#!/usr/bin/env python3
"""Registered rotating/on-off validator compromise experiment."""

from __future__ import annotations

from collections import defaultdict
import csv
from hashlib import sha256
import json
import math
import os
from pathlib import Path
from random import Random
from statistics import mean, stdev

from durac import (
    CommitteeMethod,
    RiskLevel,
    UnsafeCommitteeError,
    committee_failure_probability,
    evaluate_committee_security,
    pbft_protocol_message_count,
    select_committee_leader,
    select_risk_constrained_committee,
    select_size_matched_committee,
)
from run_durac_audit_sensitivity import (
    AUDIT_BYTES,
    AUDIT_CPU_MS,
)
from run_durac_quarantine_recovery import _quarantine_tracker
from run_durac_validator_recovery import (
    _committee,
    _domains,
    _latencies,
    _tracker,
)


METHODS = (
    "fixed_full_cbtds",
    "durac_static",
    "durac_changepoint",
    "durac_quarantine",
)
REPEATS = 10
BLOCKS = 600
COVERAGE = 0.50
ERROR_RATE = 0.05
DELAY = 10
BASE_SEED = 66109
AUDIT_BANDWIDTH_BPS = 20_000_000.0
AUDIT_ONE_WAY_LATENCY_S = 0.005
OUTPUT_DIR = Path("results/durac_rotating_attack_v1")
ASSUMPTIONS = Path("DURAC_ROTATING_ATTACK_V1_ASSUMPTIONS.md")
EPOCHS = (
    ("warmup", 1, 200),
    ("a1_early", 201, 250),
    ("a1_late", 251, 300),
    ("b_early", 301, 350),
    ("b_late", 351, 400),
    ("c_early", 401, 450),
    ("c_late", 451, 500),
    ("a2_early", 501, 550),
    ("a2_late", 551, 600),
)
LATE_EPOCHS = ("a1_late", "b_late", "c_late", "a2_late")


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _epoch(block: int) -> str:
    for name, start, end in EPOCHS:
        if start <= block <= end:
            return name
    raise ValueError("block outside registered epochs")


def _paired_uniform(*, repeat: int, block: int, validator_id: int, stream: int) -> float:
    return Random(
        BASE_SEED
        + repeat * 10_000_000
        + block * 10_000
        + validator_id * 10
        + stream
    ).random()


def _audit_success(
    *, repeat: int, block: int, validator_id: int, compromised: frozenset[int]
) -> float:
    success = validator_id not in compromised
    if _paired_uniform(
        repeat=repeat, block=block, validator_id=validator_id, stream=2
    ) < ERROR_RATE:
        success = not success
    return float(success)


def _compromised(
    block: int,
    cohort_a: frozenset[int],
    cohort_b: frozenset[int],
    cohort_c: frozenset[int],
) -> frozenset[int]:
    if 201 <= block <= 300 or 501 <= block <= 600:
        return cohort_a
    if 301 <= block <= 400:
        return cohort_b
    if 401 <= block <= 500:
        return cohort_c
    return frozenset()


def _empty() -> dict[str, float]:
    return {
        field: 0.0
        for field in (
            "attempted",
            "evaluated",
            "refused",
            "breached",
            "illegal",
            "first_commit",
            "eventual_commit",
            "view_change",
            "committee_size",
            "captured_fraction",
            "estimated_failure",
            "protocol_messages",
            "committee_audits",
            "probation_audits",
            "audit_bytes",
            "audit_cpu_ms",
            "audit_background_s",
            "true_detections",
            "false_detections",
            "honest_recoveries",
            "compromised_recoveries",
            "quarantined_count",
            "eligible_pool_size",
        )
    }


def _row(repeat: int, epoch: str, method: str, values: dict[str, float]) -> dict:
    attempted = int(values["attempted"])
    evaluated = int(values["evaluated"])

    def per_attempt(field: str) -> float:
        return values[field] / attempted

    def per_evaluated(field: str) -> float:
        return values[field] / evaluated if evaluated else math.nan

    return {
        "repeat": repeat,
        "epoch": epoch,
        "method": method,
        "attempted_blocks": attempted,
        "evaluated_blocks": evaluated,
        "safe_refusals": int(values["refused"]),
        "safety_budget_breaches": int(values["breached"]),
        "illegal_blocks_accepted": int(values["illegal"]),
        "safe_refusal_rate": per_attempt("refused"),
        "safety_budget_breach_rate": per_evaluated("breached"),
        "illegal_block_acceptance_rate": per_evaluated("illegal"),
        "legal_first_round_commit_rate": per_evaluated("first_commit"),
        "legal_eventual_commit_rate": per_evaluated("eventual_commit"),
        "view_change_rate": per_evaluated("view_change"),
        "mean_committee_size": per_evaluated("committee_size"),
        "mean_selected_compromised_fraction": per_evaluated("captured_fraction"),
        "mean_estimated_failure_probability": per_evaluated("estimated_failure"),
        "mean_protocol_message_count": per_evaluated("protocol_messages"),
        "mean_committee_audits_per_block": per_attempt("committee_audits"),
        "mean_probation_audits_per_block": per_attempt("probation_audits"),
        "mean_audit_bytes_per_block": per_attempt("audit_bytes"),
        "mean_audit_cpu_ms_per_block": per_attempt("audit_cpu_ms"),
        "mean_audit_background_time_s_per_block": per_attempt(
            "audit_background_s"
        ),
        "true_detections": int(values["true_detections"]),
        "false_detections": int(values["false_detections"]),
        "honest_recoveries": int(values["honest_recoveries"]),
        "compromised_recoveries": int(values["compromised_recoveries"]),
        "mean_quarantined_count": per_attempt("quarantined_count"),
        "mean_eligible_pool_size": per_attempt("eligible_pool_size"),
    }


def _finite(values: list[float]) -> tuple[float, float]:
    values = [value for value in values if math.isfinite(value)]
    if not values:
        return math.nan, math.nan
    return mean(values), stdev(values) if len(values) > 1 else 0.0


def _summary(rows: list[dict]) -> list[dict]:
    output = []
    numeric = (
        "safe_refusal_rate",
        "safety_budget_breach_rate",
        "illegal_block_acceptance_rate",
        "legal_first_round_commit_rate",
        "legal_eventual_commit_rate",
        "view_change_rate",
        "mean_committee_size",
        "mean_selected_compromised_fraction",
        "mean_estimated_failure_probability",
        "mean_protocol_message_count",
        "mean_committee_audits_per_block",
        "mean_probation_audits_per_block",
        "mean_audit_bytes_per_block",
        "mean_audit_cpu_ms_per_block",
        "mean_audit_background_time_s_per_block",
        "mean_quarantined_count",
        "mean_eligible_pool_size",
    )
    for epoch, _, _ in EPOCHS:
        for method in METHODS:
            subset = [
                row for row in rows if row["epoch"] == epoch and row["method"] == method
            ]
            attempted = sum(row["attempted_blocks"] for row in subset)
            evaluated = sum(row["evaluated_blocks"] for row in subset)
            item = {
                "epoch": epoch,
                "method": method,
                "repeats": len(subset),
                "attempted_blocks": attempted,
                "evaluated_blocks": evaluated,
                "safe_refusals": sum(row["safe_refusals"] for row in subset),
                "safety_budget_breaches": sum(
                    row["safety_budget_breaches"] for row in subset
                ),
                "illegal_blocks_accepted": sum(
                    row["illegal_blocks_accepted"] for row in subset
                ),
                "true_detections": sum(row["true_detections"] for row in subset),
                "false_detections": sum(row["false_detections"] for row in subset),
                "honest_recoveries": sum(row["honest_recoveries"] for row in subset),
                "compromised_recoveries": sum(
                    row["compromised_recoveries"] for row in subset
                ),
            }
            item["safe_refusal_rate"] = item["safe_refusals"] / attempted
            item["safety_budget_breach_rate"] = (
                item["safety_budget_breaches"] / evaluated
                if evaluated
                else math.nan
            )
            item["illegal_block_acceptance_rate"] = (
                item["illegal_blocks_accepted"] / evaluated
                if evaluated
                else math.nan
            )
            for field in numeric:
                avg, std = _finite([float(row[field]) for row in subset])
                if field not in item:
                    item[field] = avg
                item[f"{field}_repeat_std"] = std
            output.append(item)
    return output


def _plot(path: Path, time_rows: list[dict]) -> None:
    matplotlib_dir = path.parent / ".matplotlib"
    matplotlib_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(matplotlib_dir.resolve()))
    import matplotlib.pyplot as plt

    colors = {
        "fixed_full_cbtds": "#475569",
        "durac_static": "#F59E0B",
        "durac_changepoint": "#84CC16",
        "durac_quarantine": "#15803D",
    }
    fig, axes = plt.subplots(2, 2, figsize=(13.8, 8.4), constrained_layout=True)
    fields = (
        ("safety_budget_breach_rate", "Rolling B > f"),
        ("safe_refusal_rate", "Rolling safe refusal"),
        ("mean_selected_compromised_fraction", "Selected compromised fraction"),
        ("mean_committee_size", "Committee size"),
    )
    for axis, (field, title) in zip(axes.flat, fields):
        for method in METHODS:
            subset = [row for row in time_rows if row["method"] == method]
            values = [float(row[field]) for row in subset]
            if "rate" in field or "fraction" in field:
                smoothed = []
                for index in range(len(values)):
                    finite = [
                        value
                        for value in values[max(0, index - 24) : index + 1]
                        if math.isfinite(value)
                    ]
                    smoothed.append(mean(finite) if finite else math.nan)
                values = smoothed
            axis.plot(
                [row["block"] for row in subset],
                values,
                color=colors[method],
                linewidth=1.6,
                label=method,
            )
        for boundary in (201, 301, 401, 501):
            axis.axvline(boundary, color="#111827", linestyle="--", linewidth=0.9)
        axis.set(xlabel="Block", ylabel=title, title=title)
        axis.grid(True, alpha=0.22)
        axis.spines[["top", "right"]].set_visible(False)
    axes[0, 0].legend(fontsize=7)
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    domains = _domains()
    latencies = _latencies()
    base_tracker = _tracker(3)
    base_candidates = base_tracker.candidates(
        domains=domains, latencies_ms=latencies
    )
    ranked = sorted(
        base_candidates,
        key=lambda candidate: (-candidate.honesty_lcb, candidate.validator_id),
    )
    cohort_a = frozenset(item.validator_id for item in ranked[0:12])
    cohort_b = frozenset(item.validator_id for item in ranked[12:24])
    cohort_c = frozenset(item.validator_id for item in ranked[24:36])
    assumed_domains = {
        f"domain-{domain_index}": 0.001 for domain_index in range(6)
    }
    repeat_rows: list[dict] = []
    time_run_rows: list[dict] = []

    for repeat in range(1, REPEATS + 1):
        print(f"[repeat={repeat}]", flush=True)
        trackers = {
            "durac_changepoint": _tracker(3),
            "durac_quarantine": _quarantine_tracker(),
        }
        queues: dict[str, dict[int, list[tuple[int, float]]]] = {
            method: defaultdict(list) for method in trackers
        }
        false_pairs = {method: set() for method in trackers}
        true_pairs = {method: set() for method in trackers}
        accumulators = {
            (epoch, method): _empty()
            for epoch, _, _ in EPOCHS
            for method in METHODS
        }

        for block in range(1, BLOCKS + 1):
            epoch = _epoch(block)
            compromised = _compromised(
                block, cohort_a, cohort_b, cohort_c
            )
            for method, tracker in trackers.items():
                accumulator = accumulators[(epoch, method)]
                for validator_id, success in queues[method].pop(block, []):
                    update = tracker.update(validator_id, success)
                    if update.change_detected:
                        target = true_pairs[method] if validator_id in compromised else false_pairs[method]
                        field = "true_detections" if validator_id in compromised else "false_detections"
                        if validator_id not in target:
                            accumulator[field] += 1
                            target.add(validator_id)
                    if update.recovered:
                        field = (
                            "compromised_recoveries"
                            if validator_id in compromised
                            else "honest_recoveries"
                        )
                        accumulator[field] += 1

            for method_index, method in enumerate(METHODS):
                accumulator = accumulators[(epoch, method)]
                accumulator["attempted"] += 1
                seed = (
                    BASE_SEED
                    + repeat * 10_000_000
                    + block * 10_000
                    + method_index * 100
                )
                event_id = f"rotate-{repeat}-{block}-{method}"

                probation_audits = 0
                if method == "durac_quarantine":
                    tracker = trackers[method]
                    for validator_id in sorted(tracker.quarantined_ids):
                        if _paired_uniform(
                            repeat=repeat,
                            block=block,
                            validator_id=int(validator_id),
                            stream=1,
                        ) < COVERAGE:
                            probation_audits += 1
                            success = _audit_success(
                                repeat=repeat,
                                block=block,
                                validator_id=int(validator_id),
                                compromised=compromised,
                            )
                            if block + DELAY <= BLOCKS:
                                queues[method][block + DELAY].append(
                                    (int(validator_id), success)
                                )

                committee = None
                estimated_failure = math.nan
                try:
                    if method == "fixed_full_cbtds":
                        committee = select_size_matched_committee(
                            base_candidates,
                            size=40,
                            method=CommitteeMethod.FIXED_FULL_CBTDS,
                            seed=seed,
                            event_id=event_id,
                        )
                    elif method == "durac_static":
                        selection = select_risk_constrained_committee(
                            base_candidates,
                            risk_level=RiskLevel.HIGH,
                            seed=seed,
                            event_id=event_id,
                            domain_compromise_probability=assumed_domains,
                        )
                        by_id = {
                            candidate.validator_id: candidate
                            for candidate in base_candidates
                        }
                        committee = tuple(
                            by_id[validator_id] for validator_id in selection.member_ids
                        )
                    elif method == "durac_changepoint":
                        committee = _committee(
                            method,
                            base_candidates=base_candidates,
                            trackers=trackers,
                            domains=domains,
                            latencies=latencies,
                            assumed_domains=assumed_domains,
                            seed=seed,
                            event_id=event_id,
                        )
                    else:
                        candidates = trackers[method].candidates(
                            domains=domains,
                            latencies_ms=latencies,
                            eligible_only=True,
                        )
                        selection = select_risk_constrained_committee(
                            candidates,
                            risk_level=RiskLevel.HIGH,
                            seed=seed,
                            event_id=event_id,
                            domain_compromise_probability=assumed_domains,
                        )
                        by_id = {
                            candidate.validator_id: candidate
                            for candidate in candidates
                        }
                        committee = tuple(
                            by_id[validator_id] for validator_id in selection.member_ids
                        )
                except UnsafeCommitteeError:
                    accumulator["refused"] += 1

                committee_audits = 0
                captured = math.nan
                if method == "durac_quarantine":
                    accumulator["quarantined_count"] += len(
                        trackers[method].quarantined_ids
                    )
                    accumulator["eligible_pool_size"] += 40 - len(
                        trackers[method].quarantined_ids
                    )
                else:
                    accumulator["eligible_pool_size"] += 40

                if committee is not None:
                    leader = select_committee_leader(
                        committee,
                        seed=seed + 700_001,
                        event_id=event_id,
                        reputation_weighted=method != "fixed_full_cbtds",
                    )
                    outcome = evaluate_committee_security(
                        committee,
                        leader_id=leader.validator_id,
                        byzantine_ids=compromised,
                    )
                    estimated_failure = committee_failure_probability(
                        committee, assumed_domains
                    )
                    accumulator["evaluated"] += 1
                    accumulator["breached"] += outcome.safety_budget_breach
                    accumulator["illegal"] += outcome.illegal_block_accepted
                    accumulator["first_commit"] += outcome.legal_first_round_commit
                    accumulator["eventual_commit"] += outcome.legal_eventual_commit
                    accumulator["view_change"] += outcome.view_change
                    accumulator["committee_size"] += outcome.committee_size
                    captured = outcome.actual_byzantine / outcome.committee_size
                    accumulator["captured_fraction"] += captured
                    accumulator["estimated_failure"] += estimated_failure
                    accumulator["protocol_messages"] += pbft_protocol_message_count(
                        outcome.committee_size
                    )

                    if method in trackers:
                        for candidate in committee:
                            if _paired_uniform(
                                repeat=repeat,
                                block=block,
                                validator_id=candidate.validator_id,
                                stream=1,
                            ) < COVERAGE:
                                committee_audits += 1
                                success = _audit_success(
                                    repeat=repeat,
                                    block=block,
                                    validator_id=candidate.validator_id,
                                    compromised=compromised,
                                )
                                if block + DELAY <= BLOCKS:
                                    queues[method][block + DELAY].append(
                                        (candidate.validator_id, success)
                                    )

                total_audits = committee_audits + probation_audits
                audit_bytes = total_audits * AUDIT_BYTES
                accumulator["committee_audits"] += committee_audits
                accumulator["probation_audits"] += probation_audits
                accumulator["audit_bytes"] += audit_bytes
                accumulator["audit_cpu_ms"] += total_audits * AUDIT_CPU_MS
                if total_audits:
                    accumulator["audit_background_s"] += (
                        2 * AUDIT_ONE_WAY_LATENCY_S
                        + audit_bytes * 8 / AUDIT_BANDWIDTH_BPS
                    )
                time_run_rows.append(
                    {
                        "repeat": repeat,
                        "block": block,
                        "method": method,
                        "evaluated": int(committee is not None),
                        "safe_refusal": int(committee is None),
                        "safety_budget_breach": (
                            outcome.safety_budget_breach
                            if committee is not None
                            else 0
                        ),
                        "committee_size": (
                            outcome.committee_size if committee is not None else 0
                        ),
                        "selected_compromised_fraction": captured,
                    }
                )

        for epoch, _, _ in EPOCHS:
            for method in METHODS:
                repeat_rows.append(
                    _row(repeat, epoch, method, accumulators[(epoch, method)])
                )

    summary = _summary(repeat_rows)
    time_rows = []
    for block in range(1, BLOCKS + 1):
        for method in METHODS:
            subset = [
                row
                for row in time_run_rows
                if row["block"] == block and row["method"] == method
            ]
            evaluated = [row for row in subset if row["evaluated"]]
            time_rows.append(
                {
                    "block": block,
                    "method": method,
                    "safe_refusal_rate": mean(
                        row["safe_refusal"] for row in subset
                    ),
                    "safety_budget_breach_rate": (
                        mean(row["safety_budget_breach"] for row in evaluated)
                        if evaluated
                        else math.nan
                    ),
                    "mean_committee_size": (
                        mean(row["committee_size"] for row in evaluated)
                        if evaluated
                        else math.nan
                    ),
                    "mean_selected_compromised_fraction": (
                        mean(
                            row["selected_compromised_fraction"]
                            for row in evaluated
                        )
                        if evaluated
                        else math.nan
                    ),
                }
            )

    quarantine_late = [
        row
        for row in summary
        if row["method"] == "durac_quarantine" and row["epoch"] in LATE_EPOCHS
    ]
    false_detections = sum(
        row["false_detections"]
        for row in summary
        if row["method"] == "durac_quarantine"
    )
    compromised_recoveries = sum(
        row["compromised_recoveries"]
        for row in summary
        if row["method"] == "durac_quarantine"
    )
    checks = {
        "all_late_breach_pass": all(
            row["safety_budget_breach_rate"] <= 0.001
            for row in quarantine_late
        ),
        "all_late_illegal_pass": all(
            row["illegal_block_acceptance_rate"] <= 0.001
            for row in quarantine_late
        ),
        "all_late_refusal_pass": all(
            row["safe_refusal_rate"] <= 0.10 for row in quarantine_late
        ),
        "false_detection_pass": false_detections / (40 * REPEATS) <= 0.05,
        "compromised_recovery_pass": compromised_recoveries == 0,
        "a2_late_pass": next(
            row for row in quarantine_late if row["epoch"] == "a2_late"
        )["safety_budget_breach_rate"] <= 0.001,
    }
    go_no = [{
        **{key: int(value) for key, value in checks.items()},
        "false_detection_rate": false_detections / (40 * REPEATS),
        "compromised_recoveries": compromised_recoveries,
        "all_criteria_pass": int(all(checks.values())),
    }]
    for row in quarantine_late:
        go_no[0][f"{row['epoch']}_breach_rate"] = row[
            "safety_budget_breach_rate"
        ]
        go_no[0][f"{row['epoch']}_illegal_rate"] = row[
            "illegal_block_acceptance_rate"
        ]
        go_no[0][f"{row['epoch']}_refusal_rate"] = row["safe_refusal_rate"]

    paths = {
        "repeat_epoch": OUTPUT_DIR / "DURAC_rotating_repeat_epoch.csv",
        "summary": OUTPUT_DIR / "DURAC_rotating_summary.csv",
        "go_no": OUTPUT_DIR / "DURAC_rotating_go_no.csv",
        "time": OUTPUT_DIR / "DURAC_rotating_time.csv",
        "chart": OUTPUT_DIR / "DURAC_rotating.png",
    }
    _write_csv(paths["repeat_epoch"], repeat_rows)
    _write_csv(paths["summary"], summary)
    _write_csv(paths["go_no"], go_no)
    _write_csv(paths["time"], time_rows)
    _plot(paths["chart"], time_rows)
    manifest = {
        "protocol_status": "frozen before formal execution",
        "assumptions_sha256": _sha256(ASSUMPTIONS),
        "repeats": REPEATS,
        "blocks": BLOCKS,
        "methods": list(METHODS),
        "cohort_hashes": {
            name: sha256(
                ",".join(map(str, sorted(cohort))).encode("utf-8")
            ).hexdigest()
            for name, cohort in (("a", cohort_a), ("b", cohort_b), ("c", cohort_c))
        },
        "outputs": {
            name: {"path": str(path), "sha256": _sha256(path)}
            for name, path in paths.items()
        },
    }
    manifest_path = OUTPUT_DIR / "DURAC_rotating_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("===== ROTATING ATTACK GO/NO =====")
    for row in quarantine_late:
        print(
            f"{row['epoch']:8s} B>f={row['safety_budget_breach_rate']:.3%} "
            f"illegal={row['illegal_block_acceptance_rate']:.3%} "
            f"refuse={row['safe_refusal_rate']:.3%} "
            f"k={row['mean_committee_size']:.2f}"
        )
    print(
        f"false_detection={go_no[0]['false_detection_rate']:.3%} "
        f"compromised_recovery={compromised_recoveries} "
        f"pass={bool(go_no[0]['all_criteria_pass'])}"
    )
    print(f"[OK] {manifest_path.resolve()}")


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Legacy rotating-attack simulation runner.')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
