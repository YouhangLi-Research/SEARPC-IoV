#!/usr/bin/env python3
"""Closed-loop validator reputation recovery stress experiment."""

from __future__ import annotations

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
    ValidatorCandidate,
    ValidatorReputationTracker,
    committee_failure_probability,
    evaluate_committee_security,
    pbft_protocol_message_count,
    select_committee_leader,
    select_risk_constrained_committee,
    select_size_matched_committee,
)


POOL_SIZE = 40
DOMAINS = 6
BLOCKS = 600
ATTACK_START = 201
AUDIT_DELAY = 5
AUDIT_ERROR = 0.01
REPEATS = 10
BASE_SEED = 44107
FIXED_SIZE = 18
INITIAL_EVIDENCE = 200.0
ASSUMED_DOMAIN_PROBABILITY = 0.001
OUTPUT_DIR = Path("results/durac_validator_recovery_v1")
ASSUMPTIONS = Path("DURAC_VALIDATOR_RECOVERY_V1_ASSUMPTIONS.md")

METHODS = (
    "fixed_full_cbtds",
    "uniform_k18",
    "static_top_k18",
    "dynamic_top_k18",
    "durac_static",
    "durac_beta_only",
    "durac_changepoint",
)

EPOCHS = (
    ("warmup", 1, 200),
    ("early_attack", 201, 250),
    ("middle_attack", 251, 350),
    ("late_attack", 351, 600),
)


def _sha256(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("rows cannot be empty")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _initial_means() -> dict[int, float]:
    return {
        validator_id: (
            0.92
            + 0.07
            * ((17 * validator_id + 11) % POOL_SIZE)
            / (POOL_SIZE - 1)
        )
        for validator_id in range(POOL_SIZE)
    }


def _domains() -> dict[int, str]:
    return {
        validator_id: f"domain-{validator_id % DOMAINS}"
        for validator_id in range(POOL_SIZE)
    }


def _latencies() -> dict[int, float]:
    return {
        validator_id: 4.0 + validator_id % 5
        for validator_id in range(POOL_SIZE)
    }


def _tracker(failure_trigger: int | None) -> ValidatorReputationTracker:
    return ValidatorReputationTracker(
        _initial_means(),
        initial_evidence=INITIAL_EVIDENCE,
        bound_quantile=0.05,
        failure_trigger=failure_trigger,
    )


def _audit_success(
    *,
    repeat: int,
    block: int,
    validator_id: int,
    compromised: frozenset[int],
) -> float:
    truth = validator_id not in compromised
    seed = BASE_SEED + repeat * 10_000_000 + block * 10_000 + validator_id
    if Random(seed).random() < AUDIT_ERROR:
        truth = not truth
    return float(truth)


def _committee(
    method: str,
    *,
    base_candidates: list[ValidatorCandidate],
    trackers: dict[str, ValidatorReputationTracker],
    domains: dict[int, str],
    latencies: dict[int, float],
    assumed_domains: dict[str, float],
    seed: int,
    event_id: str,
) -> tuple[ValidatorCandidate, ...]:
    if method == "fixed_full_cbtds":
        return select_size_matched_committee(
            base_candidates,
            size=POOL_SIZE,
            method=CommitteeMethod.FIXED_FULL_CBTDS,
            seed=seed,
            event_id=event_id,
        )
    if method == "uniform_k18":
        return select_size_matched_committee(
            base_candidates,
            size=FIXED_SIZE,
            method=CommitteeMethod.UNIFORM_SIZE_MATCHED,
            seed=seed,
            event_id=event_id,
        )
    if method == "static_top_k18":
        return select_size_matched_committee(
            base_candidates,
            size=FIXED_SIZE,
            method=CommitteeMethod.REPUTATION_TOP_SIZE_MATCHED,
            seed=seed,
            event_id=event_id,
        )
    if method == "dynamic_top_k18":
        candidates = trackers[method].candidates(
            domains=domains, latencies_ms=latencies
        )
        return select_size_matched_committee(
            candidates,
            size=FIXED_SIZE,
            method=CommitteeMethod.REPUTATION_TOP_SIZE_MATCHED,
            seed=seed,
            event_id=event_id,
        )
    if method == "durac_static":
        candidates = base_candidates
    else:
        candidates = trackers[method].candidates(
            domains=domains, latencies_ms=latencies
        )
    selection = select_risk_constrained_committee(
        candidates,
        risk_level=RiskLevel.HIGH,
        seed=seed,
        event_id=event_id,
        domain_compromise_probability=assumed_domains,
    )
    candidate_by_id = {candidate.validator_id: candidate for candidate in candidates}
    return tuple(
        candidate_by_id[validator_id] for validator_id in selection.member_ids
    )


def _epoch_summary(rows: list[dict]) -> list[dict]:
    output = []
    for epoch, start, end in EPOCHS:
        for method in METHODS:
            subset = [
                row
                for row in rows
                if row["method"] == method and start <= row["block"] <= end
            ]
            evaluated = sum(row["evaluated"] for row in subset)
            attempts = len(subset)

            def pooled(field: str) -> float:
                return (
                    sum(row[field] for row in subset) / evaluated
                    if evaluated
                    else math.nan
                )

            evaluated_rows = [row for row in subset if row["evaluated"]]
            output.append(
                {
                    "epoch": epoch,
                    "start_block": start,
                    "end_block": end,
                    "method": method,
                    "attempted_blocks": attempts,
                    "evaluated_blocks": evaluated,
                    "safe_refusal_rate": (
                        sum(row["safe_refusal"] for row in subset) / attempts
                    ),
                    "safety_budget_breach_rate": pooled("safety_budget_breach"),
                    "illegal_block_acceptance_rate": pooled(
                        "illegal_block_accepted"
                    ),
                    "legal_first_round_commit_rate": pooled(
                        "legal_first_round_commit"
                    ),
                    "legal_eventual_commit_rate": pooled("legal_eventual_commit"),
                    "view_change_rate": pooled("view_change"),
                    "mean_committee_size": mean(
                        row["committee_size"] for row in evaluated_rows
                    ) if evaluated_rows else math.nan,
                    "mean_selected_compromised_fraction": mean(
                        row["selected_compromised_fraction"]
                        for row in evaluated_rows
                    ) if evaluated_rows else math.nan,
                    "mean_estimated_failure_probability": mean(
                        row["estimated_failure_probability"]
                        for row in evaluated_rows
                    ) if evaluated_rows else math.nan,
                    "mean_protocol_message_count": mean(
                        row["protocol_message_count"] for row in evaluated_rows
                    ) if evaluated_rows else math.nan,
                    "change_detections": sum(
                        row["change_detections"] for row in subset
                    ),
                }
            )
    return output


def _time_summary(rows: list[dict]) -> list[dict]:
    output = []
    for block in range(1, BLOCKS + 1):
        for method in METHODS:
            subset = [
                row
                for row in rows
                if row["block"] == block and row["method"] == method
            ]
            evaluated = [row for row in subset if row["evaluated"]]
            output.append(
                {
                    "block": block,
                    "method": method,
                    "safe_refusal_rate": mean(
                        row["safe_refusal"] for row in subset
                    ),
                    "safety_budget_breach_rate": mean(
                        row["safety_budget_breach"] for row in evaluated
                    ) if evaluated else math.nan,
                    "illegal_block_acceptance_rate": mean(
                        row["illegal_block_accepted"] for row in evaluated
                    ) if evaluated else math.nan,
                    "mean_committee_size": mean(
                        row["committee_size"] for row in evaluated
                    ) if evaluated else math.nan,
                    "mean_selected_compromised_fraction": mean(
                        row["selected_compromised_fraction"] for row in evaluated
                    ) if evaluated else math.nan,
                    "mean_cumulative_change_detections": mean(
                        row["cumulative_change_detections"] for row in subset
                    ),
                }
            )
    return output


def _rolling(values: list[float], window: int = 25) -> list[float]:
    output = []
    for index in range(len(values)):
        subset = [
            value
            for value in values[max(0, index - window + 1) : index + 1]
            if not math.isnan(value)
        ]
        output.append(mean(subset) if subset else math.nan)
    return output


def _plot(path: Path, time_rows: list[dict]) -> None:
    matplotlib_dir = path.parent / ".matplotlib"
    matplotlib_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("MPLCONFIGDIR", str(matplotlib_dir.resolve()))
    import matplotlib.pyplot as plt

    colors = {
        "fixed_full_cbtds": "#475569",
        "uniform_k18": "#0EA5E9",
        "static_top_k18": "#DC2626",
        "dynamic_top_k18": "#A855F7",
        "durac_static": "#F59E0B",
        "durac_beta_only": "#84CC16",
        "durac_changepoint": "#15803D",
    }
    labels = {
        "fixed_full_cbtds": "Full CBTDS",
        "uniform_k18": "Uniform k18",
        "static_top_k18": "Static top k18",
        "dynamic_top_k18": "Dynamic top k18",
        "durac_static": "DURAC static",
        "durac_beta_only": "DURAC Beta only",
        "durac_changepoint": "DURAC change point",
    }
    panels = (
        ("safety_budget_breach_rate", "Rolling B > f rate"),
        ("mean_selected_compromised_fraction", "Selected compromised fraction"),
        ("mean_committee_size", "Committee size"),
        ("mean_cumulative_change_detections", "Cumulative change detections"),
    )
    fig, axes = plt.subplots(2, 2, figsize=(14.2, 8.7), constrained_layout=True)
    for axis, (field, title) in zip(axes.flat, panels):
        for method in METHODS:
            subset = [row for row in time_rows if row["method"] == method]
            values = [float(row[field]) for row in subset]
            if field in (
                "safety_budget_breach_rate",
                "mean_selected_compromised_fraction",
            ):
                values = _rolling(values)
            axis.plot(
                [row["block"] for row in subset],
                values,
                color=colors[method],
                linewidth=1.6,
                label=labels[method],
            )
        axis.axvline(ATTACK_START, color="#111827", linestyle="--", linewidth=1.2)
        axis.set(xlabel="Block", ylabel=title, title=title)
        axis.grid(True, alpha=0.22)
        axis.spines[["top", "right"]].set_visible(False)
    axes[0, 0].legend(fontsize=7, ncol=2)
    fig.savefig(path, dpi=200, facecolor="white")
    plt.close(fig)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    domains = _domains()
    latencies = _latencies()
    initial_tracker = _tracker(3)
    base_candidates = initial_tracker.candidates(
        domains=domains, latencies_ms=latencies
    )
    ranked = sorted(
        base_candidates,
        key=lambda candidate: (-candidate.honesty_lcb, candidate.validator_id),
    )
    attack_ids = frozenset(
        candidate.validator_id for candidate in ranked[:12]
    )
    assumed_domains = {
        f"domain-{domain_index}": ASSUMED_DOMAIN_PROBABILITY
        for domain_index in range(DOMAINS)
    }
    rows = []
    for repeat in range(1, REPEATS + 1):
        print(f"[repeat={repeat}]", flush=True)
        trackers = {
            "dynamic_top_k18": _tracker(3),
            "durac_beta_only": _tracker(None),
            "durac_changepoint": _tracker(3),
        }
        queues: dict[str, list[tuple[int, int, float]]] = {
            method: [] for method in trackers
        }
        cumulative_detections = {method: 0 for method in METHODS}
        for block in range(1, BLOCKS + 1):
            compromised = attack_ids if block >= ATTACK_START else frozenset()
            detections_this_block = {method: 0 for method in METHODS}
            for method, tracker in trackers.items():
                due = [item for item in queues[method] if item[0] == block]
                queues[method] = [item for item in queues[method] if item[0] != block]
                for _, validator_id, success in due:
                    update = tracker.update(validator_id, success)
                    if update.change_detected:
                        detections_this_block[method] += 1
                        cumulative_detections[method] += 1

            for method_index, method in enumerate(METHODS):
                seed = (
                    BASE_SEED
                    + repeat * 10_000_000
                    + block * 10_000
                    + method_index * 100
                )
                event_id = f"recovery-{repeat}-{block}-{method}"
                try:
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
                except UnsafeCommitteeError:
                    rows.append(
                        {
                            "repeat": repeat,
                            "block": block,
                            "method": method,
                            "attack_active": int(block >= ATTACK_START),
                            "evaluated": 0,
                            "safe_refusal": 1,
                            "committee_size": 0,
                            "actual_byzantine": 0,
                            "selected_compromised_fraction": math.nan,
                            "estimated_failure_probability": math.nan,
                            "protocol_message_count": 0,
                            "safety_budget_breach": 0,
                            "illegal_block_accepted": 0,
                            "legal_first_round_commit": 0,
                            "legal_eventual_commit": 0,
                            "view_change": 0,
                            "change_detections": detections_this_block[method],
                            "cumulative_change_detections": cumulative_detections[method],
                        }
                    )
                    continue
                reputation_weighted = method not in (
                    "fixed_full_cbtds",
                    "uniform_k18",
                )
                leader = select_committee_leader(
                    committee,
                    seed=seed + 700_001,
                    event_id=event_id,
                    reputation_weighted=reputation_weighted,
                )
                outcome = evaluate_committee_security(
                    committee,
                    leader_id=leader.validator_id,
                    byzantine_ids=compromised,
                )
                if method in trackers:
                    for candidate in committee:
                        success = _audit_success(
                            repeat=repeat,
                            block=block,
                            validator_id=candidate.validator_id,
                            compromised=compromised,
                        )
                        due_block = block + AUDIT_DELAY
                        if due_block <= BLOCKS:
                            queues[method].append(
                                (due_block, candidate.validator_id, success)
                            )
                rows.append(
                    {
                        "repeat": repeat,
                        "block": block,
                        "method": method,
                        "attack_active": int(block >= ATTACK_START),
                        "evaluated": 1,
                        "safe_refusal": 0,
                        "committee_size": outcome.committee_size,
                        "actual_byzantine": outcome.actual_byzantine,
                        "selected_compromised_fraction": (
                            outcome.actual_byzantine / outcome.committee_size
                        ),
                        "estimated_failure_probability": (
                            committee_failure_probability(committee, assumed_domains)
                        ),
                        "protocol_message_count": pbft_protocol_message_count(
                            outcome.committee_size
                        ),
                        "safety_budget_breach": outcome.safety_budget_breach,
                        "illegal_block_accepted": outcome.illegal_block_accepted,
                        "legal_first_round_commit": outcome.legal_first_round_commit,
                        "legal_eventual_commit": outcome.legal_eventual_commit,
                        "view_change": outcome.view_change,
                        "change_detections": detections_this_block[method],
                        "cumulative_change_detections": cumulative_detections[method],
                    }
                )

    epoch_rows = _epoch_summary(rows)
    time_rows = _time_summary(rows)
    paths = {
        "run_level": OUTPUT_DIR / "DURAC_validator_recovery_run_level.csv",
        "epoch_summary": OUTPUT_DIR / "DURAC_validator_recovery_epoch_summary.csv",
        "time_summary": OUTPUT_DIR / "DURAC_validator_recovery_time_summary.csv",
        "chart": OUTPUT_DIR / "DURAC_validator_recovery.png",
    }
    _write_csv(paths["run_level"], rows)
    _write_csv(paths["epoch_summary"], epoch_rows)
    _write_csv(paths["time_summary"], time_rows)
    _plot(paths["chart"], time_rows)
    manifest = {
        "protocol_status": "frozen before formal execution",
        "assumptions_sha256": _sha256(ASSUMPTIONS),
        "blocks": BLOCKS,
        "attack_start": ATTACK_START,
        "repeats": REPEATS,
        "methods": list(METHODS),
        "attack_ids_sha256": sha256(
            ",".join(map(str, sorted(attack_ids))).encode("utf-8")
        ).hexdigest(),
        "outputs": {
            name: {"path": str(path), "sha256": _sha256(path)}
            for name, path in paths.items()
        },
    }
    manifest_path = OUTPUT_DIR / "DURAC_validator_recovery_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("===== LATE-ATTACK EPOCH =====")
    for row in epoch_rows:
        if row["epoch"] == "late_attack":
            print(
                f"{row['method']:24s} "
                f"refuse={row['safe_refusal_rate']:.2%} "
                f"k={row['mean_committee_size']:.2f} "
                f"B>f={row['safety_budget_breach_rate']:.2%} "
                f"illegal={row['illegal_block_acceptance_rate']:.2%} "
                f"captured={row['mean_selected_compromised_fraction']:.2%} "
                f"detections={row['change_detections']}"
            )
    print(f"[OK] {manifest_path.resolve()}")


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Legacy validator-recovery simulation runner.')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
