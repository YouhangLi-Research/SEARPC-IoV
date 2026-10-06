#!/usr/bin/env python3
"""Run the preregistered committee conditioned committee-conditioned experiment."""

from __future__ import annotations

from collections import defaultdict
import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path

from durac import (
    AdmissionState,
    CertifiedSelection,
    basic_hotstuff_message_count,
    execute_certified_committee_consensus,
    pbft_protocol_message_count,
    select_committee_leader,
)
from run_dual_path import _audit_domain
from run_closed_loop import AUDIT_WIRE_MESSAGES, _digest
from run_dual_axis import (
    FAST_SIZE,
    REGISTERED,
    PHASE14_RISK_STREAM,
    PHASE14_RISK_STREAM_SHA256,
    _aggregate,
    _apply_outcome,
    _base_row,
    _load_frozen_risk_streams,
    _relative_reduction,
    _schedule_audits,
    _write_csv,
    wilson_interval,
)
from run_detector_baselines import _v2_tracker
from run_durac_rotating_attack import (
    BASE_SEED,
    BLOCKS,
    COVERAGE,
    DELAY,
    ERROR_RATE,
    _compromised,
)
from run_durac_validator_recovery import _domains, _latencies, _tracker


SCRIPT_DIR = Path(__file__).resolve().parent
EXPERIMENT_ROOT = SCRIPT_DIR.parents[1]
CANONICAL_DIR = EXPERIMENT_ROOT / "results" / "rq4" / "searpc"
OUTPUT_DIR = EXPERIMENT_ROOT / "results" / "recomputed" / "rq4_phase16"
PROTOCOL = EXPERIMENT_ROOT / "protocols" / "frozen" / "SEARPC_COMMITTEE_CONDITIONED_PROTOCOL.md"
PROTOCOL_SHA256 = "1dc4fd4c019d76c2b394ca7e5d1871d1dba66481b47e78ef4c6916d5a04595a8"
AMENDMENT = EXPERIMENT_ROOT / "protocols" / "amendments" / "SEARPC_INTERPRETATION_AMENDMENT_20260918.md"
METHODS = (
    "fixed_full_pbft",
    "basic_full_hotstuff_proxy",
    "static_k13",
    "feedback_fixed",
    "content_only",
    "validator_only",
    "committee_dual_axis",
)
FACTORIAL_METHODS = (
    "feedback_fixed",
    "content_only",
    "validator_only",
    "committee_dual_axis",
)


def warning_cutoff(method: str, *, content_high: bool) -> int | None:
    """Return the delayed-warning streak that triggers clean resampling."""
    if method in {"feedback_fixed", "content_only"}:
        return None
    if method == "validator_only":
        return 2
    if method == "committee_dual_axis":
        return 1 if content_high else 2
    raise ValueError(f"unknown factorial method {method!r}")


def enhanced_audit_enabled(
    method: str, *, content_high: bool, primary_max: int, resampled: bool
) -> bool:
    """Dispatch only the axis or axes assigned to each factorial method."""
    if method == "feedback_fixed":
        return False
    if method == "content_only":
        return content_high
    if method == "validator_only":
        return primary_max > 0 or resampled
    if method == "committee_dual_axis":
        return content_high or primary_max > 0 or resampled
    raise ValueError(f"unknown factorial method {method!r}")


def _candidate_ids(candidates) -> tuple[int, ...]:
    return tuple(sorted(int(item.validator_id) for item in candidates))


def _predecision_signature(pool, warning_streaks: dict[int, int]) -> str:
    return ";".join(
        f"{validator_id}:{warning_streaks.get(validator_id, 0)}"
        for validator_id in _candidate_ids(pool)
    )


def _primary_max(member_ids, warning_streaks: dict[int, int]) -> int:
    return max((warning_streaks.get(int(item), 0) for item in member_ids), default=0)


def _run_repeat(repeat: int, attack: str, seed: int, stream: list[dict]):
    domains, latencies = _domains(), _latencies()
    static = _tracker(3).candidates(domains=domains, latencies_ms=latencies)
    ranked = sorted(static, key=lambda item: (-item.honesty_lcb, item.validator_id))
    cohorts = tuple(
        frozenset(item.validator_id for item in ranked[start:start + 12])
        for start in (0, 12, 24)
    )
    trackers = {method: _v2_tracker() for method in FACTORIAL_METHODS}
    warnings = {
        method: {item: 0 for item in range(REGISTERED)}
        for method in FACTORIAL_METHODS
    }
    queues = {method: defaultdict(list) for method in FACTORIAL_METHODS}
    activated = {method: 0 for method in FACTORIAL_METHODS}
    honest = {method: 0 for method in FACTORIAL_METHODS}
    false = {method: 0 for method in FACTORIAL_METHODS}
    rows = []

    for item in stream:
        block = int(item["block"])
        risk_score = float(item["risk_score"])
        content_level = "high" if item["risk_level"] == "high" else "low"
        content_high = content_level == "high"
        compromised = _compromised(block, *cohorts)

        for method, tracker in trackers.items():
            for validator_id, success, domain, was_compromised in queues[method].pop(block, []):
                update = tracker.update(validator_id, success, audit_domain=domain)
                warnings[method][validator_id] = update.failure_streak
                activated[method] += int(update.activated and validator_id in compromised)
                if not was_compromised:
                    honest[method] += 1
                    false[method] += int(success < 0.5)

        event_id = f"phase16-{repeat}-{block}"
        selection_seed = BASE_SEED + 1_600_000_000 + repeat * 10_000_000 + block * 10_000
        common = dict(
            repeat=repeat,
            attack=attack,
            seed=seed,
            block=block,
            risk_score=risk_score,
            content_level=content_level,
        )

        for method in METHODS:
            if method == "fixed_full_pbft":
                row = _base_row(**common, method=method, validator_level="na", path="direct_full")
                row.update(
                    final_legal_commit=1,
                    direct_full=1,
                    expensive_full_path=1,
                    protocol_messages=pbft_protocol_message_count(REGISTERED),
                    requested_size=REGISTERED,
                    actual_size=REGISTERED,
                )
                row.update(
                    resampled=0,
                    primary_warning_max=0,
                    primary_fast_breach=0,
                    selected_fast_breach=0,
                    primary_member_ids="",
                    selected_member_ids="",
                    predecision_signature="na",
                )
                row["total_wire_messages"] = row["protocol_messages"]
                rows.append(row)
                continue

            if method == "basic_full_hotstuff_proxy":
                leader = select_committee_leader(
                    static,
                    seed=selection_seed + 101,
                    event_id=event_id,
                    reputation_weighted=False,
                )
                row = _base_row(**common, method=method, validator_level="na", path="hotstuff_proxy")
                row.update(
                    final_legal_commit=1,
                    protocol_messages=basic_hotstuff_message_count(
                        REGISTERED,
                        failed_leader_views=int(leader.validator_id in compromised),
                    ),
                    requested_size=REGISTERED,
                    actual_size=REGISTERED,
                    resampled=0,
                    primary_warning_max=0,
                    primary_fast_breach=0,
                    selected_fast_breach=0,
                    primary_member_ids="",
                    selected_member_ids="",
                    predecision_signature="na",
                )
                row["total_wire_messages"] = row["protocol_messages"]
                rows.append(row)
                continue

            if method == "static_k13":
                outcome = execute_certified_committee_consensus(
                    static,
                    static,
                    size=FAST_SIZE,
                    selection=CertifiedSelection.DIVERSE_UNIFORM,
                    byzantine_ids=compromised,
                    seed=selection_seed,
                    event_id=event_id,
                    leader_reputation_weighted=False,
                    backup_collector_enabled=True,
                )
                row = _base_row(**common, method=method, validator_level="na", path="certified_fast")
                _apply_outcome(row, outcome, requested_size=FAST_SIZE)
                members = "|".join(map(str, outcome.member_ids))
                row.update(
                    resampled=0,
                    primary_warning_max=0,
                    primary_fast_breach=outcome.safety_budget_breach,
                    selected_fast_breach=outcome.safety_budget_breach,
                    primary_member_ids=members,
                    selected_member_ids=members,
                    predecision_signature="static",
                )
                row["total_wire_messages"] = row["protocol_messages"]
                rows.append(row)
                continue

            tracker = trackers[method]
            registered = tracker.candidates(domains=domains, latencies_ms=latencies)
            pool = tracker.candidates(
                domains=domains,
                latencies_ms=latencies,
                states={AdmissionState.ACTIVE},
            )
            warned = {
                int(validator_id)
                for validator_id in tracker.active_ids
                if warnings[method][int(validator_id)] > 0
            }
            signature = _predecision_signature(pool, warnings[method])
            primary = execute_certified_committee_consensus(
                pool,
                registered,
                size=FAST_SIZE,
                selection=CertifiedSelection.DIVERSE_UNIFORM,
                byzantine_ids=compromised,
                seed=selection_seed,
                event_id=event_id,
                leader_reputation_weighted=False,
                backup_collector_enabled=True,
            )
            primary_max = _primary_max(primary.member_ids, warnings[method])
            cutoff = warning_cutoff(method, content_high=content_high)
            should_resample = bool(
                primary.committee_size == FAST_SIZE
                and cutoff is not None
                and primary_max >= cutoff
            )
            row = _base_row(
                **common,
                method=method,
                validator_level=(
                    "high" if primary_max >= 2 else "medium" if primary_max == 1 else "low"
                ),
                path="standard_fast",
            )
            row.update(
                active_pool=len(pool),
                warned_active=len(warned),
                quarantined=len(tracker.quarantined_ids),
                probation=len(tracker.probation_ids),
                resampled=int(should_resample),
                primary_warning_max=primary_max,
                primary_fast_breach=primary.safety_budget_breach,
                selected_fast_breach=0,
                primary_member_ids="|".join(map(str, primary.member_ids)),
                selected_member_ids="",
                predecision_signature=signature,
            )

            if primary.committee_size == 0:
                row.update(
                    path="direct_full",
                    final_legal_commit=primary.final_legal_eventual_commit,
                    final_illegal_acceptance=primary.final_illegal_block_accepted,
                    final_refusal=primary.final_refusal,
                    direct_full=1,
                    expensive_full_path=1,
                    protocol_messages=primary.protocol_message_count,
                    requested_size=REGISTERED,
                    actual_size=REGISTERED,
                )
                selected = None
            elif should_resample:
                clean_pool = tuple(
                    candidate
                    for candidate in pool
                    if warnings[method].get(int(candidate.validator_id), 0) < int(cutoff)
                )
                if len(clean_pool) < FAST_SIZE:
                    row.update(
                        path="direct_full",
                        final_legal_commit=1,
                        direct_full=1,
                        expensive_full_path=1,
                        protocol_messages=pbft_protocol_message_count(REGISTERED),
                        requested_size=REGISTERED,
                        actual_size=REGISTERED,
                    )
                    selected = None
                else:
                    selected = execute_certified_committee_consensus(
                        clean_pool,
                        registered,
                        size=FAST_SIZE,
                        selection=CertifiedSelection.DIVERSE_UNIFORM,
                        byzantine_ids=compromised,
                        seed=selection_seed + 160,
                        event_id=f"{event_id}|resample",
                        leader_reputation_weighted=False,
                        backup_collector_enabled=True,
                    )
                    row["path"] = "resampled_fast"
                    _apply_outcome(row, selected, requested_size=FAST_SIZE)
            else:
                selected = primary
                _apply_outcome(row, selected, requested_size=FAST_SIZE)

            if selected is not None:
                row["selected_fast_breach"] = selected.safety_budget_breach
                row["selected_member_ids"] = "|".join(map(str, selected.member_ids))

            enhanced = enhanced_audit_enabled(
                method,
                content_high=content_high,
                primary_max=primary_max,
                resampled=should_resample,
            )
            final_members = set(
                map(int, selected.member_ids if selected is not None else primary.member_ids)
            )
            targets = (
                final_members
                | warned
                | set(map(int, tracker.quarantined_ids))
                | set(map(int, tracker.probation_ids))
            )
            if not targets and row["direct_full"]:
                targets.update(range(REGISTERED))
            _schedule_audits(
                row=row,
                method=method,
                repeat=repeat,
                block=block,
                targets=targets,
                coverage=1.0 if enhanced else COVERAGE,
                compromised=compromised,
                queues=queues,
            )
            row["total_wire_messages"] = (
                row["protocol_messages"] + AUDIT_WIRE_MESSAGES * row["audits"]
            )
            rows.append(row)

    return rows, {
        "compromised_activations": activated,
        "honest_audits": honest,
        "false_honest_audits": false,
    }


def _phase16_aggregate(rows: list[dict], group_fields: tuple[str, ...]) -> list[dict]:
    base = _aggregate(rows, group_fields)
    grouped = defaultdict(list)
    for row in rows:
        grouped[tuple(row[field] for field in group_fields)].append(row)
    for aggregate in base:
        key = tuple(aggregate[field] for field in group_fields)
        subset = grouped[key]
        total = len(subset)
        resampled = [row for row in subset if row["resampled"]]
        aggregate.update(
            resample_rate=sum(row["resampled"] for row in subset) / total,
            mean_primary_warning_max=sum(row["primary_warning_max"] for row in subset) / total,
            primary_breach_rate=sum(row["primary_fast_breach"] for row in subset) / total,
            selected_breach_rate=sum(row["selected_fast_breach"] for row in subset) / total,
            resample_precision=(
                sum(row["primary_fast_breach"] for row in resampled) / len(resampled)
                if resampled else 0.0
            ),
            resampled_primary_breach_rate=(
                sum(row["primary_fast_breach"] for row in resampled) / len(resampled)
                if resampled else 0.0
            ),
            resampled_selected_breach_rate=(
                sum(row["selected_fast_breach"] for row in resampled) / len(resampled)
                if resampled else 0.0
            ),
        )
    return base


def _pairing_mismatches(rows: list[dict]) -> tuple[int, int]:
    grouped = defaultdict(list)
    for row in rows:
        if row["method"] in FACTORIAL_METHODS:
            grouped[(row["repeat"], row["block"], row["predecision_signature"])].append(row)
    comparisons = mismatches = 0
    for subset in grouped.values():
        if len(subset) < 2:
            continue
        reference = subset[0]["primary_member_ids"]
        comparisons += len(subset) - 1
        mismatches += sum(row["primary_member_ids"] != reference for row in subset[1:])
    return comparisons, mismatches


def _simulate_main(output_dir: Path, *, repeats: int | None = None, blocks: int | None = None) -> None:
    if _digest(PROTOCOL) != PROTOCOL_SHA256:
        raise ValueError("Phase 16 protocol changed")
    if _digest(PHASE14_RISK_STREAM) != PHASE14_RISK_STREAM_SHA256:
        raise ValueError("Phase 14 risk stream changed")
    output_dir.mkdir(parents=True, exist_ok=True)
    streams, risk_rows = _load_frozen_risk_streams()
    if repeats is not None:
        streams = streams[:repeats]
        allowed = {item[0] for item in streams}
        risk_rows = [row for row in risk_rows if row["repeat"] in allowed]
    if blocks is not None:
        streams = [(r, a, seed, stream[:blocks]) for r, a, seed, stream in streams]
        risk_rows = [row for row in risk_rows if int(row["block"]) <= blocks and any(row["repeat"] == item[0] for item in streams)]
    all_rows, repeat_diag = [], []
    print("[run paired committee-conditioned validation methods]", flush=True)
    for repeat, attack, seed, stream in streams:
        print(f"  consensus repeat={repeat}/10 attack={attack}", flush=True)
        rows, diag = _run_repeat(repeat, attack, seed, stream)
        all_rows.extend(rows)
        for method in FACTORIAL_METHODS:
            repeat_diag.append(
                {
                    "repeat": repeat,
                    "attack": attack,
                    "seed": seed,
                    "method": method,
                    "compromised_activations": diag["compromised_activations"][method],
                    "honest_audits": diag["honest_audits"][method],
                    "false_honest_audits": diag["false_honest_audits"][method],
                }
            )

    overall = _phase16_aggregate(all_rows, ("method",))
    by_content = _phase16_aggregate(all_rows, ("method", "content_level"))
    by_epoch = _phase16_aggregate(all_rows, ("method", "epoch"))
    idx = {row["method"]: row for row in overall}
    fixed = idx["feedback_fixed"]
    content = idx["content_only"]
    validator = idx["validator_only"]
    dual = idx["committee_dual_axis"]
    full = idx["fixed_full_pbft"]

    exposure_reduction = _relative_reduction(
        fixed["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"]
    )
    vs_validator = _relative_reduction(
        validator["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"]
    )
    interaction = (
        content["risk_weighted_fast_exposure"]
        + validator["risk_weighted_fast_exposure"]
        - fixed["risk_weighted_fast_exposure"]
        - dual["risk_weighted_fast_exposure"]
    )
    wire_ratio = dual["mean_total_wire_messages"] / fixed["mean_total_wire_messages"]
    full_reduction = _relative_reduction(
        full["mean_total_wire_messages"], dual["mean_total_wire_messages"]
    )
    full_margin = dual["expensive_full_path_rate"] - fixed["fallback_rate"]
    resampled_reduction = _relative_reduction(
        dual["resampled_primary_breach_rate"], dual["resampled_selected_breach_rate"]
    )
    warmup_direct = sum(
        row["direct_full"]
        for row in all_rows
        if row["method"] == "committee_dual_axis" and int(row["block"]) <= 100
    )
    comparisons, pairing_mismatches = _pairing_mismatches(all_rows)
    total_honest = sum(
        row["honest_audits"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    total_false = sum(
        row["false_honest_audits"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    low, high = wilson_interval(total_false, total_honest)
    activations = sum(
        row["compromised_activations"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    diagnostics = [{
        "exposure_reduction_vs_feedback_fixed": exposure_reduction,
        "exposure_reduction_vs_validator_only": vs_validator,
        "factorial_interaction": interaction,
        "wire_ratio_vs_feedback_fixed": wire_ratio,
        "wire_reduction_vs_full_pbft": full_reduction,
        "expensive_full_path_margin_vs_fixed_fallback": full_margin,
        "resample_precision": dual["resample_precision"],
        "resampled_primary_breach_rate": dual["resampled_primary_breach_rate"],
        "resampled_selected_breach_rate": dual["resampled_selected_breach_rate"],
        "resampled_breach_reduction": resampled_reduction,
        "warmup_direct_full_count": warmup_direct,
        "equal_state_pairing_comparisons": comparisons,
        "equal_state_pairing_mismatches": pairing_mismatches,
        "honest_audit_false_rate": total_false / total_honest,
        "honest_audit_wilson_low": low,
        "honest_audit_wilson_high": high,
        "compromised_activations": activations,
    }]
    stop = [{
        "integrity_pairing_pass": int(pairing_mismatches == 0 and comparisons > 0),
        "safety_liveness_pass": int(
            dual["final_illegal_acceptance_rate"] == 0
            and dual["final_legal_commit_rate"] >= 0.99
            and dual["final_refusal_rate"] <= 0.01
        ),
        "risk_weighted_exposure_pass": int(exposure_reduction >= 0.20),
        "wire_noninferiority_pass": int(wire_ratio <= 1.10),
        "wire_vs_full_pbft_pass": int(full_reduction >= 0.15),
        "expensive_full_path_pass": int(full_margin <= 0.05),
        "dual_vs_validator_only_pass": int(vs_validator >= 0.10),
        "positive_interaction_pass": int(interaction > 0),
        "resample_precision_pass": int(dual["resample_precision"] >= 0.15),
        "resampled_breach_reduction_pass": int(resampled_reduction >= 0.30),
        "warmup_direct_full_pass": int(warmup_direct == 0),
        "audit_reactivation_pass": int(
            low <= ERROR_RATE <= high and activations == 0
        ),
    }]
    stop[0]["all_phase16_stop_lines_pass"] = int(all(stop[0].values()))

    for name, data in (
        ("risk_stream", risk_rows),
        ("block_level", all_rows),
        ("overall", overall),
        ("by_content", by_content),
        ("by_epoch", by_epoch),
        ("repeat_diagnostics", repeat_diag),
        ("diagnostics", diagnostics),
        ("stop_lines", stop),
    ):
        _write_csv(output_dir / f"DURAC_phase16_{name}.csv", data)

    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "amendment_sha256": _digest(AMENDMENT),
        "phase14_risk_stream_sha256": _digest(PHASE14_RISK_STREAM),
        "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "blocks_per_repeat": BLOCKS,
        "repeats": len(streams),
        "methods": METHODS,
        "outputs": {
            path.name: _digest(path)
            for path in sorted(output_dir.glob("*.csv"))
        },
    }
    (output_dir / "DURAC_phase16_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("===== DURAC PHASE 16 COMMITTEE CONDITIONED =====")
    for row in overall:
        print(
            f"{row['method']:27s} commit={row['final_legal_commit_rate']:.3%} "
            f"fallback={row['fallback_rate']:.3%} resample={row['resample_rate']:.3%} "
            f"direct={row['direct_full_rate']:.3%} "
            f"exposure={row['risk_weighted_fast_exposure']:.4%} "
            f"wire={row['mean_total_wire_messages']:.2f}"
        )
    print(json.dumps(diagnostics[0], indent=2, sort_keys=True))
    print(json.dumps(stop[0], indent=2, sort_keys=True))




_INT_FIELDS = {
    "repeat", "seed", "block", "final_legal_commit", "final_illegal_acceptance",
    "final_refusal", "fast_attempt", "fast_breach", "fast_illegal_proposal",
    "fallback", "direct_full", "expensive_full_path", "protocol_messages",
    "audits", "total_wire_messages", "requested_size", "actual_size",
    "warned_active", "quarantined", "probation", "shadow_fast_attempt",
    "shadow_fast_breach", "active_pool", "resampled", "primary_warning_max",
    "primary_fast_breach", "selected_fast_breach",
}
_FLOAT_FIELDS = {"risk_score"}


def _read_block_rows(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for raw in csv.DictReader(handle):
            row = dict(raw)
            for field in _INT_FIELDS:
                row[field] = int(float(row[field] or 0))
            for field in _FLOAT_FIELDS:
                row[field] = float(row[field])
            rows.append(row)
    if not rows:
        raise ValueError(f"no block rows in {path}")
    return rows


def _ids(text: str) -> set[int]:
    if not text or text == "nan":
        return set()
    return {int(item) for item in text.split("|") if item != ""}


def _signature_state(text: str) -> tuple[set[int], dict[int, int]]:
    if not text or text in {"na", "static", "nan"}:
        return set(), {}
    warnings: dict[int, int] = {}
    for item in text.split(";"):
        if not item:
            continue
        validator, streak = item.split(":", 1)
        warnings[int(validator)] = int(streak)
    return set(warnings), warnings


def _replay_repeat_diagnostics(rows: list[dict]) -> list[dict]:
    """Reconstruct audit diagnostics from the public block trace.

    The predecision signature contains every active validator and its delivered
    warning streak.  Together with the selected member ids, deterministic audit
    sampling, and the public rotating-fault schedule, this is sufficient to
    replay honest-audit errors and active-set re-entry without rerunning the
    expensive committee simulation.
    """

    domains, latencies = _domains(), _latencies()
    static = _tracker(3).candidates(domains=domains, latencies_ms=latencies)
    ranked = sorted(static, key=lambda item: (-item.honesty_lcb, item.validator_id))
    cohorts = tuple(
        frozenset(item.validator_id for item in ranked[start:start + 12])
        for start in (0, 12, 24)
    )
    grouped: dict[tuple[int, str, int, str], list[dict]] = defaultdict(list)
    for row in rows:
        if row["method"] in FACTORIAL_METHODS:
            grouped[(row["repeat"], row["attack"], row["seed"], row["method"])].append(row)
    output: list[dict] = []
    for (repeat, attack, seed, method), subset in sorted(grouped.items()):
        subset.sort(key=lambda item: item["block"])
        honest_audits = false_honest_audits = compromised_activations = 0
        previous_active: set[int] | None = None
        for row in subset:
            block = int(row["block"])
            compromised = _compromised(block, *cohorts)
            active, warning_map = _signature_state(str(row["predecision_signature"]))
            if previous_active is not None:
                compromised_activations += len((active - previous_active) & compromised)
            previous_active = active
            warned = {item for item, streak in warning_map.items() if streak > 0}
            nonactive = set(range(REGISTERED)) - active
            final_members = _ids(str(row["selected_member_ids"]))
            if not final_members:
                final_members = _ids(str(row["primary_member_ids"]))
            targets = final_members | warned | nonactive
            if not targets and row["direct_full"]:
                targets = set(range(REGISTERED))
            enhanced = enhanced_audit_enabled(
                method,
                content_high=row["content_level"] == "high",
                primary_max=int(row["primary_warning_max"]),
                resampled=bool(row["resampled"]),
            )
            coverage = 1.0 if enhanced else COVERAGE
            for validator_id in sorted(targets):
                selected = coverage >= 1.0 or __import__(
                    "run_durac_rotating_attack"
                )._paired_uniform(
                    repeat=repeat, block=block, validator_id=validator_id, stream=1
                ) < coverage
                if not selected:
                    continue
                success = __import__("run_durac_rotating_attack")._audit_success(
                    repeat=repeat,
                    block=block,
                    validator_id=validator_id,
                    compromised=compromised,
                )
                if validator_id not in compromised:
                    honest_audits += 1
                    false_honest_audits += int(success < 0.5)
        output.append({
            "repeat": repeat,
            "attack": attack,
            "seed": seed,
            "method": method,
            "compromised_activations": compromised_activations,
            "honest_audits": honest_audits,
            "false_honest_audits": false_honest_audits,
        })
    return output


def _diagnostics_and_stop(all_rows: list[dict], repeat_diag: list[dict]) -> tuple[list[dict], list[dict]]:
    overall = _phase16_aggregate(all_rows, ("method",))
    idx = {row["method"]: row for row in overall}
    fixed, content, validator, dual, full = (
        idx[name] for name in (
            "feedback_fixed", "content_only", "validator_only",
            "committee_dual_axis", "fixed_full_pbft"
        )
    )
    exposure_reduction = _relative_reduction(
        fixed["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"]
    )
    vs_validator = _relative_reduction(
        validator["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"]
    )
    interaction = (
        content["risk_weighted_fast_exposure"]
        + validator["risk_weighted_fast_exposure"]
        - fixed["risk_weighted_fast_exposure"]
        - dual["risk_weighted_fast_exposure"]
    )
    wire_ratio = dual["mean_total_wire_messages"] / fixed["mean_total_wire_messages"]
    full_reduction = _relative_reduction(
        full["mean_total_wire_messages"], dual["mean_total_wire_messages"]
    )
    full_margin = dual["expensive_full_path_rate"] - fixed["fallback_rate"]
    resampled_reduction = _relative_reduction(
        dual["resampled_primary_breach_rate"], dual["resampled_selected_breach_rate"]
    )
    warmup_direct = sum(
        row["direct_full"] for row in all_rows
        if row["method"] == "committee_dual_axis" and int(row["block"]) <= 100
    )
    comparisons, pairing_mismatches = _pairing_mismatches(all_rows)
    total_honest = sum(
        row["honest_audits"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    total_false = sum(
        row["false_honest_audits"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    low, high = wilson_interval(total_false, total_honest)
    activations = sum(
        row["compromised_activations"] for row in repeat_diag
        if row["method"] == "committee_dual_axis"
    )
    diagnostics = [{
        "exposure_reduction_vs_feedback_fixed": exposure_reduction,
        "exposure_reduction_vs_validator_only": vs_validator,
        "factorial_interaction": interaction,
        "wire_ratio_vs_feedback_fixed": wire_ratio,
        "wire_reduction_vs_full_pbft": full_reduction,
        "expensive_full_path_margin_vs_fixed_fallback": full_margin,
        "resample_precision": dual["resample_precision"],
        "resampled_primary_breach_rate": dual["resampled_primary_breach_rate"],
        "resampled_selected_breach_rate": dual["resampled_selected_breach_rate"],
        "resampled_breach_reduction": resampled_reduction,
        "warmup_direct_full_count": warmup_direct,
        "equal_state_pairing_comparisons": comparisons,
        "equal_state_pairing_mismatches": pairing_mismatches,
        "honest_audit_false_rate": total_false / total_honest,
        "honest_audit_wilson_low": low,
        "honest_audit_wilson_high": high,
        "compromised_activations": activations,
    }]
    stop = [{
        "integrity_pairing_pass": int(pairing_mismatches == 0 and comparisons > 0),
        "safety_liveness_pass": int(
            dual["final_illegal_acceptance_rate"] == 0
            and dual["final_legal_commit_rate"] >= 0.99
            and dual["final_refusal_rate"] <= 0.01
        ),
        "risk_weighted_exposure_pass": int(exposure_reduction >= 0.20),
        "wire_noninferiority_pass": int(wire_ratio <= 1.10),
        "wire_vs_full_pbft_pass": int(full_reduction >= 0.15),
        "expensive_full_path_pass": int(full_margin <= 0.05),
        "dual_vs_validator_only_pass": int(vs_validator >= 0.10),
        "positive_interaction_pass": int(interaction > 0),
        "resample_precision_pass": int(dual["resample_precision"] >= 0.15),
        "resampled_breach_reduction_pass": int(resampled_reduction >= 0.30),
        "warmup_direct_full_pass": int(warmup_direct == 0),
        "audit_reactivation_pass": int(low <= ERROR_RATE <= high and activations == 0),
    }]
    stop[0]["all_phase16_stop_lines_pass"] = int(all(stop[0].values()))
    stop[0]["interpretation"] = (
        "principal validator-evidence/resampling contribution; content risk is "
        "a secondary escalation modifier because the 10% validator-only gate failed"
    )
    return diagnostics, stop


def _replay_main(input_path: Path, output_dir: Path, *, compare_canonical: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    all_rows = _read_block_rows(input_path)
    repeat_diag = _replay_repeat_diagnostics(all_rows)
    overall = _phase16_aggregate(all_rows, ("method",))
    by_content = _phase16_aggregate(all_rows, ("method", "content_level"))
    by_epoch = _phase16_aggregate(all_rows, ("method", "epoch"))
    diagnostics, stop = _diagnostics_and_stop(all_rows, repeat_diag)
    risk_rows: list[dict] = []
    risk_path = CANONICAL_DIR / "DURAC_phase16_risk_stream.csv"
    if risk_path.exists():
        with risk_path.open(newline="", encoding="utf-8") as handle:
            risk_rows = list(csv.DictReader(handle))
    for name, data in (
        ("risk_stream", risk_rows),
        ("block_level", all_rows),
        ("overall", overall),
        ("by_content", by_content),
        ("by_epoch", by_epoch),
        ("repeat_diagnostics", repeat_diag),
        ("diagnostics", diagnostics),
        ("stop_lines", stop),
    ):
        _write_csv(output_dir / f"DURAC_phase16_{name}.csv", data)
    comparison = {}
    if compare_canonical:
        for name in ("block_level", "overall", "by_epoch", "risk_stream"):
            generated = output_dir / f"DURAC_phase16_{name}.csv"
            canonical = CANONICAL_DIR / generated.name
            if canonical.exists():
                comparison[name] = {
                    "generated_sha256": _digest(generated),
                    "canonical_sha256": _digest(canonical),
                    "exact_match": _digest(generated) == _digest(canonical),
                }
        (output_dir / "DURAC_phase16_canonical_comparison.json").write_text(
            json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    manifest = {
        "mode": "bundled-block-trace-replay",
        "source_block_level_sha256": _digest(input_path),
        "protocol_sha256": _digest(PROTOCOL),
        "interpretation_amendment_sha256": _digest(AMENDMENT),
        "outputs": {
            path.name: _digest(path) for path in sorted(output_dir.glob("*.csv"))
        },
    }
    (output_dir / "DURAC_phase16_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output_dir": str(output_dir), "comparison": comparison,
                      "stop_lines": stop[0]}, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Recompute Phase-16 tables/gates from the bundled block trace, or "
            "rerun the slower source simulation."
        )
    )
    parser.add_argument("--mode", choices=("replay", "simulate"), default="replay")
    parser.add_argument(
        "--input-block-level", type=Path,
        default=CANONICAL_DIR / "DURAC_phase16_block_level.csv"
    )
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--compare-canonical", action="store_true")
    parser.add_argument("--repeats", type=int, default=None,
                        help="simulate only the first N paired repeats")
    parser.add_argument("--blocks", type=int, default=None,
                        help="simulate only the first N blocks per repeat")
    args = parser.parse_args(argv)
    if args.mode == "replay":
        _replay_main(args.input_block_level, args.output_dir,
                     compare_canonical=args.compare_canonical)
    else:
        _simulate_main(args.output_dir, repeats=args.repeats, blocks=args.blocks)


if __name__ == "__main__":
    main()
