#!/usr/bin/env python3
"""Run the preregistered dual axis dual-axis selective-validation experiment."""

from __future__ import annotations

from collections import defaultdict
import csv
from hashlib import sha256
import json
import math
from pathlib import Path

from durac import (
    AdmissionState, CertifiedSelection, basic_hotstuff_message_count,
    execute_certified_committee_consensus, pbft_protocol_message_count,
    select_committee_leader,
)
from run_dual_path import _audit_domain
from run_dual_role import SEEDS
from run_conditional_trust import ATTACKS
from run_closed_loop import AUDIT_WIRE_MESSAGES, SIZES, _digest
from run_detector_baselines import _v2_tracker
from run_durac_rotating_attack import (
    BASE_SEED, BLOCKS, COVERAGE, DELAY, ERROR_RATE, _audit_success,
    _compromised, _epoch, _paired_uniform,
)
from run_durac_validator_recovery import _domains, _latencies, _tracker

SCRIPT_DIR = Path(__file__).resolve().parent
EXPERIMENT_ROOT = SCRIPT_DIR.parents[1]
OUTPUT_DIR = EXPERIMENT_ROOT / "results" / "recomputed" / "phase15_dual_axis"
PROTOCOL = EXPERIMENT_ROOT / "protocols" / "frozen" / "SEARPC_DUAL_AXIS_PROTOCOL.md"
PROTOCOL_SHA256 = "8c0fcf944f334c8aec1e73d7e72411f9d35240154f44b3b95668d04c880e0604"
PHASE14_RISK_STREAM = EXPERIMENT_ROOT / "results" / "rq4" / "searpc" / "DURAC_phase14_risk_stream.csv"
PHASE14_RISK_STREAM_SHA256 = "4ffde9a9e09245ada285502e78d2f9d3fa916a268169ea9768a856e319448bc4"
FAST_SIZE, REGISTERED = 13, 40
METHODS = (
    "fixed_full_pbft", "basic_full_hotstuff_proxy", "static_k13",
    "old_risk_size", "feedback_fixed", "content_only", "validator_only",
    "dual_axis",
)
FACTORIAL_METHODS = ("feedback_fixed", "content_only", "validator_only", "dual_axis")


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("rows cannot be empty")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader(); writer.writerows(rows)


def validator_risk_level(active_ids, warning_streaks: dict[int, int]) -> str:
    if len(active_ids) < FAST_SIZE:
        return "high"
    maximum = max((warning_streaks.get(int(item), 0) for item in active_ids), default=0)
    return "high" if maximum >= 2 else "medium" if maximum == 1 else "low"


def select_validation_path(method: str, *, content_high: bool, validator_level: str) -> str:
    if validator_level not in {"low", "medium", "high"}:
        raise ValueError("unknown validator level")
    if method == "feedback_fixed":
        return "standard_fast"
    if method == "content_only":
        return "enhanced_audit" if content_high else "standard_fast"
    if method == "validator_only":
        return "direct_full" if validator_level == "high" else (
            "enhanced_audit" if validator_level == "medium" else "standard_fast"
        )
    if method == "dual_axis":
        if validator_level == "high" or (content_high and validator_level == "medium"):
            return "direct_full"
        return "enhanced_audit" if content_high or validator_level == "medium" else "standard_fast"
    raise ValueError(f"method {method!r} has no selective path")


def wilson_interval(successes: int, trials: int, z: float = 1.959963984540054):
    if trials < 1 or not 0 <= successes <= trials:
        raise ValueError("invalid binomial counts")
    p = successes / trials; d = 1.0 + z * z / trials
    c = (p + z * z / (2.0 * trials)) / d
    r = z * math.sqrt(p * (1.0 - p) / trials + z * z / (4.0 * trials * trials)) / d
    return c - r, c + r


def _base_row(**values) -> dict:
    row = dict(values)
    row["epoch"] = _epoch(row["block"])
    for key in (
        "final_legal_commit", "final_illegal_acceptance", "final_refusal",
        "fast_attempt", "fast_breach", "fast_illegal_proposal", "fallback",
        "direct_full", "expensive_full_path", "protocol_messages", "audits",
        "total_wire_messages", "requested_size", "actual_size", "warned_active",
        "quarantined", "probation", "shadow_fast_attempt", "shadow_fast_breach",
    ):
        row[key] = 0
    row["active_pool"] = REGISTERED
    return row


def _apply_outcome(row: dict, outcome, *, requested_size: int) -> None:
    row.update({
        "final_legal_commit": outcome.final_legal_eventual_commit,
        "final_illegal_acceptance": outcome.final_illegal_block_accepted,
        "final_refusal": outcome.final_refusal,
        "fast_attempt": int(outcome.committee_size > 0),
        "fast_breach": outcome.safety_budget_breach,
        "fast_illegal_proposal": outcome.fast_illegal_proposal,
        "fallback": outcome.fallback_triggered,
        "expensive_full_path": outcome.fallback_triggered,
        "protocol_messages": outcome.protocol_message_count,
        "requested_size": requested_size,
        "actual_size": outcome.committee_size,
    })


def _schedule_audits(*, row, method, repeat, block, targets, coverage, compromised, queues):
    for validator_id in sorted(targets):
        selected = coverage >= 1.0 or _paired_uniform(
            repeat=repeat, block=block, validator_id=validator_id, stream=1
        ) < coverage
        if not selected:
            continue
        success = _audit_success(
            repeat=repeat, block=block, validator_id=validator_id,
            compromised=compromised,
        )
        row["audits"] += 1
        if block + DELAY <= BLOCKS:
            queues[method][block + DELAY].append((
                validator_id, success, _audit_domain(repeat, block, validator_id),
                validator_id in compromised,
            ))


def _run_repeat(repeat: int, attack: str, seed: int, stream: list[dict]):
    domains, latencies = _domains(), _latencies()
    static = _tracker(3).candidates(domains=domains, latencies_ms=latencies)
    ranked = sorted(static, key=lambda item: (-item.honesty_lcb, item.validator_id))
    cohorts = tuple(frozenset(item.validator_id for item in ranked[start:start + 12]) for start in (0, 12, 24))
    trackers = {method: _v2_tracker() for method in FACTORIAL_METHODS}
    warnings = {method: {item: 0 for item in range(REGISTERED)} for method in FACTORIAL_METHODS}
    queues = {method: defaultdict(list) for method in FACTORIAL_METHODS}
    activated = {method: 0 for method in FACTORIAL_METHODS}
    honest = {method: 0 for method in FACTORIAL_METHODS}
    false = {method: 0 for method in FACTORIAL_METHODS}
    rows = []
    for item in stream:
        block, risk_score = int(item["block"]), float(item["risk_score"])
        content_level = "high" if item["risk_level"] == "high" else "low"
        compromised = _compromised(block, *cohorts)
        for method, tracker in trackers.items():
            for validator_id, success, domain, was_compromised in queues[method].pop(block, []):
                update = tracker.update(validator_id, success, audit_domain=domain)
                warnings[method][validator_id] = update.failure_streak
                activated[method] += int(update.activated and validator_id in compromised)
                if not was_compromised:
                    honest[method] += 1; false[method] += int(success < 0.5)
        event_id = f"phase15-{repeat}-{block}"
        selection_seed = BASE_SEED + 1_500_000_000 + repeat * 10_000_000 + block * 10_000
        common = dict(repeat=repeat, attack=attack, seed=seed, block=block,
                      risk_score=risk_score, content_level=content_level)
        for method in METHODS:
            if method == "fixed_full_pbft":
                row = _base_row(**common, method=method, validator_level="na", path="direct_full")
                row.update(final_legal_commit=1, direct_full=1, expensive_full_path=1,
                           protocol_messages=pbft_protocol_message_count(REGISTERED),
                           requested_size=REGISTERED, actual_size=REGISTERED)
                row["total_wire_messages"] = row["protocol_messages"]; rows.append(row); continue
            if method == "basic_full_hotstuff_proxy":
                leader = select_committee_leader(static, seed=selection_seed + 101,
                    event_id=event_id, reputation_weighted=False)
                row = _base_row(**common, method=method, validator_level="na", path="hotstuff_proxy")
                row.update(final_legal_commit=1,
                    protocol_messages=basic_hotstuff_message_count(REGISTERED,
                        failed_leader_views=int(leader.validator_id in compromised)),
                    requested_size=REGISTERED, actual_size=REGISTERED)
                row["total_wire_messages"] = row["protocol_messages"]; rows.append(row); continue
            if method in {"static_k13", "old_risk_size"}:
                requested = FAST_SIZE if method == "static_k13" else SIZES[item["risk_level"]]
                outcome = execute_certified_committee_consensus(static, static, size=requested,
                    selection=CertifiedSelection.DIVERSE_UNIFORM, byzantine_ids=compromised,
                    seed=selection_seed, event_id=event_id, leader_reputation_weighted=False,
                    backup_collector_enabled=True)
                row = _base_row(**common, method=method, validator_level="na", path="certified_fast")
                _apply_outcome(row, outcome, requested_size=requested)
                row["total_wire_messages"] = row["protocol_messages"]; rows.append(row); continue
            tracker = trackers[method]
            registered = tracker.candidates(domains=domains, latencies_ms=latencies)
            pool = tracker.candidates(domains=domains, latencies_ms=latencies,
                                      states={AdmissionState.ACTIVE})
            level = validator_risk_level(tracker.active_ids, warnings[method])
            path = select_validation_path(method, content_high=content_level == "high",
                                          validator_level=level)
            row = _base_row(**common, method=method, validator_level=level, path=path)
            warned = {int(item) for item in tracker.active_ids if warnings[method][int(item)] > 0}
            row.update(active_pool=len(pool), warned_active=len(warned),
                       quarantined=len(tracker.quarantined_ids), probation=len(tracker.probation_ids))
            if path == "direct_full":
                shadow = execute_certified_committee_consensus(pool, registered, size=FAST_SIZE,
                    selection=CertifiedSelection.DIVERSE_UNIFORM, byzantine_ids=compromised,
                    seed=selection_seed, event_id=event_id, leader_reputation_weighted=False,
                    backup_collector_enabled=True)
                row.update(shadow_fast_attempt=int(shadow.committee_size > 0),
                    shadow_fast_breach=shadow.safety_budget_breach, final_legal_commit=1,
                    direct_full=1, expensive_full_path=1,
                    protocol_messages=pbft_protocol_message_count(REGISTERED),
                    requested_size=REGISTERED, actual_size=REGISTERED)
                targets = warned | set(map(int, tracker.quarantined_ids)) | set(map(int, tracker.probation_ids))
                coverage = 1.0
            else:
                outcome = execute_certified_committee_consensus(pool, registered, size=FAST_SIZE,
                    selection=CertifiedSelection.DIVERSE_UNIFORM, byzantine_ids=compromised,
                    seed=selection_seed, event_id=event_id, leader_reputation_weighted=False,
                    backup_collector_enabled=True)
                _apply_outcome(row, outcome, requested_size=FAST_SIZE)
                targets = set(map(int, outcome.member_ids)) | warned | set(map(int, tracker.quarantined_ids)) | set(map(int, tracker.probation_ids))
                if outcome.committee_size == 0: targets.update(range(REGISTERED))
                coverage = 1.0 if path == "enhanced_audit" else COVERAGE
            _schedule_audits(row=row, method=method, repeat=repeat, block=block,
                targets=targets, coverage=coverage, compromised=compromised, queues=queues)
            row["total_wire_messages"] = row["protocol_messages"] + AUDIT_WIRE_MESSAGES * row["audits"]
            rows.append(row)
    return rows, {"compromised_activations": activated, "honest_audits": honest,
                  "false_honest_audits": false}


def _aggregate(rows: list[dict], group_fields: tuple[str, ...]) -> list[dict]:
    grouped = defaultdict(list)
    for row in rows: grouped[tuple(row[field] for field in group_fields)].append(row)
    output = []
    for key in sorted(grouped, key=lambda item: tuple(map(str, item))):
        subset = grouped[key]; total = len(subset); risk_sum = sum(float(r["risk_score"]) for r in subset)
        item = {field: value for field, value in zip(group_fields, key, strict=True)}
        def avg(field): return sum(r[field] for r in subset) / total
        fast_attempts = sum(r["fast_attempt"] for r in subset)
        directs = sum(r["direct_full"] for r in subset)
        item.update(blocks=total, final_legal_commit_rate=avg("final_legal_commit"),
            final_illegal_acceptance_rate=avg("final_illegal_acceptance"),
            final_refusal_rate=avg("final_refusal"), fast_attempt_rate=avg("fast_attempt"),
            fast_breach_rate_all_blocks=avg("fast_breach"),
            fast_breach_rate_attempted=(sum(r["fast_breach"] for r in subset) / fast_attempts if fast_attempts else 0.0),
            fast_illegal_proposal_rate=avg("fast_illegal_proposal"), fallback_rate=avg("fallback"),
            direct_full_rate=avg("direct_full"), expensive_full_path_rate=avg("expensive_full_path"),
            mean_protocol_messages=avg("protocol_messages"), mean_audits=avg("audits"),
            mean_total_wire_messages=avg("total_wire_messages"), mean_active_pool=avg("active_pool"),
            mean_warned_active=avg("warned_active"),
            risk_weighted_fast_exposure=(sum(float(r["risk_score"]) * r["fast_breach"] for r in subset) / risk_sum if risk_sum else 0.0),
            shadow_fast_breach_precision=(sum(r["shadow_fast_breach"] for r in subset) / directs if directs else 0.0))
        output.append(item)
    return output


def _relative_reduction(reference: float, value: float) -> float:
    return 0.0 if reference == value == 0.0 else 1.0 - value / reference


def _load_frozen_risk_streams():
    """Load the exact closed loop artifact registered as the dual axis input."""
    if _digest(PHASE14_RISK_STREAM) != PHASE14_RISK_STREAM_SHA256:
        raise ValueError("frozen Phase 14 risk stream changed")
    grouped = defaultdict(list)
    risk_rows = []
    with PHASE14_RISK_STREAM.open(newline="", encoding="utf-8") as handle:
        for raw in csv.DictReader(handle):
            row = {
                "repeat": int(raw["repeat"]), "attack": raw["attack"],
                "seed": int(raw["seed"]), "block": int(raw["block"]),
                "source_index": int(raw["source_index"]),
                "risk_score": float(raw["risk_score"]),
                "risk_level": raw["risk_level"],
            }
            risk_rows.append(row)
            grouped[(row["repeat"], row["attack"], row["seed"])].append({
                key: row[key] for key in ("block", "source_index", "risk_score", "risk_level")
            })
    streams = [(*key, grouped[key]) for key in sorted(grouped)]
    if len(streams) != len(ATTACKS) * len(SEEDS):
        raise ValueError("frozen Phase 14 stream has unexpected repeat count")
    if any(len(stream) != BLOCKS for _, _, _, stream in streams):
        raise ValueError("frozen Phase 14 stream has unexpected block count")
    return streams, risk_rows


def main() -> None:
    if _digest(PROTOCOL) != PROTOCOL_SHA256: raise ValueError("Phase 15 protocol changed")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    streams, risk_rows = _load_frozen_risk_streams()
    print("[load SHA-256 verified Phase 14 public content-risk streams]", flush=True)
    for repeat, attack, seed, stream in streams:
        print(f"  repeat={repeat}/10 attack={attack} high={sum(i['risk_level']=='high' for i in stream)}", flush=True)
    all_rows, repeat_diag = [], []
    print("[run paired dual-axis validation methods]", flush=True)
    for repeat, attack, seed, stream in streams:
        print(f"  consensus repeat={repeat}/10 attack={attack}", flush=True)
        rows, diag = _run_repeat(repeat, attack, seed, stream); all_rows.extend(rows)
        for method in FACTORIAL_METHODS:
            repeat_diag.append({"repeat": repeat, "attack": attack, "seed": seed, "method": method,
                "compromised_activations": diag["compromised_activations"][method],
                "honest_audits": diag["honest_audits"][method], "false_honest_audits": diag["false_honest_audits"][method]})
    overall = _aggregate(all_rows, ("method",)); by_content = _aggregate(all_rows, ("method", "content_level"))
    by_validator = _aggregate([r for r in all_rows if r["validator_level"] != "na"], ("method", "validator_level"))
    by_epoch = _aggregate(all_rows, ("method", "epoch")); idx = {r["method"]: r for r in overall}
    fixed, content, validator, dual, full = (idx[m] for m in ("feedback_fixed", "content_only", "validator_only", "dual_axis", "fixed_full_pbft"))
    exposure = _relative_reduction(fixed["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"])
    vs_validator = _relative_reduction(validator["risk_weighted_fast_exposure"], dual["risk_weighted_fast_exposure"])
    interaction = content["risk_weighted_fast_exposure"] + validator["risk_weighted_fast_exposure"] - fixed["risk_weighted_fast_exposure"] - dual["risk_weighted_fast_exposure"]
    wire_ratio = dual["mean_total_wire_messages"] / fixed["mean_total_wire_messages"]
    full_reduction = _relative_reduction(full["mean_total_wire_messages"], dual["mean_total_wire_messages"])
    margin = dual["expensive_full_path_rate"] - fixed["fallback_rate"]
    total_honest = sum(r["honest_audits"] for r in repeat_diag if r["method"] == "dual_axis")
    total_false = sum(r["false_honest_audits"] for r in repeat_diag if r["method"] == "dual_axis")
    lo, hi = wilson_interval(total_false, total_honest)
    activations = sum(r["compromised_activations"] for r in repeat_diag if r["method"] == "dual_axis")
    static_idx = {(r["repeat"], r["block"], r["method"]): r for r in all_rows if r["method"] in {"static_k13", "old_risk_size"}}
    mismatches = 0
    for rr in risk_rows:
        if rr["risk_level"] != "low": continue
        a, b = static_idx[(rr["repeat"], rr["block"], "static_k13")], static_idx[(rr["repeat"], rr["block"], "old_risk_size")]
        mismatches += sum(a[k] != b[k] for k in ("fallback", "fast_breach", "protocol_messages"))
    diagnostics = [{"exposure_reduction_vs_feedback_fixed": exposure,
        "exposure_reduction_vs_validator_only": vs_validator, "factorial_interaction": interaction,
        "wire_ratio_vs_feedback_fixed": wire_ratio, "wire_reduction_vs_full_pbft": full_reduction,
        "expensive_full_path_margin_vs_fixed_fallback": margin,
        "direct_full_shadow_breach_precision": dual["shadow_fast_breach_precision"],
        "honest_audit_false_rate": total_false / total_honest, "honest_audit_wilson_low": lo,
        "honest_audit_wilson_high": hi, "compromised_activations": activations,
        "paired_static_low_mismatches": mismatches}]
    stop = [{"integrity_pairing_pass": int(mismatches == 0),
        "safety_liveness_pass": int(dual["final_illegal_acceptance_rate"] == 0 and dual["final_legal_commit_rate"] >= .99 and dual["final_refusal_rate"] <= .01),
        "risk_weighted_exposure_pass": int(exposure >= .20), "wire_noninferiority_pass": int(wire_ratio <= 1.10),
        "wire_vs_full_pbft_pass": int(full_reduction >= .15), "expensive_full_path_pass": int(margin <= .05),
        "dual_vs_validator_only_pass": int(vs_validator >= .10), "positive_interaction_pass": int(interaction > 0),
        "alert_precision_pass": int(dual["shadow_fast_breach_precision"] >= .10),
        "audit_reactivation_pass": int(lo <= ERROR_RATE <= hi and activations == 0)}]
    stop[0]["all_phase15_stop_lines_pass"] = int(all(stop[0].values()))
    for name, data in (("risk_stream", risk_rows), ("block_level", all_rows), ("overall", overall),
        ("by_content", by_content), ("by_validator", by_validator), ("by_epoch", by_epoch),
        ("repeat_diagnostics", repeat_diag), ("diagnostics", diagnostics), ("stop_lines", stop)):
        _write_csv(OUTPUT_DIR / f"DURAC_phase15_{name}.csv", data)
    (OUTPUT_DIR / "DURAC_phase15_manifest.json").write_text(json.dumps({
        "protocol_sha256": _digest(PROTOCOL), "runner_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "phase14_risk_stream_sha256": _digest(PHASE14_RISK_STREAM),
        "blocks_per_repeat": BLOCKS, "repeats": len(streams), "methods": METHODS,
        "outputs": {p.name: _digest(p) for p in sorted(OUTPUT_DIR.glob("*.csv"))}}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("===== DURAC PHASE 15 DUAL AXIS =====")
    for row in overall: print(f"{row['method']:27s} commit={row['final_legal_commit_rate']:.3%} fallback={row['fallback_rate']:.3%} direct={row['direct_full_rate']:.3%} exposure={row['risk_weighted_fast_exposure']:.4%} wire={row['mean_total_wire_messages']:.2f}")
    print(json.dumps(diagnostics[0], indent=2, sort_keys=True)); print(json.dumps(stop[0], indent=2, sort_keys=True))


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Phase 15 legacy dual-axis source simulation. The paper uses the Phase-16 replay runner for canonical RQ4 regeneration.')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
