#!/usr/bin/env python3
"""BRBC-derived eligibility versus pure SEARPC core under shared audits."""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
import hashlib
import itertools
import json
import math
from pathlib import Path
import random
from statistics import mean, stdev

from authorized_selection import plan_authorized_fast_path
from canonical_evidence import (
    CanonicalEvidenceLog,
    CanonicalEvidenceRecord,
    audit_plan_output_root,
    build_snapshot,
    derive_committee_capability,
    experiment_registry_entries,
    neutral_risk_record,
    registry_root,
)
from durac import CertifiedSelection
from durac.consensus import pbft_protocol_message_count
from observable_fast_path import (
    decide_from_observation,
    offline_fault_evaluation,
    simulate_transcript_from_fault_labels,
)
from run_dual_path import AUDIT_DOMAIN_COUNT, _audit_domain
from run_closed_loop import AUDIT_WIRE_MESSAGES
from run_durac_rotating_attack import DELAY, _compromised
from run_participation import (
    EQUAL_AUDIT_BUDGET,
    K,
    N,
    Q,
    QK,
    _observable_audit_outcome,
    _rank_ids,
    block_beacon,
    candidate_list,
    cohorts,
    load_risk_stream,
    main_selection_capability,
    run_repeat,
)
from run_durac_validator_recovery import _domains, _latencies


METHODS = ("brbc_eligibility", "searpc_core_shared_audits")
BRBC_THRESHOLD = 7.0
BRBC_INITIAL = 7.0
BRBC_DELTA = 1.0
JUDGE_DOMAINS = tuple(f"audit-{index}" for index in range(AUDIT_DOMAIN_COUNT))


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"empty output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _scores() -> dict[str, dict[int, float]]:
    return {
        domain: {validator_id: BRBC_INITIAL for validator_id in range(N)}
        for domain in JUDGE_DOMAINS
    }


def _eligible(scores, validator_id: int) -> bool:
    below = sum(scores[domain][validator_id] < BRBC_THRESHOLD for domain in JUDGE_DOMAINS)
    return below < math.floor(AUDIT_DOMAIN_COUNT / 2) + 1


def _update_score(scores, record: CanonicalEvidenceRecord) -> None:
    if record.source_domain not in scores:
        raise ValueError(f"unknown BRBC judge domain {record.source_domain}")
    previous = scores[record.source_domain][record.subject_id]
    change = BRBC_DELTA if record.outcome >= 0.5 else -BRBC_DELTA
    scores[record.source_domain][record.subject_id] = min(10.0, max(0.0, previous + change))


def run_brbc_repeat(repeat, attack, seed, stream):
    domains, latencies = _domains(), _latencies()
    cohort_tuple = cohorts()
    registry_entries = experiment_registry_entries(
        [domains[index] for index in range(N)],
        registry_epoch=0,
        configuration={
            "committee_size": K,
            "fast_quorum": QK,
            "final_quorum": Q,
            "domain_seat_fraction": "0.40",
        },
    )
    reg_root = registry_root(registry_entries)
    registered = candidate_list(range(N), domains, latencies)
    scores = _scores()
    queue = defaultdict(list)
    log = CanonicalEvidenceLog()
    rows = []

    for item in stream:
        block = int(item["block"])
        risk = float(item["risk_score"])
        compromised = _compromised(block, *cohort_tuple)
        committed = log.commit(queue.pop(block, []), decision_height=block)
        for record in committed.accepted:
            _update_score(scores, record)

        eligible_ids = {validator_id for validator_id in range(N) if _eligible(scores, validator_id)}
        pool = candidate_list(eligible_ids, domains, latencies)
        direct = int(len(pool) < K)
        selected_ids = ()
        latent = 0
        actual_handoff = 0
        timeout = invalid = unavailable = 0
        protocol_messages = pbft_protocol_message_count(N) if direct else 0
        final_legal = 1
        final_illegal = 0

        source_height = max(0, block - 1)
        risk_record = neutral_risk_record(source_height, "brbc-content-not-authorized")
        snapshot = build_snapshot(
            height=block,
            view=0,
            audit_root=log.root,
            risk=risk_record,
            registry_root=reg_root,
        )
        seed_commitment = snapshot.commit_seed_projection()
        audit_capability = snapshot.audit_capability(content_aware=False)
        capability = main_selection_capability(
            repeat, block, seed_commitment, "primary"
        )
        if not direct:
            plan = plan_authorized_fast_path(
                pool,
                registered,
                size=K,
                selection=CertifiedSelection.DIVERSE_UNIFORM,
                capability=capability,
                leader_reputation_weighted=False,
                backup_collector_enabled=True,
            )
            selected_ids = plan.member_ids
            latent = int(
                offline_fault_evaluation(plan, byzantine_ids=compromised).fault_budget_exceedance
            )
            transcript = simulate_transcript_from_fault_labels(plan, byzantine_ids=compromised)
            decision = decide_from_observation(
                plan,
                transcript,
                use_full_certificate=True,
                fallback_enabled=True,
                backup_collector_enabled=True,
            )
            actual_handoff = int(decision.actual_handoff)
            timeout = int(decision.hint_assembly_timeout)
            invalid = int(decision.invalid_hint)
            unavailable = int(decision.block_unavailable)
            protocol_messages = decision.protocol_message_count
            final_legal = int(decision.final_legal_eventual_commit)
            final_illegal = int(decision.final_illegal_block_accepted)

        targets = tuple(_rank_ids(repeat, block, range(N), 41)[:EQUAL_AUDIT_BUDGET])
        audit_output_root = audit_plan_output_root(
            audit_capability, targets=targets, coverage=1.0
        )
        behavior_outcomes = []
        for validator_id in targets:
            outcome, behavior = _observable_audit_outcome(
                repeat=repeat,
                block=block,
                validator_id=validator_id,
                compromised=compromised,
            )
            due = block + DELAY
            domain = _audit_domain(repeat, block, validator_id)
            behavior_outcomes.append(f"{validator_id}:{behavior}:{int(outcome)}")
            if due <= len(stream):
                queue[due].append(CanonicalEvidenceRecord(
                    evidence_id=f"{repeat}:{block}:{due}:{validator_id}:{domain}:{int(outcome >= 0.5)}",
                    subject_id=int(validator_id),
                    evidence_kind="validator_audit",
                    outcome=float(outcome),
                    source_domain=domain,
                    effective_height=due - 1,
                    delivery_height=due,
                    source_height=block,
                ))

        selected_malicious = sum(int(validator_id in compromised) for validator_id in selected_ids)
        all_scores = [scores[domain][validator_id] for domain in JUDGE_DOMAINS for validator_id in range(N)]
        rows.append({
            "repeat": repeat,
            "attack": attack,
            "seed": seed,
            "block": block,
            "method": "brbc_eligibility",
            "audit_regime": "shared_exogenous_7",
            "risk_score": risk,
            "evidence_root": log.root,
            "control_snapshot_root": snapshot.root,
            "seed_projection_root": seed_commitment.root,
            "audit_plan_projection_root": audit_capability.projection_root,
            "audit_plan_output_root": audit_output_root,
            "registry_root": reg_root,
            "beacon_digest": block_beacon(repeat, block),
            "evidence_records": log.records,
            "replayed_records": len(committed.replayed),
            "conflicting_records": len(committed.conflicts),
            "rejected_records": len(committed.rejected),
            "active_pool": len(eligible_ids),
            "latent_post_control_exceedance": latent,
            "direct_standard": direct,
            "actual_handoff": actual_handoff,
            "expensive_full_path": int(direct or actual_handoff),
            "hint_assembly_timeout": timeout,
            "invalid_hint": invalid,
            "block_unavailable": unavailable,
            "audits": len(targets),
            "protocol_messages": protocol_messages,
            "total_wire_messages": protocol_messages + AUDIT_WIRE_MESSAGES * len(targets),
            "final_Q": Q,
            "final_legal_commit": final_legal,
            "final_illegal_acceptance": final_illegal,
            "selected_malicious_seats": selected_malicious,
            "selected_compromised_fraction": selected_malicious / K if selected_ids else 0.0,
            "brbc_mean_judge_reputation": mean(all_scores),
            "brbc_min_judge_reputation": min(all_scores),
            "audit_target_ids": "|".join(map(str, targets)),
            "audit_behavior_outcomes": "|".join(behavior_outcomes),
            "selected_member_ids": "|".join(map(str, selected_ids)),
        })
    return rows


def normalize_searpc_rows(rows: list[dict]) -> list[dict]:
    cohort_tuple = cohorts()
    output = []
    for row in rows:
        selected_ids = tuple(
            int(item) for item in str(row.get("selected_member_ids", "")).split("|") if item
        )
        compromised = _compromised(int(row["block"]), *cohort_tuple)
        malicious = sum(int(validator_id in compromised) for validator_id in selected_ids)
        output.append({
            "repeat": int(row["repeat"]),
            "attack": row["attack"],
            "seed": int(row["seed"]),
            "block": int(row["block"]),
            "method": "searpc_core_shared_audits",
            "audit_regime": "shared_exogenous_7",
            "risk_score": float(row["risk_score"]),
            "evidence_root": row["evidence_root"],
            "control_snapshot_root": row["control_snapshot_root"],
            "seed_projection_root": row["seed_projection_root"],
            "audit_plan_projection_root": row["audit_plan_projection_root"],
            "audit_plan_output_root": row["audit_plan_output_root"],
            "registry_root": row["registry_root"],
            "beacon_digest": row["beacon_digest"],
            "evidence_records": int(row["evidence_records"]),
            "replayed_records": int(row["replayed_records"]),
            "conflicting_records": int(row["conflicting_records"]),
            "rejected_records": int(row["rejected_records"]),
            "active_pool": int(row["active_pool"]),
            "latent_post_control_exceedance": int(row["latent_post_control_exceedance"]),
            "direct_standard": int(row["direct_standard"]),
            "actual_handoff": int(row["actual_handoff"]),
            "expensive_full_path": int(row["direct_standard"] or row["actual_handoff"]),
            "hint_assembly_timeout": int(row["hint_assembly_timeout"]),
            "invalid_hint": int(row["invalid_hint"]),
            "block_unavailable": int(row["block_unavailable"]),
            "audits": int(row["audits"]),
            "protocol_messages": int(row["protocol_messages"]),
            "total_wire_messages": int(row["total_wire_messages"]),
            "final_Q": int(row["final_Q"]),
            "final_legal_commit": int(row["final_legal_commit"]),
            "final_illegal_acceptance": int(row["final_illegal_acceptance"]),
            "selected_malicious_seats": malicious,
            "selected_compromised_fraction": malicious / K if selected_ids else 0.0,
            "brbc_mean_judge_reputation": "",
            "brbc_min_judge_reputation": "",
            "audit_target_ids": row["audit_target_ids"],
            "audit_behavior_outcomes": row["audit_behavior_outcomes"],
            "selected_member_ids": row["selected_member_ids"],
        })
    return output


def summarize(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[row["method"]].append(row)
    output = []
    for method in METHODS:
        members = groups[method]
        risk_total = sum(row["risk_score"] for row in members)
        output.append({
            "method": method,
            "blocks": len(members),
            "risk_weighted_exposure": sum(
                row["risk_score"] * row["latent_post_control_exceedance"] for row in members
            ) / risk_total,
            "unweighted_exceedance_rate": mean(row["latent_post_control_exceedance"] for row in members),
            "actual_handoff_rate": mean(row["actual_handoff"] for row in members),
            "direct_standard_rate": mean(row["direct_standard"] for row in members),
            "expensive_full_path_rate": mean(row["expensive_full_path"] for row in members),
            "mean_active_pool": mean(row["active_pool"] for row in members),
            "mean_selected_compromised_fraction": mean(row["selected_compromised_fraction"] for row in members),
            "mean_audits": mean(row["audits"] for row in members),
            "mean_total_wire_messages": mean(row["total_wire_messages"] for row in members),
            "final_Q_min": min(row["final_Q"] for row in members),
            "final_Q_max": max(row["final_Q"] for row in members),
            "final_legal_commit_rate": mean(row["final_legal_commit"] for row in members),
            "final_illegal_acceptance": sum(row["final_illegal_acceptance"] for row in members),
        })
    return output


def exact_sign_flip_pvalue(values: list[float]) -> float:
    nonzero = [value for value in values if abs(value) > 1e-15]
    if not nonzero:
        return 1.0
    observed = abs(mean(nonzero))
    extreme = total = 0
    for signs in itertools.product((-1.0, 1.0), repeat=len(nonzero)):
        statistic = abs(mean([sign * value for sign, value in zip(signs, nonzero)]))
        extreme += int(statistic >= observed - 1e-15)
        total += 1
    return extreme / total


def paired_inference(rows: list[dict], draws: int = 20_000, seed: int = 20260921) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[(row["repeat"], row["method"])].append(row)
    metrics = (
        "risk_weighted_exposure",
        "unweighted_exceedance_rate",
        "actual_handoff_rate",
        "direct_standard_rate",
        "expensive_full_path_rate",
        "mean_active_pool",
        "mean_selected_compromised_fraction",
        "mean_total_wire_messages",
    )

    def unit_summary(members):
        risk_total = sum(row["risk_score"] for row in members)
        return {
            "risk_weighted_exposure": sum(
                row["risk_score"] * row["latent_post_control_exceedance"] for row in members
            ) / risk_total,
            "unweighted_exceedance_rate": mean(row["latent_post_control_exceedance"] for row in members),
            "actual_handoff_rate": mean(row["actual_handoff"] for row in members),
            "direct_standard_rate": mean(row["direct_standard"] for row in members),
            "expensive_full_path_rate": mean(row["expensive_full_path"] for row in members),
            "mean_active_pool": mean(row["active_pool"] for row in members),
            "mean_selected_compromised_fraction": mean(row["selected_compromised_fraction"] for row in members),
            "mean_total_wire_messages": mean(row["total_wire_messages"] for row in members),
        }

    repeats = sorted({row["repeat"] for row in rows})
    unit = {
        (repeat, method): unit_summary(groups[(repeat, method)])
        for repeat in repeats for method in METHODS
    }
    output = []
    rng = random.Random(seed)
    for metric in metrics:
        differences = [
            unit[(repeat, "searpc_core_shared_audits")][metric]
            - unit[(repeat, "brbc_eligibility")][metric]
            for repeat in repeats
        ]
        boot = []
        for _ in range(draws):
            sample = [differences[rng.randrange(len(differences))] for _ in differences]
            boot.append(mean(sample))
        boot.sort()
        output.append({
            "baseline": "brbc_eligibility",
            "treated": "searpc_core_shared_audits",
            "metric": metric,
            "n_traces": len(repeats),
            "searpc_minus_brbc_mean": mean(differences),
            "ci95_low": boot[int(0.025 * draws)],
            "ci95_high": boot[min(draws - 1, int(0.975 * draws))],
            "exact_sign_flip_p": exact_sign_flip_pvalue(differences),
            "searpc_favorable_count": sum(value < 0 for value in differences) if metric != "mean_active_pool" else sum(value > 0 for value in differences),
        })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--risk-stream", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    streams, risk_rows = load_risk_stream(args.risk_stream)
    all_rows = []
    for repeat, attack, seed, stream in streams:
        print(f"BRBC/SEARPC shared-audit trace {repeat}/10", flush=True)
        brbc_rows = run_brbc_repeat(repeat, attack, seed, stream)
        searpc_raw = run_repeat(
            repeat,
            attack,
            seed,
            stream,
            audit_regime="shared_exogenous",
            audit_budget=EQUAL_AUDIT_BUDGET,
            selected_methods=("validator_only",),
        )
        all_rows.extend(brbc_rows)
        all_rows.extend(normalize_searpc_rows(searpc_raw))
    all_rows.sort(key=lambda row: (row["repeat"], row["block"], METHODS.index(row["method"])))
    summary = summarize(all_rows)
    paired = paired_inference(all_rows)
    write_csv(args.output_dir / "BRBC_RQ4_block_level.csv", all_rows)
    write_csv(args.output_dir / "BRBC_RQ4_summary.csv", summary)
    write_csv(args.output_dir / "BRBC_RQ4_paired_inference.csv", paired)
    write_csv(args.output_dir / "BRBC_RQ4_risk_stream.csv", risk_rows)
    manifest = {
        "protocol_status": "frozen before result computation",
        "publication_label": "BRBC-derived reputation-threshold eligibility under shared fixed-finality",
        "risk_stream": str(args.risk_stream),
        "risk_stream_sha256": digest(args.risk_stream),
        "runner_sha256": digest(Path(__file__)),
        "network": {"N": N, "k": K, "q_k": QK, "Q": Q},
        "audit_budget_per_block": EQUAL_AUDIT_BUDGET,
        "audit_regime": "shared_exogenous",
        "brbc": {
            "threshold": BRBC_THRESHOLD,
            "initial_reputation": BRBC_INITIAL,
            "unit_delta": BRBC_DELTA,
            "judge_domains": list(JUDGE_DOMAINS),
            "strict_majority_below_threshold_for_ineligibility": math.floor(AUDIT_DOMAIN_COUNT / 2) + 1,
        },
        "rows": len(all_rows),
        "outputs": {path.name: digest(path) for path in sorted(args.output_dir.glob("*.csv"))},
    }
    (args.output_dir / "BRBC_RQ4_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
