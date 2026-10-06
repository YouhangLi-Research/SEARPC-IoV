#!/usr/bin/env python3
"""Yadav direct-history selection versus SEARPC under identical shared audits.

This provenance-closure runner keeps the published Yadav selection-stage
adaptation and replaces its former selected-member audit schedule with the
same seven exogenous audit challenges used by the external baseline BRBC comparison.  The
two methods therefore receive identical targets, outcomes, delivery heights,
risk weights, committee size, and finality threshold at every block.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import csv
from hashlib import sha256
import itertools
import json
from pathlib import Path
import random
from statistics import mean

from authorized_selection import plan_authorized_fast_path
from canonical_evidence import (
    CanonicalEvidenceLog,
    CanonicalEvidenceRecord,
    SelectionCapability,
    audit_plan_output_root,
    build_snapshot,
    experiment_registry_entries,
    neutral_risk_record,
    registry_root,
)
from durac import CertifiedSelection
from observable_fast_path import (
    decide_from_observation,
    offline_fault_evaluation,
    simulate_transcript_from_fault_labels,
)
from run_dual_path import _audit_domain
from run_closed_loop import AUDIT_WIRE_MESSAGES
from run_durac_rotating_attack import BASE_SEED, DELAY, _compromised
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
from typed_authority import AuthorityTarget, require_authority


METHODS = ("yadav_direct_history_shared_audits", "searpc_shared_audits")
BOOTSTRAP_SEED = 310826
BOOTSTRAP_DRAWS = 20_000


def digest(path: Path) -> str:
    hasher = sha256()
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


class DirectHistoryTrustState:
    """Yadav Eqs. (6), (7), and (12) with a symmetric Beta(1,1) start."""

    def __init__(self, validator_ids):
        self.successes = {int(item): 1.0 for item in validator_ids}
        self.failures = {int(item): 1.0 for item in validator_ids}

    def update(self, validator_id: int, outcome: float) -> None:
        validator_id = int(validator_id)
        if float(outcome) not in (0.0, 1.0):
            raise ValueError("direct-history adapter requires binary outcomes")
        target = self.successes if float(outcome) == 1.0 else self.failures
        target[validator_id] += 1.0

    def scores(self) -> dict[int, float]:
        return {
            item: self.successes[item] / (self.successes[item] + self.failures[item])
            for item in self.successes
        }


def _selection_hash(
    *, repeat: int, block: int, validator_id: int, purpose: str
) -> bytes:
    """Frozen Yadav-adapter tie key with no caller-supplied event label."""

    selection_seed = (
        BASE_SEED + 1_600_000_000 + repeat * 10_000_000 + block * 10_000
    )
    canonical_context = f"phase16-{repeat}-{block}"
    material = (
        f"{selection_seed}|{canonical_context}|"
        f"{int(validator_id)}|{purpose}"
    )
    return sha256(material.encode("utf-8")).digest()


def select_highest_trust(
    scores: dict[int, float], *, repeat: int, block: int,
    capability: SelectionCapability
) -> tuple[int, ...]:
    """Highest-trust membership with deterministic random tie resolution."""

    require_authority(capability.authority, AuthorityTarget.COMMITTEE_SEED)
    if len(scores) < K or any(not 0.0 <= value <= 1.0 for value in scores.values()):
        raise ValueError("invalid trust-score population")
    ordered = sorted(
        scores,
        key=lambda validator_id: (
            -scores[validator_id],
            _selection_hash(
                repeat=repeat,
                block=block,
                validator_id=validator_id,
                purpose="yadav-tie",
            ),
            validator_id,
        ),
    )
    return tuple(int(item) for item in ordered[:K])


def run_yadav_repeat(repeat, attack, seed, stream):
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
    trust = DirectHistoryTrustState(range(N))
    queue = defaultdict(list)
    log = CanonicalEvidenceLog()
    previous_members: set[int] | None = None
    rows = []

    for item in stream:
        block = int(item["block"])
        risk = float(item["risk_score"])
        compromised = _compromised(block, *cohort_tuple)

        committed = log.commit(queue.pop(block, []), decision_height=block)
        for record in committed.accepted:
            trust.update(record.subject_id, record.outcome)

        source_height = max(0, block - 1)
        risk_record = neutral_risk_record(
            source_height, "yadav-content-not-authorized"
        )
        snapshot = build_snapshot(
            height=block,
            view=0,
            audit_root=log.root,
            risk=risk_record,
            registry_root=reg_root,
        )
        seed_commitment = snapshot.commit_seed_projection()
        audit_capability = snapshot.audit_capability(content_aware=False)
        selection_capability = main_selection_capability(
            repeat, block, seed_commitment, "primary"
        )

        scores = trust.scores()
        ranked_ids = select_highest_trust(
            scores,
            repeat=repeat,
            block=block,
            capability=selection_capability,
        )
        selected_pool = candidate_list(ranked_ids, domains, latencies)
        plan = plan_authorized_fast_path(
            selected_pool,
            registered,
            size=K,
            selection=CertifiedSelection.DIVERSE_UNIFORM,
            capability=selection_capability,
            leader_reputation_weighted=False,
            backup_collector_enabled=True,
        )
        if set(plan.member_ids) != set(ranked_ids):
            raise AssertionError("fixed-k shell changed Yadav membership")

        latent = int(
            offline_fault_evaluation(
                plan, byzantine_ids=compromised
            ).fault_budget_exceedance
        )
        transcript = simulate_transcript_from_fault_labels(
            plan, byzantine_ids=compromised
        )
        decision = decide_from_observation(
            plan,
            transcript,
            use_full_certificate=True,
            fallback_enabled=True,
            backup_collector_enabled=True,
        )

        targets = tuple(
            _rank_ids(repeat, block, range(N), 41)[:EQUAL_AUDIT_BUDGET]
        )
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
            behavior_outcomes.append(
                f"{validator_id}:{behavior}:{int(outcome)}"
            )
            if due <= len(stream):
                queue[due].append(
                    CanonicalEvidenceRecord(
                        evidence_id=(
                            f"{repeat}:{block}:{due}:{validator_id}:"
                            f"{domain}:{int(outcome >= 0.5)}"
                        ),
                        subject_id=int(validator_id),
                        evidence_kind="validator_audit",
                        outcome=float(outcome),
                        source_domain=domain,
                        effective_height=due - 1,
                        delivery_height=due,
                        source_height=block,
                    )
                )

        selected_ids = tuple(int(item) for item in plan.member_ids)
        selected_malicious = sum(
            int(validator_id in compromised) for validator_id in selected_ids
        )
        current_members = set(selected_ids)
        changed_seats = (
            0
            if previous_members is None
            else K - len(previous_members & current_members)
        )
        previous_members = current_members
        score_values = list(scores.values())
        rows.append({
            "repeat": repeat,
            "attack": attack,
            "seed": seed,
            "block": block,
            "method": "yadav_direct_history_shared_audits",
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
            "active_pool": N,
            "latent_post_control_exceedance": latent,
            "direct_standard": 0,
            "actual_handoff": int(decision.actual_handoff),
            "expensive_full_path": int(decision.actual_handoff),
            "hint_assembly_timeout": int(decision.hint_assembly_timeout),
            "invalid_hint": int(decision.invalid_hint),
            "block_unavailable": int(decision.block_unavailable),
            "audits": len(targets),
            "protocol_messages": decision.protocol_message_count,
            "total_wire_messages": (
                decision.protocol_message_count
                + AUDIT_WIRE_MESSAGES * len(targets)
            ),
            "final_Q": Q,
            "final_legal_commit": int(decision.final_legal_eventual_commit),
            "final_illegal_acceptance": int(
                decision.final_illegal_block_accepted
            ),
            "selected_malicious_seats": selected_malicious,
            "selected_compromised_fraction": selected_malicious / K,
            "trust_min": min(score_values),
            "trust_mean": mean(score_values),
            "trust_max": max(score_values),
            "selected_trust_mean": mean(
                scores[validator_id] for validator_id in selected_ids
            ),
            "changed_seats": changed_seats,
            "audit_target_ids": "|".join(map(str, targets)),
            "audit_behavior_outcomes": "|".join(behavior_outcomes),
            "ranked_member_ids": "|".join(map(str, ranked_ids)),
            "selected_member_ids": "|".join(map(str, selected_ids)),
        })
    return rows


def normalize_searpc_rows(rows: list[dict]) -> list[dict]:
    cohort_tuple = cohorts()
    output = []
    for row in rows:
        selected_ids = tuple(
            int(item)
            for item in str(row.get("selected_member_ids", "")).split("|")
            if item
        )
        compromised = _compromised(int(row["block"]), *cohort_tuple)
        malicious = sum(
            int(validator_id in compromised) for validator_id in selected_ids
        )
        output.append({
            "repeat": int(row["repeat"]),
            "attack": row["attack"],
            "seed": int(row["seed"]),
            "block": int(row["block"]),
            "method": "searpc_shared_audits",
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
            "latent_post_control_exceedance": int(
                row["latent_post_control_exceedance"]
            ),
            "direct_standard": int(row["direct_standard"]),
            "actual_handoff": int(row["actual_handoff"]),
            "expensive_full_path": int(
                row["direct_standard"] or row["actual_handoff"]
            ),
            "hint_assembly_timeout": int(row["hint_assembly_timeout"]),
            "invalid_hint": int(row["invalid_hint"]),
            "block_unavailable": int(row["block_unavailable"]),
            "audits": int(row["audits"]),
            "protocol_messages": int(row["protocol_messages"]),
            "total_wire_messages": int(row["total_wire_messages"]),
            "final_Q": int(row["final_Q"]),
            "final_legal_commit": int(row["final_legal_commit"]),
            "final_illegal_acceptance": int(
                row["final_illegal_acceptance"]
            ),
            "selected_malicious_seats": malicious,
            "selected_compromised_fraction": (
                malicious / K if selected_ids else 0.0
            ),
            "trust_min": "",
            "trust_mean": "",
            "trust_max": "",
            "selected_trust_mean": "",
            "changed_seats": "",
            "audit_target_ids": row["audit_target_ids"],
            "audit_behavior_outcomes": row["audit_behavior_outcomes"],
            "ranked_member_ids": "",
            "selected_member_ids": row["selected_member_ids"],
        })
    return output


def unit_summary(members: list[dict]) -> dict[str, float]:
    risk_total = sum(float(row["risk_score"]) for row in members)
    return {
        "risk_weighted_exposure": sum(
            float(row["risk_score"])
            * int(row["latent_post_control_exceedance"])
            for row in members
        ) / risk_total,
        "unweighted_exceedance_rate": mean(
            int(row["latent_post_control_exceedance"]) for row in members
        ),
        "actual_handoff_rate": mean(
            int(row["actual_handoff"]) for row in members
        ),
        "direct_standard_rate": mean(
            int(row["direct_standard"]) for row in members
        ),
        "expensive_full_path_rate": mean(
            int(row["expensive_full_path"]) for row in members
        ),
        "mean_active_pool": mean(int(row["active_pool"]) for row in members),
        "mean_selected_compromised_fraction": mean(
            float(row["selected_compromised_fraction"]) for row in members
        ),
        "mean_audits": mean(int(row["audits"]) for row in members),
        "mean_total_wire_messages": mean(
            int(row["total_wire_messages"]) for row in members
        ),
        "final_legal_commit_rate": mean(
            int(row["final_legal_commit"]) for row in members
        ),
        "final_illegal_acceptance": sum(
            int(row["final_illegal_acceptance"]) for row in members
        ),
    }


def summarize(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[row["method"]].append(row)
    output = []
    for method in METHODS:
        members = groups[method]
        item = {"method": method, "blocks": len(members)}
        item.update(unit_summary(members))
        item.update(
            final_Q_min=min(int(row["final_Q"]) for row in members),
            final_Q_max=max(int(row["final_Q"]) for row in members),
        )
        output.append(item)
    return output


def per_trace(rows: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for row in rows:
        groups[(int(row["repeat"]), row["attack"], row["method"])].append(row)
    output = []
    for (repeat, attack, method), members in sorted(groups.items()):
        item = {"repeat": repeat, "attack": attack, "method": method}
        item.update(unit_summary(members))
        output.append(item)
    return output


def exact_sign_flip_pvalue(values: list[float]) -> float:
    nonzero = [value for value in values if abs(value) > 1e-15]
    observed = abs(mean(nonzero))
    extreme = total = 0
    for signs in itertools.product((-1.0, 1.0), repeat=len(nonzero)):
        statistic = abs(
            mean(sign * value for sign, value in zip(signs, nonzero))
        )
        extreme += int(statistic >= observed - 1e-15)
        total += 1
    return extreme / total


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    low = int(position)
    high = min(len(ordered) - 1, low + 1)
    fraction = position - low
    return ordered[low] * (1.0 - fraction) + ordered[high] * fraction


def paired_inference(trace_rows: list[dict]) -> list[dict]:
    lookup = {
        (int(row["repeat"]), row["method"]): row for row in trace_rows
    }
    repeats = sorted({int(row["repeat"]) for row in trace_rows})
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
    output = []
    for metric_index, metric in enumerate(metrics):
        differences = [
            float(lookup[(repeat, "searpc_shared_audits")][metric])
            - float(
                lookup[(repeat, "yadav_direct_history_shared_audits")][metric]
            )
            for repeat in repeats
        ]
        rng = random.Random(BOOTSTRAP_SEED + metric_index)
        bootstrap = [
            mean(
                differences[rng.randrange(len(differences))]
                for _ in differences
            )
            for _ in range(BOOTSTRAP_DRAWS)
        ]
        output.append({
            "baseline": "yadav_direct_history_shared_audits",
            "treated": "searpc_shared_audits",
            "metric": metric,
            "n_traces": len(repeats),
            "searpc_minus_yadav_mean": mean(differences),
            "ci95_low": percentile(bootstrap, 0.025),
            "ci95_high": percentile(bootstrap, 0.975),
            "exact_sign_flip_p": exact_sign_flip_pvalue(differences),
            "searpc_lower_count": sum(value < 0 for value in differences),
            "bootstrap_seed": BOOTSTRAP_SEED + metric_index,
            "bootstrap_draws": BOOTSTRAP_DRAWS,
        })
    return output


def validate_pairing(rows: list[dict]) -> list[dict]:
    groups = defaultdict(dict)
    for row in rows:
        groups[(int(row["repeat"]), int(row["block"]))][row["method"]] = row
    missing = target_mismatch = outcome_mismatch = audit_mismatch = 0
    seed_projection_mismatch = evidence_root_mismatch = 0
    for methods in groups.values():
        if set(methods) != set(METHODS):
            missing += 1
            continue
        yadav = methods[METHODS[0]]
        searpc = methods[METHODS[1]]
        target_mismatch += int(
            yadav["audit_target_ids"] != searpc["audit_target_ids"]
        )
        outcome_mismatch += int(
            yadav["audit_behavior_outcomes"]
            != searpc["audit_behavior_outcomes"]
        )
        audit_mismatch += int(int(yadav["audits"]) != int(searpc["audits"]))
        seed_projection_mismatch += int(
            yadav["seed_projection_root"] != searpc["seed_projection_root"]
        )
        evidence_root_mismatch += int(
            yadav["evidence_root"] != searpc["evidence_root"]
        )
    yadav_rows = [row for row in rows if row["method"] == METHODS[0]]
    searpc_rows = [row for row in rows if row["method"] == METHODS[1]]
    checks = {
        "paired_blocks": len(groups),
        "missing_method_blocks": missing,
        "audit_target_mismatches": target_mismatch,
        "audit_outcome_mismatches": outcome_mismatch,
        "audit_count_mismatches": audit_mismatch,
        "seed_projection_mismatches": seed_projection_mismatch,
        "evidence_root_mismatches": evidence_root_mismatch,
        "exact_seven_audits_pass": int(
            all(int(row["audits"]) == EQUAL_AUDIT_BUDGET for row in rows)
        ),
        "fixed_k13_pass": int(
            all(
                len(str(row["selected_member_ids"]).split("|")) == K
                for row in yadav_rows
            )
        ),
        "fixed_final_Q27_pass": int(
            all(int(row["final_Q"]) == Q for row in rows)
        ),
        "legal_commit_100pct_pass": int(
            all(int(row["final_legal_commit"]) == 1 for row in rows)
        ),
        "illegal_acceptance_zero_pass": int(
            all(int(row["final_illegal_acceptance"]) == 0 for row in rows)
        ),
        "yadav_rows": len(yadav_rows),
        "searpc_rows": len(searpc_rows),
    }
    checks["all_pairing_and_protocol_checks_pass"] = int(
        len(groups) == 6000
        and len(yadav_rows) == 6000
        and len(searpc_rows) == 6000
        and all(
            checks[name] == 0
            for name in (
                "missing_method_blocks",
                "audit_target_mismatches",
                "audit_outcome_mismatches",
                "audit_count_mismatches",
                "seed_projection_mismatches",
                "evidence_root_mismatches",
            )
        )
        and all(
            checks[name] == 1
            for name in (
                "exact_seven_audits_pass",
                "fixed_k13_pass",
                "fixed_final_Q27_pass",
                "legal_commit_100pct_pass",
                "illegal_acceptance_zero_pass",
            )
        )
    )
    return [checks]


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
        print(f"Yadav/SEARPC shared-audit trace {repeat}/10", flush=True)
        all_rows.extend(run_yadav_repeat(repeat, attack, seed, stream))
        searpc_raw = run_repeat(
            repeat,
            attack,
            seed,
            stream,
            audit_regime="shared_exogenous",
            audit_budget=EQUAL_AUDIT_BUDGET,
            selected_methods=("validator_only",),
        )
        all_rows.extend(normalize_searpc_rows(searpc_raw))
    all_rows.sort(
        key=lambda row: (
            int(row["repeat"]),
            int(row["block"]),
            METHODS.index(row["method"]),
        )
    )

    summary_rows = summarize(all_rows)
    trace_rows = per_trace(all_rows)
    paired_rows = paired_inference(trace_rows)
    validation_rows = validate_pairing(all_rows)

    write_csv(
        args.output_dir / "YADAV_SHARED7_block_level.csv", all_rows
    )
    write_csv(
        args.output_dir / "YADAV_SHARED7_summary.csv", summary_rows
    )
    write_csv(
        args.output_dir / "YADAV_SHARED7_per_trace.csv", trace_rows
    )
    write_csv(
        args.output_dir / "YADAV_SHARED7_paired_inference.csv",
        paired_rows,
    )
    write_csv(
        args.output_dir / "YADAV_SHARED7_validation.csv",
        validation_rows,
    )
    write_csv(
        args.output_dir / "YADAV_SHARED7_risk_stream.csv", risk_rows
    )

    manifest = {
        "status": "deterministic result-provenance closure",
        "publication_label": "Yadav direct-history trust-ranked selection",
        "external_reference_doi": "10.1109/TVT.2025.3575775",
        "risk_stream": str(args.risk_stream),
        "risk_stream_sha256": digest(args.risk_stream),
        "runner_sha256": digest(Path(__file__)),
        "network": {"N": N, "k": K, "q_k": QK, "Q": Q},
        "traces": len(streams),
        "blocks_per_trace": 600,
        "audit_budget_per_block": EQUAL_AUDIT_BUDGET,
        "audit_regime": "shared_exogenous",
        "delivery_delay_blocks": DELAY,
        "trust": {
            "direct_history": "successes/(successes+failures)",
            "pseudo_successes": 1.0,
            "pseudo_failures": 1.0,
            "selection": "highest trust; deterministic hash tie resolution",
            "tie_seed": "frozen adapter seed plus canonical repeat/height context",
            "caller_controlled_event_label": False,
        },
        "rows": len(all_rows),
        "validation": validation_rows[0],
        "outputs": {
            path.name: digest(path)
            for path in sorted(args.output_dir.glob("*.csv"))
        },
    }
    manifest_path = args.output_dir / "YADAV_SHARED7_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "summary": summary_rows,
        "paired_exposure": paired_rows[0],
        "validation": validation_rows[0],
        "manifest_sha256": digest(manifest_path),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
