#!/usr/bin/env python3
"""Run the preregistered closed loop public-risk closed-loop comparison."""

from __future__ import annotations

from collections import defaultdict, deque
import csv
from hashlib import sha256
import json
import math
from pathlib import Path
import random
from statistics import mean, stdev

import numpy as np
from scipy.stats import beta as beta_distribution

from durac import (
    AdmissionState,
    CertifiedSelection,
    basic_hotstuff_message_count,
    execute_certified_committee_consensus,
    iter_veremi_directory,
    pbft_protocol_message_count,
    select_committee_leader,
)
from run_dual_path import _audit_domain
from run_dual_role import (
    ADJUDICATION_DELAY,
    LCB_QUANTILE,
    OPINION_ATTACK_PROBABILITY,
    OPINION_NOISE,
    RECOMMENDERS,
    SEEDS,
    _ArrayBook,
    _active,
    _domain,
    _sample_recommenders,
    domain_capped_fusion,
    select_opinion_attackers,
)
from run_holdout_authorization import SAMPLE_STRIDE, _bounds
from run_conditional_trust import ATTACKS, HOLDOUT_ROOT
from run_detector_baselines import _v2_tracker
from run_durac_rotating_attack import (
    BASE_SEED,
    BLOCKS,
    COVERAGE,
    DELAY,
    ERROR_RATE,
    _audit_success,
    _compromised,
    _paired_uniform,
)
from run_durac_validator_recovery import _domains, _latencies, _tracker


OUTPUT_DIR = Path("results/durac_phase14_closed_loop")
PROTOCOL = Path("SEARPC_CLOSED_LOOP_PROTOCOL.md")
PREDICTIONS = Path(
    "results/durac_phase13_conditional_trust/SEARPC_holdout_holdout_predictions.csv"
)
PREDICTIONS_SHA256 = "58a93ef9159a7a090654c8b3adc4ffb5eeaabd7f895049e32c4911ec5c82b915"
ROLLING_WINDOW = 100
HIGH_QUANTILE = 0.90
MEDIAN_QUANTILE = 0.50
ROLE_OVERLAP = 0.5
AUDIT_WIRE_MESSAGES = 2
SIZES = {"low": 13, "medium": 19, "high": 25}
METHODS = (
    "fixed_full_pbft",
    "basic_full_hotstuff_proxy",
    "fixed_low_certified",
    "serial_risk_adaptive",
    "closed_loop_low_ablation",
    "durac_closed_loop",
)


def _digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def evenly_spaced_indices(length: int, count: int) -> tuple[int, ...]:
    if length < count or count < 2:
        raise ValueError("invalid evenly spaced mapping dimensions")
    indices = np.rint(np.linspace(0, length - 1, count)).astype(int)
    if len(set(int(value) for value in indices)) != count:
        raise ValueError("even mapping produced duplicate indices")
    return tuple(int(value) for value in indices)


def online_risk_levels(scores: list[float]) -> tuple[str, ...]:
    levels = []
    for index, score in enumerate(scores):
        if index < ROLLING_WINDOW:
            levels.append("medium")
            continue
        history = np.asarray(scores[index - ROLLING_WINDOW:index], dtype=float)
        median = float(np.quantile(history, MEDIAN_QUANTILE, method="linear"))
        high = float(np.quantile(history, HIGH_QUANTILE, method="linear"))
        levels.append("high" if score >= high else "low" if score < median else "medium")
    return tuple(levels)


def _load_prediction_rows() -> dict[str, list[dict]]:
    if _digest(PREDICTIONS) != PREDICTIONS_SHA256:
        raise ValueError("Phase 13 prediction hash mismatch")
    grouped = {attack: [] for attack in ATTACKS}
    with PREDICTIONS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            grouped[row["attack"]].append(row)
    return grouped


def _apply_pending(book: _ArrayBook, item) -> None:
    provider, truth, reliability, recommenders, opinions = item
    provider_index = np.asarray([provider], dtype=int)
    book.update(0, provider_index, np.asarray([truth]), np.asarray([reliability]))
    honesty = 1.0 - np.abs(opinions - truth)
    book.update(1, recommenders, honesty)


def _prepare_trace(attack: str, prediction_rows: list[dict]):
    definition = ATTACKS[attack]
    root = HOLDOUT_ROOT / definition["holdout_folder"] / "Train" / "json"
    sender_ids = set()
    attacker_ids = set()
    sampled = []
    records_seen = 0
    for index, (record, prediction) in enumerate(
        zip(iter_veremi_directory(root), prediction_rows, strict=True)
    ):
        if int(prediction["holdout_row"]) != index or record.attacker != int(prediction["attacker"]):
            raise ValueError(f"Phase 14 row alignment mismatch for {attack} at {index}")
        records_seen += 1
        sender_ids.add(record.sender_id)
        if record.attacker:
            attacker_ids.add(record.sender_id)
        if index % SAMPLE_STRIDE == 0:
            sampled.append(
                (
                    record.sender_id,
                    record.attacker,
                    float(prediction["contextual_probability"]),
                    float(prediction["contextual_uncertainty"]),
                )
            )
    if records_seen != len(prediction_rows):
        raise ValueError(f"Phase 14 record/prediction count mismatch for {attack}")
    identities = tuple(sorted(sender_ids))
    identity_index = {identity: index for index, identity in enumerate(identities)}
    data_attackers = frozenset(identity_index[identity] for identity in attacker_ids)
    trace = tuple(
        (identity_index[sender], attacker, probability, uncertainty)
        for sender, attacker, probability, uncertainty in sampled
    )
    domains = tuple(_domain(identity) for identity in identities)
    return trace, identities, data_attackers, domains


def _risk_stream(attack: str, seed: int, prepared) -> list[dict]:
    trace, identities, data_attackers, domains = prepared
    opinion_attackers = select_opinion_attackers(
        data_attackers, len(identities), ROLE_OVERLAP, seed
    )

    rng = random.Random(seed * 1_000_003 + 140014)
    book = _ArrayBook(len(identities), 2)
    pending = deque()
    scores = []
    for event_index, (provider, attacker, malicious_probability, message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            _apply_pending(book, item)
        truth = 1.0 - attacker
        recommenders = _sample_recommenders(rng, provider, len(identities))
        opinions = np.empty(RECOMMENDERS, dtype=float)
        for position, recommender in enumerate(recommenders):
            base = truth
            if (
                recommender in opinion_attackers
                and _active(event_index, len(trace))
                and rng.random() < OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, OPINION_NOISE)))
        recommender_domains = np.asarray([domains[item] for item in recommenders])

        provider_lcb, provider_ucb = _bounds(book, 0, provider)
        provider_mean = float(book.mean(0, provider))
        reliability = min(1.0, max(0.0, 1.0 - message_uncertainty)) * (
            1.0 - float(provider_ucb - provider_lcb)
        )
        fusion = domain_capped_fusion(
            opinions,
            recommender_domains,
            np.asarray(book.lcb(1, recommenders)) * reliability,
        )
        value, disagreement, effective_weight, represented_domains = fusion
        alpha = 1.0 + reliability * (1.0 - malicious_probability) + provider_mean
        beta_value = 1.0 + reliability * malicious_probability + (1.0 - provider_mean)
        if represented_domains:
            opinion_weight = min(1.0, effective_weight / represented_domains) * (
                1.0 - disagreement
            )
            alpha += opinion_weight * value
            beta_value += opinion_weight * (1.0 - value)
        credibility_lcb = float(beta_distribution.ppf(LCB_QUANTILE, alpha, beta_value))
        scores.append(1.0 - credibility_lcb)
        base_reliability = min(1.0, max(0.0, 1.0 - message_uncertainty))
        pending.append(
            (
                event_index + ADJUDICATION_DELAY,
                (provider, truth, base_reliability, recommenders, opinions),
            )
        )

    levels = online_risk_levels(scores)
    selected = evenly_spaced_indices(len(scores), BLOCKS)
    return [
        {"block": block, "source_index": index, "risk_score": scores[index], "risk_level": levels[index]}
        for block, index in enumerate(selected, 1)
    ]


def _empty() -> dict[str, float]:
    return defaultdict(float)


def _record_outcome(acc, outcome, requested_size: int) -> None:
    acc["attempted"] += 1
    acc["commit"] += outcome.final_legal_eventual_commit
    acc["illegal"] += outcome.final_illegal_block_accepted
    acc["refusal"] += outcome.final_refusal
    acc["fast_success"] += int(outcome.path == "fast_certified")
    acc["fallback"] += outcome.fallback_triggered
    acc["breach"] += outcome.safety_budget_breach
    acc["fast_illegal"] += outcome.fast_illegal_proposal
    acc["protocol_messages"] += outcome.protocol_message_count
    acc["requested_size"] += requested_size
    acc["actual_size"] += outcome.committee_size


def _run_consensus_repeat(repeat: int, attack: str, seed: int, risk_stream: list[dict]) -> list[dict]:
    domains = _domains()
    latencies = _latencies()
    static = _tracker(3).candidates(domains=domains, latencies_ms=latencies)
    ranked = sorted(static, key=lambda item: (-item.honesty_lcb, item.validator_id))
    cohort_a = frozenset(item.validator_id for item in ranked[0:12])
    cohort_b = frozenset(item.validator_id for item in ranked[12:24])
    cohort_c = frozenset(item.validator_id for item in ranked[24:36])
    trackers = {
        "closed_loop_low_ablation": _v2_tracker(),
        "durac_closed_loop": _v2_tracker(),
    }
    queues = {method: defaultdict(list) for method in trackers}
    accumulators = {
        (method, level): _empty()
        for method in METHODS
        for level in ("low", "medium", "high")
    }
    compromised_activations = {method: 0 for method in trackers}
    honest_audits = {method: 0 for method in trackers}
    false_honest_audits = {method: 0 for method in trackers}

    for item in risk_stream:
        block = int(item["block"])
        level = item["risk_level"]
        compromised = _compromised(block, cohort_a, cohort_b, cohort_c)
        for method, tracker in trackers.items():
            for validator_id, success, audit_domain_name, was_compromised in queues[method].pop(block, []):
                update = tracker.update(validator_id, success, audit_domain=audit_domain_name)
                compromised_activations[method] += int(
                    update.activated and validator_id in compromised
                )
                if not was_compromised:
                    honest_audits[method] += 1
                    false_honest_audits[method] += int(success < 0.5)

        for method in METHODS:
            acc = accumulators[(method, level)]
            acc["risk_score"] += float(item["risk_score"])
            if method == "fixed_full_pbft":
                acc["attempted"] += 1
                acc["commit"] += 1
                acc["protocol_messages"] += pbft_protocol_message_count(40)
                acc["requested_size"] += 40
                acc["actual_size"] += 40
                continue
            # The committee hash key is deliberately common across methods.
            # Including the method name breaks the registered paired draw even
            # when two variants use the same pool and requested size.
            event_id = f"phase14-{repeat}-{block}"
            selection_seed = BASE_SEED + 1_400_000_000 + repeat * 10_000_000 + block * 10_000
            if method == "basic_full_hotstuff_proxy":
                leader = select_committee_leader(
                    static,
                    seed=selection_seed + 101,
                    event_id=event_id,
                    reputation_weighted=False,
                )
                view_change = int(leader.validator_id in compromised)
                acc["attempted"] += 1
                acc["commit"] += 1
                acc["protocol_messages"] += basic_hotstuff_message_count(40, failed_leader_views=view_change)
                acc["requested_size"] += 40
                acc["actual_size"] += 40
                continue

            if method == "fixed_low_certified":
                requested = 13
                pool = registered = static
            elif method == "serial_risk_adaptive":
                requested = SIZES[level]
                pool = registered = static
            else:
                tracker = trackers[method]
                requested = 13 if method == "closed_loop_low_ablation" else SIZES[level]
                registered = tracker.candidates(domains=domains, latencies_ms=latencies)
                pool = tracker.candidates(
                    domains=domains,
                    latencies_ms=latencies,
                    states={AdmissionState.ACTIVE},
                )
                acc["active_pool"] += len(pool)
            outcome = execute_certified_committee_consensus(
                pool,
                registered,
                size=requested,
                selection=CertifiedSelection.DIVERSE_UNIFORM,
                byzantine_ids=compromised,
                seed=selection_seed,
                event_id=event_id,
                leader_reputation_weighted=False,
                backup_collector_enabled=True,
            )
            _record_outcome(acc, outcome, requested)

            if method in trackers:
                targets = set(outcome.member_ids)
                tracker = trackers[method]
                targets.update(tracker.quarantined_ids)
                targets.update(tracker.probation_ids)
                if outcome.committee_size == 0:
                    targets.update(range(40))
                for validator_id in sorted(targets):
                    if _paired_uniform(
                        repeat=repeat,
                        block=block,
                        validator_id=int(validator_id),
                        stream=1,
                    ) < COVERAGE:
                        success = _audit_success(
                            repeat=repeat,
                            block=block,
                            validator_id=int(validator_id),
                            compromised=compromised,
                        )
                        acc["audits"] += 1
                        if block + DELAY <= BLOCKS:
                            queues[method][block + DELAY].append(
                                (
                                    int(validator_id),
                                    success,
                                    _audit_domain(repeat, block, int(validator_id)),
                                    int(validator_id) in compromised,
                                )
                            )

    rows = []
    for method in METHODS:
        for level in ("low", "medium", "high"):
            acc = accumulators[(method, level)]
            attempted = int(acc["attempted"])
            rows.append(
                {
                    "repeat": repeat,
                    "attack": attack,
                    "seed": seed,
                    "risk_level": level,
                    "method": method,
                    "attempted_blocks": attempted,
                    "mean_risk_score": acc["risk_score"] / attempted,
                    "final_legal_commit_rate": acc["commit"] / attempted,
                    "final_illegal_acceptance_rate": acc["illegal"] / attempted,
                    "final_refusal_rate": acc["refusal"] / attempted,
                    "fast_success_rate": acc["fast_success"] / attempted,
                    "fallback_rate": acc["fallback"] / attempted,
                    "fast_breach_rate": acc["breach"] / attempted,
                    "fast_illegal_proposal_rate": acc["fast_illegal"] / attempted,
                    "mean_requested_size": acc["requested_size"] / attempted,
                    "mean_actual_size": acc["actual_size"] / attempted,
                    "mean_active_pool": acc["active_pool"] / attempted if acc["active_pool"] else 40.0,
                    "mean_protocol_messages": acc["protocol_messages"] / attempted,
                    "mean_audits": acc["audits"] / attempted,
                    "mean_total_wire_messages": (
                        acc["protocol_messages"] + AUDIT_WIRE_MESSAGES * acc["audits"]
                    ) / attempted,
                    "compromised_activations": compromised_activations.get(method, 0),
                    "honest_audits": honest_audits.get(method, 0),
                    "false_honest_audits": false_honest_audits.get(method, 0),
                }
            )
    return rows


def _pooled(rows: list[dict], *, by_risk: bool) -> list[dict]:
    output = []
    for method in METHODS:
        levels = ("low", "medium", "high") if by_risk else ("overall",)
        for level in levels:
            subset = [
                row for row in rows
                if row["method"] == method and (level == "overall" or row["risk_level"] == level)
            ]
            total = sum(row["attempted_blocks"] for row in subset)
            item = {"method": method, **({"risk_level": level} if by_risk else {}), "attempted_blocks": total}
            for metric in (
                "mean_risk_score", "final_legal_commit_rate", "final_illegal_acceptance_rate",
                "final_refusal_rate", "fast_success_rate", "fallback_rate", "fast_breach_rate",
                "fast_illegal_proposal_rate", "mean_requested_size", "mean_actual_size",
                "mean_active_pool", "mean_protocol_messages", "mean_audits", "mean_total_wire_messages",
            ):
                item[metric] = sum(float(row[metric]) * row["attempted_blocks"] for row in subset) / total
            output.append(item)
    return output


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    predictions = _load_prediction_rows()
    prepared = {
        attack: _prepare_trace(attack, predictions[attack]) for attack in ATTACKS
    }
    risk_rows = []
    streams = []
    repeat = 0
    print("[reconstruct Phase 13 unified public-risk streams]", flush=True)
    for attack in ATTACKS:
        for seed in SEEDS:
            repeat += 1
            stream = _risk_stream(attack, seed, prepared[attack])
            if len(stream) != BLOCKS:
                raise ValueError("Phase 14 block mapping mismatch")
            for item in stream:
                risk_rows.append({"repeat": repeat, "attack": attack, "seed": seed, **item})
            streams.append((repeat, attack, seed, stream))
            counts = {level: sum(item["risk_level"] == level for item in stream) for level in SIZES}
            print(f"  risk repeat={repeat} attack={attack} seed={seed} counts={counts}", flush=True)

    print("[run paired closed-loop consensus methods]", flush=True)
    rows = []
    for repeat, attack, seed, stream in streams:
        print(f"  consensus repeat={repeat}/10 attack={attack}", flush=True)
        rows.extend(_run_consensus_repeat(repeat, attack, seed, stream))
    by_risk = _pooled(rows, by_risk=True)
    overall = _pooled(rows, by_risk=False)
    oi = {row["method"]: row for row in overall}
    ri = {(row["method"], row["risk_level"]): row for row in by_risk}

    closed = oi["durac_closed_loop"]
    serial = oi["serial_risk_adaptive"]
    low_ablation_high = ri[("closed_loop_low_ablation", "high")]
    closed_high = ri[("durac_closed_loop", "high")]
    fallback_reduction = 1.0 - closed["fallback_rate"] / serial["fallback_rate"]
    wire_reduction = 1.0 - closed["mean_total_wire_messages"] / serial["mean_total_wire_messages"]
    high_breach_reduction = 1.0 - closed_high["fast_breach_rate"] / low_ablation_high["fast_breach_rate"]
    pbft_wire_reduction = 1.0 - closed["mean_total_wire_messages"] / oi["fixed_full_pbft"]["mean_total_wire_messages"]
    total_honest_audits = sum(row["honest_audits"] for row in rows if row["method"] == "durac_closed_loop")
    total_false_honest = sum(row["false_honest_audits"] for row in rows if row["method"] == "durac_closed_loop")
    false_audit_rate = total_false_honest / total_honest_audits
    compromised_activations = max(row["compromised_activations"] for row in rows)
    raw_index = {
        (row["repeat"], row["risk_level"], row["method"]): row for row in rows
    }
    paired_static_low_mismatches = 0
    for repeat in range(1, 11):
        fixed = raw_index[(repeat, "low", "fixed_low_certified")]
        serial_low = raw_index[(repeat, "low", "serial_risk_adaptive")]
        for metric in (
            "final_legal_commit_rate",
            "final_illegal_acceptance_rate",
            "fallback_rate",
            "fast_breach_rate",
            "mean_protocol_messages",
        ):
            paired_static_low_mismatches += int(fixed[metric] != serial_low[metric])
    categories_present = all(
        any(row["attack"] == attack and row["risk_level"] == level for row in risk_rows)
        for attack in ATTACKS for level in SIZES
    )
    stop = {
        "integrity_alignment_accounting_pass": int(paired_static_low_mismatches == 0),
        "closed_loop_safety_liveness_pass": int(
            closed["final_illegal_acceptance_rate"] == 0.0
            and closed["final_legal_commit_rate"] >= 0.99
            and closed["final_refusal_rate"] <= 0.01
        ),
        "closed_loop_vs_serial_fallback_pass": int(fallback_reduction >= 0.15),
        "closed_loop_vs_serial_wire_pass": int(wire_reduction >= 0.15),
        "high_risk_breach_reduction_pass": int(high_breach_reduction >= 0.15),
        "risk_mapping_and_coverage_pass": int(
            categories_present
            and all(abs(ri[("serial_risk_adaptive", level)]["mean_requested_size"] - SIZES[level]) < 1e-12 for level in SIZES)
        ),
        "closed_loop_vs_full_pbft_wire_pass": int(pbft_wire_reduction >= 0.15),
        "audit_and_reactivation_pass": int(false_audit_rate <= ERROR_RATE and compromised_activations == 0),
    }
    stop["all_phase14_stop_lines_pass"] = int(all(stop.values()))
    diagnostics = [{
        "fallback_reduction_vs_serial": fallback_reduction,
        "wire_reduction_vs_serial": wire_reduction,
        "high_risk_breach_reduction_vs_low_ablation": high_breach_reduction,
        "wire_reduction_vs_full_pbft": pbft_wire_reduction,
        "honest_audit_false_rate": false_audit_rate,
        "compromised_activations": compromised_activations,
        "paired_static_low_mismatches": paired_static_low_mismatches,
    }]

    _write_csv(OUTPUT_DIR / "DURAC_phase14_risk_stream.csv", risk_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase14_repeat_risk.csv", rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase14_by_risk.csv", by_risk)
    _write_csv(OUTPUT_DIR / "DURAC_phase14_overall.csv", overall)
    _write_csv(OUTPUT_DIR / "DURAC_phase14_diagnostics.csv", diagnostics)
    _write_csv(OUTPUT_DIR / "DURAC_phase14_stop_lines.csv", [stop])
    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "amendment_sha256": _digest(Path("SEARPC_AMENDMENT_1.md")),
        "phase13_predictions_sha256": _digest(PREDICTIONS),
        "blocks_per_repeat": BLOCKS,
        "repeats": 10,
        "outputs": {path.name: _digest(path) for path in sorted(OUTPUT_DIR.glob("*.csv"))},
    }
    (OUTPUT_DIR / "DURAC_phase14_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print("===== DURAC PHASE 14 CLOSED LOOP =====")
    for row in overall:
        print(
            f"{row['method']:29s} commit={row['final_legal_commit_rate']:.3%} "
            f"fallback={row['fallback_rate']:.3%} breach={row['fast_breach_rate']:.3%} "
            f"wire={row['mean_total_wire_messages']:.2f}"
        )
    print(json.dumps(diagnostics[0], indent=2, sort_keys=True))
    print(json.dumps(stop, indent=2, sort_keys=True))


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Phase 14 closed-loop source simulation (requires bundled Phase-13 trace and restored helper modules).')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
