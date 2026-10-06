#!/usr/bin/env python3
"""Run the preregistered conditional trust conditional-role and cold-start holdout."""

from __future__ import annotations

import argparse
from collections import deque
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import random
from statistics import mean, stdev

import numpy as np

from durac import message_evidence_metrics, select_fpr_constrained_threshold
from authority import apply_malicious_authority_gate
from run_temporal_evaluation import _calibrate, _fit_ensemble
from run_context_evaluation import _load as _load_phase9
from run_dual_role import (
    ADJUDICATION_DELAY,
    OPINION_ATTACK_PROBABILITY,
    OPINION_NOISE,
    OVERLAPS,
    RECOMMENDERS,
    SEEDS,
    _ArrayBook,
    _active,
    _domain,
    _event_is_false,
    _sample_recommenders,
    _weighted_median,
    domain_capped_fusion,
    select_opinion_attackers,
)
from run_holdout_authorization import (
    ATTACKS as DEVELOPMENT_ATTACKS,
    DEVELOPMENT_ROOT,
    SAMPLE_STRIDE,
    _DynamicStates,
    _bounds,
    _event_metrics,
    _load_holdout,
    _observe_actions,
    _rates,
    _trusted,
    run_cell as run_uniform_phase12_cell,
)


COLD_JOIN_FRACTION = 0.55
COLD_RECOMMENDERS = 6
WARM_RECOMMENDERS = RECOMMENDERS - COLD_RECOMMENDERS
ROLE_OVERLAP_COLD = 0.5
VARIANTS_COLD = ("dual_role_mean_weight", "dual_role_lcb_weight")

SCRATCH_ROOT = Path(__file__).resolve().parents[4]
HOLDOUT_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase13"
NESTED_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase13_nested"
OUTPUT_DIR = Path("results/durac_phase13_conditional_trust")
PROTOCOL = Path("SEARPC_CONDITIONAL_TRUST_PROTOCOL.md")

ATTACKS = {
    "dataReplay": {
        "holdout_folder": "InTAS_urban_2_dataReplay",
        "nested_folder": "dataReplay",
        "nested_md5": "3ad535432d81b1e3913ee19e6cd26d67",
        "nested_sha256": "2e46d7231012cdd2bc45cc003727696c343952e3006ee02e55913cca4d6d3b47",
    },
    "timeDelayAttack": {
        "holdout_folder": "InTAS_urban_2_timeDelayAttack",
        "nested_folder": "timeDelayAttack",
        "nested_md5": "d67e1db0989aeab1dbb3cc5c8f3e1d88",
        "nested_sha256": "f96649235e8efe72ee2d2cdf4234dbdae819275eb7665d4c6dfd56144b6f6c1c",
    },
}


def _digest(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _summaries(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault(tuple(row[key] for key in keys), []).append(row)
    excluded = set(keys) | {"seed", "messages", "identities", "data_attackers", "opinion_attackers"}
    metrics = [key for key in rows[0] if key not in excluded]
    output = []
    for group, members in sorted(groups.items()):
        item = {key: value for key, value in zip(keys, group)}
        item["repeats"] = len(members)
        for metric in metrics:
            samples = [float(member[metric]) for member in members]
            finite = [value for value in samples if math.isfinite(value)]
            item[f"{metric}_mean"] = mean(finite) if finite else math.nan
            item[f"{metric}_sd"] = stdev(finite) if len(finite) > 1 else 0.0
        output.append(item)
    return output


def select_cold_cohort(
    opinion_attackers: frozenset[int], identities: int, seed: int
) -> frozenset[int]:
    """Pair every cold attacker with one deterministic cold honest identity."""
    honest = sorted(set(range(identities)) - set(opinion_attackers))
    if len(honest) < len(opinion_attackers):
        raise ValueError("insufficient honest identities for matched cold cohort")
    rng = random.Random(seed * 1_000_033 + 130013)
    matched_honest = rng.sample(honest, len(opinion_attackers))
    return frozenset(set(opinion_attackers) | set(matched_honest))


def sample_cold_start_recommenders(
    rng: random.Random,
    provider: int,
    identities: int,
    cold_cohort: frozenset[int],
    admitted: bool,
) -> np.ndarray:
    cold = sorted(set(cold_cohort) - {provider})
    warm = sorted(set(range(identities)) - set(cold_cohort) - {provider})
    if not admitted:
        if len(warm) < RECOMMENDERS:
            raise ValueError("insufficient warm recommenders")
        return np.asarray(rng.sample(warm, RECOMMENDERS), dtype=int)
    if len(cold) < COLD_RECOMMENDERS or len(warm) < WARM_RECOMMENDERS:
        raise ValueError("insufficient stratified cold-start recommenders")
    selected = rng.sample(cold, COLD_RECOMMENDERS) + rng.sample(warm, WARM_RECOMMENDERS)
    rng.shuffle(selected)
    return np.asarray(selected, dtype=int)


def effective_adversarial_weight(
    values: np.ndarray,
    domains: np.ndarray,
    weights: np.ndarray,
    truth: float,
) -> tuple[float, float]:
    """Return adversarial and total weights after administrative-domain caps."""
    adversarial = 0.0
    total = 0.0
    for domain in sorted(set(int(value) for value in domains)):
        mask = domains == domain
        pairs = [
            (float(value), float(weight))
            for value, weight in zip(values[mask], weights[mask])
            if weight > 0.0
        ]
        if not pairs:
            continue
        domain_value = _weighted_median(pairs)
        domain_weight = max(weight for _, weight in pairs)
        total += domain_weight
        if abs(domain_value - (1.0 - truth)) < abs(domain_value - truth):
            adversarial += domain_weight
    return adversarial, total


def _apply_dual_pending(book: _ArrayBook, states: _DynamicStates, item) -> None:
    provider, truth, reliability, recommenders, opinions = item
    provider_index = np.asarray([provider], dtype=int)
    provider_truth = np.asarray([truth], dtype=float)
    book.update(0, provider_index, provider_truth, np.asarray([reliability]))
    states.observe(0, provider_index, provider_truth)
    honesty = 1.0 - np.abs(opinions - truth)
    book.update(1, recommenders, honesty)
    states.observe(1, recommenders, honesty)


def run_cold_cell(attack, trace, data_attackers, domains, seed):
    identities = len(domains)
    opinion_attackers = select_opinion_attackers(
        frozenset(data_attackers), identities, ROLE_OVERLAP_COLD, seed
    )
    cold_cohort = select_cold_cohort(opinion_attackers, identities, seed)
    rng = random.Random(seed * 1_000_003 + 130013)
    book = _ArrayBook(identities, 2)
    states = _DynamicStates(2, identities)
    pending = deque()
    actual_false: set[int] = set()
    predicted_false = {variant: set() for variant in VARIANTS_COLD}
    accumulators = {
        variant: {
            "adversarial_effective_weight": 0.0,
            "total_effective_weight": 0.0,
            "raw_inverted_weight": 0.0,
            "raw_total_weight": 0.0,
            "cold_malicious_weight": 0.0,
            "cold_malicious_count": 0,
            "cold_honest_weight": 0.0,
            "cold_honest_count": 0,
        }
        for variant in VARIANTS_COLD
    }
    join_index = math.ceil(COLD_JOIN_FRACTION * len(trace))

    for event_index, (provider, attacker, malicious_probability, message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            _apply_dual_pending(book, states, item)

        truth = 1.0 - attacker
        if attacker:
            actual_false.add(event_index)
        admitted = event_index >= join_index
        recommenders = sample_cold_start_recommenders(
            rng, provider, identities, cold_cohort, admitted
        )
        opinions = np.empty(RECOMMENDERS, dtype=float)
        inverted = np.zeros(RECOMMENDERS, dtype=bool)
        for position, recommender in enumerate(recommenders):
            base = truth
            if (
                recommender in opinion_attackers
                and _active(event_index, len(trace))
                and rng.random() < OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
                inverted[position] = True
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, OPINION_NOISE)))
        recommender_domains = np.asarray([domains[item] for item in recommenders])

        provider_lcb, provider_ucb = _bounds(book, 0, provider)
        reliability = min(1.0, max(0.0, 1.0 - message_uncertainty)) * (
            1.0 - float(provider_ucb - provider_lcb)
        )
        malicious_mask = states.malicious[1, recommenders]
        weights_by_variant = {
            # Both weighting ablations share the same executable three-state
            # authorization; only mean versus LCB influence differs.
            "dual_role_mean_weight": apply_malicious_authority_gate(
                np.asarray(book.mean(1, recommenders)) * reliability, malicious_mask
            ),
            "dual_role_lcb_weight": apply_malicious_authority_gate(
                np.asarray(book.lcb(1, recommenders)) * reliability, malicious_mask
            ),
        }
        credibility_probability = 1.0 - malicious_probability
        provider_mean = float(book.mean(0, provider))
        measure_influence = admitted and _active(event_index, len(trace))
        for variant, weights in weights_by_variant.items():
            fusion = domain_capped_fusion(opinions, recommender_domains, weights)
            if _event_is_false(credibility_probability, reliability, provider_mean, fusion):
                predicted_false[variant].add(event_index)
            if measure_influence:
                adverse, effective_total = effective_adversarial_weight(
                    opinions, recommender_domains, weights, truth
                )
                accumulator = accumulators[variant]
                accumulator["adversarial_effective_weight"] += adverse
                accumulator["total_effective_weight"] += effective_total
                accumulator["raw_inverted_weight"] += float(np.sum(weights[inverted]))
                accumulator["raw_total_weight"] += float(np.sum(weights))
                cold_mask = np.asarray([item in cold_cohort for item in recommenders])
                malicious_cold = cold_mask & np.asarray(
                    [item in opinion_attackers for item in recommenders]
                )
                honest_cold = cold_mask & ~malicious_cold
                accumulator["cold_malicious_weight"] += float(np.sum(weights[malicious_cold]))
                accumulator["cold_malicious_count"] += int(np.sum(malicious_cold))
                accumulator["cold_honest_weight"] += float(np.sum(weights[honest_cold]))
                accumulator["cold_honest_count"] += int(np.sum(honest_cold))

        base_reliability = min(1.0, max(0.0, 1.0 - message_uncertainty))
        pending.append(
            (
                event_index + ADJUDICATION_DELAY,
                (provider, truth, base_reliability, recommenders, opinions),
            )
        )

    rows = []
    for variant in VARIANTS_COLD:
        accumulator = accumulators[variant]
        rows.append(
            {
                "attack": attack,
                "seed": seed,
                "variant": variant,
                "adversarial_effective_weight_share": accumulator["adversarial_effective_weight"]
                / accumulator["total_effective_weight"],
                "raw_inverted_weight_share": accumulator["raw_inverted_weight"]
                / accumulator["raw_total_weight"],
                "cold_malicious_mean_weight": accumulator["cold_malicious_weight"]
                / accumulator["cold_malicious_count"],
                "cold_honest_mean_weight": accumulator["cold_honest_weight"]
                / accumulator["cold_honest_count"],
                **_event_metrics(actual_false, predicted_false[variant], len(trace)),
                "messages": len(trace),
                "identities": identities,
                "data_attackers": len(data_attackers),
                "opinion_attackers": len(opinion_attackers),
                "cold_identities": len(cold_cohort),
                "join_index": join_index,
            }
        )
    return rows


def _uniform_comparisons(rows: list[dict]) -> list[dict]:
    indexed = {
        (row["attack"], row["overlap"], row["seed"], row["variant"]): row
        for row in rows
    }
    output = []
    for attack in ATTACKS:
        for overlap in OVERLAPS:
            metrics = {
                "opinion_trusted_relative_reduction": [],
                "opinion_honest_denied_delta": [],
                "opinion_state_fpr_delta": [],
                "event_macro_f1_delta": [],
            }
            for seed in SEEDS:
                single = indexed[(attack, overlap, seed, "single_role_three_state")]
                dual = indexed[(attack, overlap, seed, "dual_role_three_state")]
                single_rate = single["opinion_malicious_trusted_rate"]
                dual_rate = dual["opinion_malicious_trusted_rate"]
                metrics["opinion_trusted_relative_reduction"].append(
                    (single_rate - dual_rate) / single_rate if single_rate else float(dual_rate == 0)
                )
                metrics["opinion_honest_denied_delta"].append(
                    dual["opinion_honest_denied_rate"] - single["opinion_honest_denied_rate"]
                )
                metrics["opinion_state_fpr_delta"].append(
                    dual["opinion_malicious_state_fpr"] - single["opinion_malicious_state_fpr"]
                )
                metrics["event_macro_f1_delta"].append(
                    dual["event_macro_f1"] - single["event_macro_f1"]
                )
            item = {"attack": attack, "overlap": overlap}
            for metric, samples in metrics.items():
                item[f"{metric}_mean"] = mean(samples)
                item[f"{metric}_sd"] = stdev(samples)
            output.append(item)
    return output


def _cold_comparisons(rows: list[dict]) -> list[dict]:
    indexed = {(row["attack"], row["seed"], row["variant"]): row for row in rows}
    output = []
    for attack in ATTACKS:
        metrics = {
            "effective_adversarial_relative_reduction": [],
            "raw_inverted_relative_reduction": [],
            "event_macro_f1_delta": [],
            "event_fpr_delta": [],
        }
        for seed in SEEDS:
            baseline = indexed[(attack, seed, "dual_role_mean_weight")]
            lcb = indexed[(attack, seed, "dual_role_lcb_weight")]
            for source, target in (
                ("adversarial_effective_weight_share", "effective_adversarial_relative_reduction"),
                ("raw_inverted_weight_share", "raw_inverted_relative_reduction"),
            ):
                base = baseline[source]
                metrics[target].append((base - lcb[source]) / base if base else float(lcb[source] == 0))
            metrics["event_macro_f1_delta"].append(lcb["event_macro_f1"] - baseline["event_macro_f1"])
            metrics["event_fpr_delta"].append(lcb["event_fpr"] - baseline["event_fpr"])
        item = {"attack": attack}
        for metric, samples in metrics.items():
            item[f"{metric}_mean"] = mean(samples)
            item[f"{metric}_sd"] = stdev(samples)
        output.append(item)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=min(10, os.cpu_count() or 4))
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    integrity_rows = []
    for attack, definition in ATTACKS.items():
        nested = (
            NESTED_ROOT
            / definition["nested_folder"]
            / f"{definition['holdout_folder']}.zip"
        )
        md5 = _digest(nested, "md5")
        sha256 = _digest(nested)
        if md5 != definition["nested_md5"] or sha256 != definition["nested_sha256"]:
            raise ValueError(f"nested Phase 13 holdout archive mismatch for {attack}")
        integrity_rows.append({"attack": attack, "md5": md5, "sha256": sha256, "pass": 1})

    print("[load frozen highway development and untouched urban Train]", flush=True)
    development = {"Train": {}, "Validation": {}}
    audit_rows = []
    for split in development:
        for attack, definition in DEVELOPMENT_ATTACKS.items():
            root = DEVELOPMENT_ROOT / definition["development_folder"] / split / "json"
            _, contextual, labels, audit = _load_phase9(root)
            development[split][attack] = (contextual, labels)
            audit_rows.append(
                {"split": f"highway_{split.lower()}", "attack": attack, "messages": len(labels),
                 "attack_messages": int(np.sum(labels)), "identities": audit.sender_ids}
            )

    holdout = {}
    holdout_senders = {}
    for attack, definition in ATTACKS.items():
        root = HOLDOUT_ROOT / definition["holdout_folder"] / "Train" / "json"
        matrix, labels, senders = _load_holdout(root)
        holdout[attack] = (matrix, labels)
        holdout_senders[attack] = senders
        audit_rows.append(
            {"split": "urban_train_holdout", "attack": attack, "messages": len(labels),
             "attack_messages": int(np.sum(labels)), "identities": len(set(senders))}
        )

    x_train = np.concatenate([development["Train"][attack][0] for attack in ATTACKS])
    y_train = np.concatenate([development["Train"][attack][1] for attack in ATTACKS])
    x_validation = np.concatenate([development["Validation"][attack][0] for attack in ATTACKS])
    y_validation = np.concatenate([development["Validation"][attack][1] for attack in ATTACKS])
    x_holdout = np.concatenate([holdout[attack][0] for attack in ATTACKS])

    print("[fit unchanged contextual ensemble and highway-only calibration]", flush=True)
    raw_validation, raw_holdout, _, uncertainty_holdout = _fit_ensemble(
        x_train, y_train, x_validation, x_holdout, 3000
    )
    calibration, calibrated_validation, calibrated_holdout, calibration_rows = _calibrate(
        raw_validation, raw_holdout, y_validation
    )
    threshold = select_fpr_constrained_threshold(y_validation, calibrated_validation, maximum_fpr=0.05)

    evidence_rows = []
    prediction_rows = []
    traces = {}
    start = 0
    for attack in ATTACKS:
        labels = holdout[attack][1]
        stop = start + len(labels)
        probabilities = calibrated_holdout[start:stop]
        uncertainties = uncertainty_holdout[start:stop]
        evidence_rows.append(
            {"attack": attack, "calibration": calibration, "threshold": threshold,
             **asdict(message_evidence_metrics(labels, probabilities, threshold=threshold))}
        )
        senders = holdout_senders[attack]
        identities = tuple(sorted(set(senders)))
        identity_index = {identity: index for index, identity in enumerate(identities)}
        data_attackers = {
            identity_index[sender] for sender, label in zip(senders, labels) if label
        }
        trace = []
        for index, (sender, label, probability, uncertainty) in enumerate(
            zip(senders, labels, probabilities, uncertainties)
        ):
            prediction_rows.append(
                {"attack": attack, "holdout_row": index, "attacker": int(label),
                 "contextual_probability": float(probability),
                 "contextual_uncertainty": float(uncertainty)}
            )
            if index % SAMPLE_STRIDE == 0:
                trace.append((identity_index[sender], int(label), float(probability), float(uncertainty)))
        domains = tuple(_domain(identity) for identity in identities)
        traces[attack] = (tuple(trace), frozenset(data_attackers), domains)
        start = stop

    print("[run paired uniform-role and cold-start cells]", flush=True)
    uniform_rows = []
    cold_rows = []
    futures = {}
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for attack, (trace, data_attackers, domains) in traces.items():
            for overlap in OVERLAPS:
                for seed in SEEDS:
                    future = executor.submit(
                        run_uniform_phase12_cell, attack, trace, data_attackers, domains, overlap, seed
                    )
                    futures[future] = "uniform"
            for seed in SEEDS:
                future = executor.submit(run_cold_cell, attack, trace, data_attackers, domains, seed)
                futures[future] = "cold"
        for index, future in enumerate(as_completed(futures), 1):
            kind = futures[future]
            result = future.result()
            if kind == "uniform":
                uniform_rows.extend(
                    row for row in result
                    if row["variant"] in ("single_role_three_state", "dual_role_three_state")
                )
            else:
                cold_rows.extend(result)
            print(f"  completed {index}/{len(futures)} cells", flush=True)

    uniform_rows.sort(key=lambda row: (row["attack"], row["overlap"], row["seed"], row["variant"]))
    cold_rows.sort(key=lambda row: (row["attack"], row["seed"], row["variant"]))
    uniform_summary = _summaries(uniform_rows, ("attack", "overlap", "variant"))
    cold_summary = _summaries(cold_rows, ("attack", "variant"))
    uniform_comparison = _uniform_comparisons(uniform_rows)
    cold_comparison = _cold_comparisons(cold_rows)
    us = {(row["attack"], row["overlap"], row["variant"]): row for row in uniform_summary}
    uc = {(row["attack"], row["overlap"]): row for row in uniform_comparison}
    cc = {row["attack"]: row for row in cold_comparison}

    stop_lines = {
        "integrity_alignment_accounting_pass": 1,
        "overlap_0_role_reduction_pass": int(all(
            uc[(attack, 0.0)]["opinion_trusted_relative_reduction_mean"] >= 0.20 for attack in ATTACKS
        )),
        "overlap_05_direction_and_safety_pass": int(all(
            uc[(attack, 0.5)]["opinion_trusted_relative_reduction_mean"] > 0.0
            and us[(attack, 0.5, "dual_role_three_state")]["opinion_malicious_trusted_rate_mean"] <= 0.05
            for attack in ATTACKS
        )),
        "overlap_1_absolute_noninferiority_pass": int(all(
            us[(attack, 1.0, "dual_role_three_state")]["opinion_malicious_trusted_rate_mean"]
            <= us[(attack, 1.0, "single_role_three_state")]["opinion_malicious_trusted_rate_mean"] + 0.05
            for attack in ATTACKS
        )),
        "role_safety_utility_pass": int(all(
            us[(attack, overlap, "dual_role_three_state")]["opinion_malicious_state_fpr_mean"] <= 0.05
            and uc[(attack, overlap)]["opinion_honest_denied_delta_mean"] <= 0.05
            and uc[(attack, overlap)]["event_macro_f1_delta_mean"] >= -0.02
            for attack in ATTACKS for overlap in OVERLAPS
        )),
        "lcb_effective_influence_pass": int(all(
            cc[attack]["effective_adversarial_relative_reduction_mean"] >= 0.20 for attack in ATTACKS
        )),
        "lcb_raw_influence_pass": int(all(
            cc[attack]["raw_inverted_relative_reduction_mean"] > 0.0 for attack in ATTACKS
        )),
        "lcb_event_noninferiority_pass": int(all(
            cc[attack]["event_macro_f1_delta_mean"] >= -0.02
            and cc[attack]["event_fpr_delta_mean"] <= 0.01
            for attack in ATTACKS
        )),
    }
    stop_lines["all_phase13_stop_lines_pass"] = int(all(stop_lines.values()))

    _write_csv(OUTPUT_DIR / "SEARPC_holdout_integrity.csv", integrity_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_audit.csv", audit_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_calibration.csv", calibration_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_message_metrics.csv", evidence_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_holdout_predictions.csv", prediction_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_uniform_raw.csv", uniform_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_uniform_summary.csv", uniform_summary)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_uniform_comparison.csv", uniform_comparison)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_cold_raw.csv", cold_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_cold_summary.csv", cold_summary)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_cold_comparison.csv", cold_comparison)
    _write_csv(OUTPUT_DIR / "SEARPC_holdout_stop_lines.csv", [stop_lines])
    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "seeds": SEEDS,
        "sample_stride": SAMPLE_STRIDE,
        "threshold": threshold,
        "calibration": calibration,
        "outputs": {path.name: _digest(path) for path in sorted(OUTPUT_DIR.glob("*.csv"))},
    }
    with (OUTPUT_DIR / "SEARPC_holdout_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    print("===== DURAC PHASE 13 CONDITIONAL TRUST =====")
    for row in uniform_comparison:
        print(
            f"uniform {row['attack']:18s} overlap={row['overlap']:.1f} "
            f"auth_reduction={row['opinion_trusted_relative_reduction_mean']:+.4f} "
            f"macro_delta={row['event_macro_f1_delta_mean']:+.4f}"
        )
    for row in cold_comparison:
        print(
            f"cold    {row['attack']:18s} effective_reduction="
            f"{row['effective_adversarial_relative_reduction_mean']:+.4f} "
            f"raw_reduction={row['raw_inverted_relative_reduction_mean']:+.4f} "
            f"macro_delta={row['event_macro_f1_delta_mean']:+.4f}"
        )
    print(json.dumps(stop_lines, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

