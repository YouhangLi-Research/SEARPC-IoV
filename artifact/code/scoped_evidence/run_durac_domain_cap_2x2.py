#!/usr/bin/env python3
"""Run the frozen DURAC opinion-fusion LCB × Domain Cap 2×2 experiment."""

from __future__ import annotations

import argparse
from collections import deque
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import random
from statistics import mean, stdev
from typing import Sequence

import numpy as np

from authority import apply_malicious_authority_gate
from adjudication import perturb_binary_truth
from run_holdout_authorization import _DynamicStates
from run_dual_role import (
    LCB_QUANTILE,
    OPINION_ATTACK_PROBABILITY,
    OPINION_NOISE,
    RECOMMENDERS,
    _ArrayBook,
    _event_is_false,
    _weighted_median,
    domain_capped_fusion,
)
from run_holdout_authorization import ADJUDICATION_DELAY, SAMPLE_STRIDE, _event_metrics


INPUT_PATH = Path(
    "results/durac_phase13_conditional_trust/SEARPC_holdout_holdout_predictions.csv"
)
INPUT_SHA256 = "58a93ef9159a7a090654c8b3adc4ffb5eeaabd7f895049e32c4911ec5c82b915"
PROTOCOL_PATH = Path("DURAC_DOMAIN_CAP_2X2_PROTOCOL.md")
AMENDMENT_PATH = Path("DURAC_DOMAIN_CAP_2X2_AMENDMENT_1.md")
OUTPUT_DIR = Path("results/durac_domain_cap_2x2")
ATTACKS = ("dataReplay", "timeDelayAttack")
EXPECTED_ROWS_PER_ATTACK = 291_050
EXPECTED_EVENTS_PER_ATTACK = 36_382
SEEDS = tuple(range(260825, 260830))
MULTIPLICITIES = (1, 3, 5, 7)
LAYOUTS = ("concentrated", "distributed_control")
VARIANTS = ("mean_no_cap", "lcb_no_cap", "mean_cap", "lcb_cap")
JOIN_FRACTION = 0.55
ATTACK_STOP_FRACTION = 0.85
DOMAINS = 8


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def load_traces(path: Path = INPUT_PATH) -> dict[str, tuple[tuple[int, float, float], ...]]:
    if digest(path) != INPUT_SHA256:
        raise ValueError("frozen Phase 13 prediction hash mismatch")
    grouped: dict[str, list[tuple[int, int, float, float]]] = {attack: [] for attack in ATTACKS}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        expected = {
            "attack",
            "holdout_row",
            "attacker",
            "contextual_probability",
            "contextual_uncertainty",
        }
        if set(reader.fieldnames or ()) != expected:
            raise ValueError("unexpected frozen prediction columns")
        for row in reader:
            attack = row["attack"]
            if attack not in grouped:
                raise ValueError(f"unexpected attack {attack}")
            grouped[attack].append(
                (
                    int(row["holdout_row"]),
                    int(row["attacker"]),
                    float(row["contextual_probability"]),
                    float(row["contextual_uncertainty"]),
                )
            )

    traces = {}
    for attack in ATTACKS:
        rows = grouped[attack]
        if len(rows) != EXPECTED_ROWS_PER_ATTACK:
            raise ValueError(f"{attack} row accounting mismatch")
        if [item[0] for item in rows] != list(range(EXPECTED_ROWS_PER_ATTACK)):
            raise ValueError(f"{attack} row order/alignment mismatch")
        trace = tuple((label, probability, uncertainty) for index, label, probability, uncertainty in rows if index % SAMPLE_STRIDE == 0)
        if len(trace) != EXPECTED_EVENTS_PER_ATTACK:
            raise ValueError(f"{attack} sampled event accounting mismatch")
        traces[attack] = trace
    return traces


def domain_layout(multiplicity: int, layout: str) -> tuple[np.ndarray, np.ndarray]:
    """Return domains for nine warm identities and `multiplicity` attackers."""
    if multiplicity not in MULTIPLICITIES:
        raise ValueError("unregistered multiplicity")
    if layout not in LAYOUTS:
        raise ValueError("unregistered domain layout")
    if layout == "concentrated":
        attacker_domains = np.zeros(multiplicity, dtype=int)
        warm_domains = np.asarray([1 + (index % (DOMAINS - 1)) for index in range(RECOMMENDERS)])
    else:
        attacker_domains = np.asarray([index % DOMAINS for index in range(multiplicity)])
        unused = [domain for domain in range(DOMAINS) if domain not in set(attacker_domains)]
        choices = unused if unused else list(range(DOMAINS))
        warm_domains = np.asarray([choices[index % len(choices)] for index in range(RECOMMENDERS)])
    return warm_domains, attacker_domains


def individual_fusion(
    values: np.ndarray, domains: np.ndarray, weights: np.ndarray
) -> tuple[float, float, float, int]:
    pairs = [
        (float(value), float(weight))
        for value, weight in zip(values, weights)
        if weight > 0.0
    ]
    if not pairs:
        return 0.5, 1.0, 0.0, 0
    fused = _weighted_median(pairs)
    total = sum(weight for _, weight in pairs)
    disagreement = sum(weight * abs(value - fused) for value, weight in pairs) / total
    return fused, disagreement, total, len(set(int(value) for value in domains))


def domain_influence(
    values: np.ndarray,
    domains: np.ndarray,
    weights: np.ndarray,
    truth: float,
    *,
    capped: bool,
) -> tuple[float, float, float, float]:
    """Return adverse, total, max adverse-domain, and strongest adverse member weights."""
    adverse = 0.0
    total = 0.0
    max_adverse_domain = 0.0
    strongest_adverse_member = 0.0
    for domain in sorted(set(int(item) for item in domains)):
        mask = domains == domain
        pairs = [
            (float(value), float(weight))
            for value, weight in zip(values[mask], weights[mask])
            if weight > 0.0
        ]
        if not pairs:
            continue
        domain_value = _weighted_median(pairs)
        domain_weight = max(weight for _, weight in pairs) if capped else sum(weight for _, weight in pairs)
        total += domain_weight
        is_adverse = abs(domain_value - (1.0 - truth)) < abs(domain_value - truth)
        if is_adverse:
            adverse += domain_weight
            max_adverse_domain = max(max_adverse_domain, domain_weight)
            strongest_adverse_member = max(
                strongest_adverse_member, max(weight for _, weight in pairs)
            )
    return adverse, total, max_adverse_domain, strongest_adverse_member


def _new_accumulator() -> dict[str, float | int]:
    return {
        "early_adverse": 0.0,
        "early_total": 0.0,
        "early_max_adverse_domain": 0.0,
        "early_fusion_errors": 0,
        "early_events": 0,
        "window_adverse": 0.0,
        "window_total": 0.0,
        "window_max_adverse_domain": 0.0,
        "window_fusion_errors": 0,
        "window_events": 0,
        "cap_bound_violations": 0,
    }


def run_cell(
    attack: str,
    trace: Sequence[tuple[int, float, float]],
    layout: str,
    multiplicity: int,
    seed: int,
    adjudication_delay: int = ADJUDICATION_DELAY,
    adjudication_error: float = 0.0,
) -> list[dict]:
    warm_domains, attacker_domains = domain_layout(multiplicity, layout)
    attacker_ids = np.arange(RECOMMENDERS, RECOMMENDERS + multiplicity, dtype=int)
    post_join_warm = np.arange(RECOMMENDERS - multiplicity, dtype=int)
    post_join_ids = np.concatenate((post_join_warm, attacker_ids))
    all_domains = np.concatenate((warm_domains, attacker_domains))
    book = _ArrayBook(RECOMMENDERS + multiplicity, 1)
    states = _DynamicStates(1, RECOMMENDERS + multiplicity)
    pending: deque[tuple[int, np.ndarray, np.ndarray]] = deque()
    attack_offset = 0 if attack == "dataReplay" else 10_000_019
    layout_offset = 0 if layout == "concentrated" else 20_000_033
    rng = random.Random(seed * 1_000_003 + attack_offset + layout_offset + multiplicity * 1009)
    join_index = math.ceil(JOIN_FRACTION * len(trace))
    attack_stop = math.ceil(ATTACK_STOP_FRACTION * len(trace))
    early_stop = join_index + adjudication_delay
    predicted_false = {variant: set() for variant in VARIANTS}
    actual_false: set[int] = set()
    accumulators = {variant: _new_accumulator() for variant in VARIANTS}

    for event_index, (attacker, malicious_probability, uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, ids, honesty = pending.popleft()
            book.update(0, ids, honesty)
            states.observe(0, ids, honesty)

        truth = 1.0 - attacker
        if attacker:
            actual_false.add(event_index)
        joined = event_index >= join_index
        recommender_ids = post_join_ids if joined else np.arange(RECOMMENDERS, dtype=int)
        domains = all_domains[recommender_ids]
        opinions = np.empty(RECOMMENDERS, dtype=float)
        for position, recommender in enumerate(recommender_ids):
            is_malicious = recommender >= RECOMMENDERS
            base = truth
            if (
                is_malicious
                and join_index <= event_index < attack_stop
                and rng.random() < OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, OPINION_NOISE)))

        reliability = min(1.0, max(0.0, 1.0 - uncertainty))
        malicious_mask = states.malicious[0, recommender_ids]
        weights_by_rule = {
            # Authorization is shared across the 2x2 factorial; only the
            # registered weight and domain-cap switches differ.
            "mean": apply_malicious_authority_gate(
                np.asarray(book.mean(0, recommender_ids), dtype=float) * reliability,
                malicious_mask,
            ),
            "lcb": apply_malicious_authority_gate(
                np.asarray(book.lcb(0, recommender_ids), dtype=float) * reliability,
                malicious_mask,
            ),
        }
        for variant in VARIANTS:
            weighting = "lcb" if variant.startswith("lcb") else "mean"
            capped = variant.endswith("cap") and not variant.endswith("no_cap")
            weights = weights_by_rule[weighting]
            fusion = (
                domain_capped_fusion(opinions, domains, weights)
                if capped
                else individual_fusion(opinions, domains, weights)
            )
            if _event_is_false(
                1.0 - malicious_probability, reliability, 0.5, fusion
            ):
                predicted_false[variant].add(event_index)

            if join_index <= event_index < attack_stop:
                adverse, total, max_domain, strongest_member = domain_influence(
                    opinions, domains, weights, truth, capped=capped
                )
                accumulator = accumulators[variant]
                accumulator["window_adverse"] += adverse
                accumulator["window_total"] += total
                accumulator["window_max_adverse_domain"] = max(
                    float(accumulator["window_max_adverse_domain"]), max_domain
                )
                accumulator["window_fusion_errors"] += int(
                    abs(fusion[0] - (1.0 - truth)) < abs(fusion[0] - truth)
                )
                accumulator["window_events"] += 1
                if capped and max_domain > strongest_member + 1e-12:
                    accumulator["cap_bound_violations"] += 1
                if event_index < early_stop:
                    accumulator["early_adverse"] += adverse
                    accumulator["early_total"] += total
                    accumulator["early_max_adverse_domain"] = max(
                        float(accumulator["early_max_adverse_domain"]), max_domain
                    )
                    accumulator["early_fusion_errors"] += int(
                        abs(fusion[0] - (1.0 - truth)) < abs(fusion[0] - truth)
                    )
                    accumulator["early_events"] += 1

        delivered_truth = perturb_binary_truth(
            truth, seed=seed, event_index=event_index, error_rate=adjudication_error, tag=f'domain:{attack}:{layout}:{multiplicity}'
        )
        honesty = 1.0 - np.abs(opinions - delivered_truth)
        pending.append((event_index + adjudication_delay, recommender_ids.copy(), honesty))

    rows = []
    for variant in VARIANTS:
        accumulator = accumulators[variant]
        event_metrics = _event_metrics(actual_false, predicted_false[variant], len(trace))
        rows.append(
            {
                "attack": attack,
                "layout": layout,
                "multiplicity": multiplicity,
                "seed": seed,
                "variant": variant,
                "weighting": "lcb" if variant.startswith("lcb") else "mean",
                "domain_cap": int(variant.endswith("cap") and not variant.endswith("no_cap")),
                # When adjudication_delay == 0, the preregistered pre-feedback
                # "early" window has length zero.  That diagnostic is therefore
                # undefined (NaN), not a protocol failure and not a zero score.
                # Non-zero-delay behavior is bit-for-bit unchanged.
                "early_adversarial_weight_share": (
                    float(accumulator["early_adverse"]) / float(accumulator["early_total"])
                    if float(accumulator["early_total"]) > 0.0 else float("nan")
                ),
                "early_max_adverse_domain_weight": accumulator["early_max_adverse_domain"],
                "early_fused_error_rate": (
                    float(accumulator["early_fusion_errors"]) / int(accumulator["early_events"])
                    if int(accumulator["early_events"]) > 0 else float("nan")
                ),
                "window_adversarial_weight_share": float(accumulator["window_adverse"])
                / float(accumulator["window_total"]),
                "window_max_adverse_domain_weight": accumulator["window_max_adverse_domain"],
                "window_fused_error_rate": float(accumulator["window_fusion_errors"])
                / int(accumulator["window_events"]),
                "cap_bound_violations": accumulator["cap_bound_violations"],
                **event_metrics,
                "early_events": accumulator["early_events"],
                "window_events": accumulator["window_events"],
                "messages": len(trace),
                "join_index": join_index,
                "attack_stop": attack_stop,
            }
        )
    return rows


def summarize(rows: list[dict]) -> list[dict]:
    keys = ("attack", "layout", "multiplicity", "variant", "weighting", "domain_cap")
    groups: dict[tuple, list[dict]] = {}
    for row in rows:
        groups.setdefault(tuple(row[key] for key in keys), []).append(row)
    excluded = set(keys) | {"seed"}
    metrics = [key for key in rows[0] if key not in excluded]
    output = []
    for group, members in sorted(groups.items()):
        item = {key: value for key, value in zip(keys, group)}
        item["repeats"] = len(members)
        for metric in metrics:
            values = [float(member[metric]) for member in members]
            item[f"{metric}_mean"] = mean(values)
            item[f"{metric}_sd"] = stdev(values) if len(values) > 1 else 0.0
        output.append(item)
    return output


def exact_sign_flip_pvalue(differences: Sequence[float]) -> float:
    nonzero = [float(value) for value in differences if abs(value) > 1e-15]
    if not nonzero:
        return 1.0
    observed = abs(mean(nonzero))
    extreme = 0
    total = 0
    for signs in itertools.product((-1.0, 1.0), repeat=len(nonzero)):
        statistic = abs(mean([sign * value for sign, value in zip(signs, nonzero)]))
        extreme += int(statistic >= observed - 1e-15)
        total += 1
    return extreme / total


def registered_relative_reduction(baseline: float, treatment: float) -> float:
    """Apply the protocol's non-zero-baseline requirement to a reduction."""
    if baseline > 0.0:
        return (baseline - treatment) / baseline
    return 0.0 if treatment == 0.0 else -1.0


def paired_effects(rows: list[dict]) -> list[dict]:
    indexed = {
        (row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]): row
        for row in rows
    }
    output = []
    for attack in ATTACKS:
        for layout in LAYOUTS:
            for multiplicity in MULTIPLICITIES:
                for weighting in ("mean", "lcb"):
                    baseline_name = f"{weighting}_no_cap"
                    capped_name = f"{weighting}_cap"
                    metric_differences: dict[str, list[float]] = {
                        "early_adversarial_weight_share": [],
                        "early_fused_error_rate": [],
                        "window_adversarial_weight_share": [],
                        "window_fused_error_rate": [],
                        "event_macro_f1": [],
                        "event_fpr": [],
                    }
                    relative: dict[str, list[float]] = {
                        "early_adversarial_relative_reduction": [],
                        "early_fused_error_relative_reduction": [],
                        "window_adversarial_relative_reduction": [],
                        "window_fused_error_relative_reduction": [],
                    }
                    for seed in SEEDS:
                        baseline = indexed[(attack, layout, multiplicity, seed, baseline_name)]
                        capped = indexed[(attack, layout, multiplicity, seed, capped_name)]
                        for metric in metric_differences:
                            metric_differences[metric].append(capped[metric] - baseline[metric])
                        for metric, source in (
                            ("early_adversarial_relative_reduction", "early_adversarial_weight_share"),
                            ("early_fused_error_relative_reduction", "early_fused_error_rate"),
                            ("window_adversarial_relative_reduction", "window_adversarial_weight_share"),
                            ("window_fused_error_relative_reduction", "window_fused_error_rate"),
                        ):
                            base = baseline[source]
                            relative[metric].append(
                                registered_relative_reduction(base, capped[source])
                            )
                    item = {
                        "attack": attack,
                        "layout": layout,
                        "multiplicity": multiplicity,
                        "weighting": weighting,
                        "paired_seeds": len(SEEDS),
                    }
                    for metric, values in metric_differences.items():
                        item[f"{metric}_paired_delta_mean"] = mean(values)
                        item[f"{metric}_paired_delta_sd"] = stdev(values)
                        item[f"{metric}_sign_flip_p"] = exact_sign_flip_pvalue(values)
                    for metric, values in relative.items():
                        item[f"{metric}_mean"] = mean(values)
                        item[f"{metric}_sd"] = stdev(values)
                    output.append(item)
    return output


def multiplicity_slopes(rows: list[dict]) -> list[dict]:
    indexed = {
        (row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]): row
        for row in rows
    }
    output = []
    for attack in ATTACKS:
        for layout in LAYOUTS:
            for weighting in ("mean", "lcb"):
                no_cap_slopes = []
                cap_slopes = []
                for seed in SEEDS:
                    no_cap_slopes.append(
                        indexed[(attack, layout, 7, seed, f"{weighting}_no_cap")]["early_adversarial_weight_share"]
                        - indexed[(attack, layout, 1, seed, f"{weighting}_no_cap")]["early_adversarial_weight_share"]
                    )
                    cap_slopes.append(
                        indexed[(attack, layout, 7, seed, f"{weighting}_cap")]["early_adversarial_weight_share"]
                        - indexed[(attack, layout, 1, seed, f"{weighting}_cap")]["early_adversarial_weight_share"]
                    )
                differences = [cap - no_cap for cap, no_cap in zip(cap_slopes, no_cap_slopes)]
                output.append(
                    {
                        "attack": attack,
                        "layout": layout,
                        "weighting": weighting,
                        "no_cap_1_to_7_increase_mean": mean(no_cap_slopes),
                        "no_cap_1_to_7_increase_sd": stdev(no_cap_slopes),
                        "cap_1_to_7_increase_mean": mean(cap_slopes),
                        "cap_1_to_7_increase_sd": stdev(cap_slopes),
                        "cap_minus_no_cap_slope_mean": mean(differences),
                        "cap_minus_no_cap_slope_sd": stdev(differences),
                        "sign_flip_p": exact_sign_flip_pvalue(differences),
                    }
                )
    return output


def stop_lines(
    rows: list[dict], effects: list[dict], slopes: list[dict]
) -> dict[str, int]:
    relevant = [
        row
        for row in effects
        if row["layout"] == "concentrated" and row["multiplicity"] in (5, 7)
    ]
    influence_pass = all(
        row["early_adversarial_relative_reduction_mean"] >= 0.30 for row in relevant
    )
    fusion_pass = all(
        row["early_fused_error_relative_reduction_mean"] >= 0.30 for row in relevant
    )
    bound_pass = all(
        int(row["cap_bound_violations"]) == 0
        for row in rows
        if row["layout"] == "concentrated" and int(row["domain_cap"]) == 1
    )
    slope_pass = all(
        row["cap_1_to_7_increase_mean"] < row["no_cap_1_to_7_increase_mean"]
        for row in slopes
        if row["layout"] == "concentrated"
    )

    utility_pass = True
    for attack in ATTACKS:
        for layout in LAYOUTS:
            for multiplicity in MULTIPLICITIES:
                members = [
                    row for row in rows
                    if row["attack"] == attack
                    and row["layout"] == layout
                    and row["multiplicity"] == multiplicity
                ]
                by_variant = {
                    variant: [row for row in members if row["variant"] == variant]
                    for variant in VARIANTS
                }
                macro = {variant: mean(row["event_macro_f1"] for row in values) for variant, values in by_variant.items()}
                fpr = {variant: mean(row["event_fpr"] for row in values) for variant, values in by_variant.items()}
                utility_pass &= macro["lcb_cap"] >= max(macro.values()) - 0.02
                utility_pass &= fpr["lcb_cap"] <= min(fpr.values()) + 0.01

    result = {
        "input_integrity_and_pairing_pass": 1,
        "concentrated_early_influence_reduction_pass": int(influence_pass),
        "concentrated_early_fusion_error_reduction_pass": int(fusion_pass),
        "domain_weight_bound_pass": int(bound_pass),
        "multiplicity_slope_attenuation_pass": int(slope_pass),
        "full_method_event_utility_noninferiority_pass": int(utility_pass),
    }
    result["all_registered_domain_cap_lines_pass"] = int(all(result.values()))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=min(10, os.cpu_count() or 4))
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty formal output: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    traces = load_traces()
    futures = {}
    raw_rows = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for attack, trace in traces.items():
            for layout in LAYOUTS:
                for multiplicity in MULTIPLICITIES:
                    for seed in SEEDS:
                        future = executor.submit(
                            run_cell, attack, trace, layout, multiplicity, seed
                        )
                        futures[future] = (attack, layout, multiplicity, seed)
        for index, future in enumerate(as_completed(futures), 1):
            raw_rows.extend(future.result())
            print(f"completed {index}/{len(futures)} paired cells", flush=True)

    raw_rows.sort(
        key=lambda row: (
            row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]
        )
    )
    summary_rows = summarize(raw_rows)
    effect_rows = paired_effects(raw_rows)
    slope_rows = multiplicity_slopes(raw_rows)
    stop = stop_lines(raw_rows, effect_rows, slope_rows)

    write_csv(args.output_dir / "DURAC_domain_cap_2x2_raw.csv", raw_rows)
    write_csv(args.output_dir / "DURAC_domain_cap_2x2_summary.csv", summary_rows)
    write_csv(args.output_dir / "DURAC_domain_cap_2x2_paired_effects.csv", effect_rows)
    write_csv(args.output_dir / "DURAC_domain_cap_2x2_multiplicity_slopes.csv", slope_rows)
    write_csv(args.output_dir / "DURAC_domain_cap_2x2_stop_lines.csv", [stop])
    manifest = {
        "protocol_sha256": digest(PROTOCOL_PATH),
        "amendment_1_sha256": digest(AMENDMENT_PATH),
        "runner_sha256": digest(Path(__file__)),
        "input": str(INPUT_PATH),
        "input_sha256": digest(INPUT_PATH),
        "seeds": SEEDS,
        "multiplicities": MULTIPLICITIES,
        "layouts": LAYOUTS,
        "variants": VARIANTS,
        "lcb_quantile": LCB_QUANTILE,
        "sample_stride": SAMPLE_STRIDE,
        "recommendations_per_event": RECOMMENDERS,
        "adjudication_delay": ADJUDICATION_DELAY,
        "outputs": {
            path.name: digest(path) for path in sorted(args.output_dir.glob("*.csv"))
        },
    }
    with (args.output_dir / "DURAC_domain_cap_2x2_manifest.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    print("===== DURAC LCB × DOMAIN CAP 2×2 =====")
    for row in effect_rows:
        if row["layout"] == "concentrated" and row["multiplicity"] in (5, 7):
            print(
                f"{row['attack']:18s} a={row['multiplicity']} {row['weighting']:4s} "
                f"early influence reduction={row['early_adversarial_relative_reduction_mean']:.4f} "
                f"early fusion-error reduction={row['early_fused_error_relative_reduction_mean']:.4f}"
            )
    print(json.dumps(stop, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
