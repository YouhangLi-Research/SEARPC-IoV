#!/usr/bin/env python3
"""BRS and TWSL identity-level baselines on the frozen RQ3 stress grid."""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
from statistics import mean, stdev
import sys

import numpy as np

from adjudication import perturb_binary_truth
from run_durac_domain_cap_2x2 import (
    ADJUDICATION_DELAY,
    ATTACKS,
    ATTACK_STOP_FRACTION,
    JOIN_FRACTION,
    LAYOUTS,
    MULTIPLICITIES,
    OPINION_ATTACK_PROBABILITY,
    OPINION_NOISE,
    RECOMMENDERS,
    _ArrayBook,
    _event_is_false,
    _event_metrics,
    domain_influence,
    domain_layout,
    individual_fusion,
    load_traces,
)


BASELINE_ROOT = Path(__file__).resolve().parents[2] / "baselines" / "TWSL_VeReMi_Adapted_Baseline" / "src"
sys.path.insert(0, str(BASELINE_ROOT))
from twsl_baseline.core import local_opinion  # noqa: E402


SEEDS = tuple(range(260825, 260845))
VARIANTS = ("brs_identity_pooling", "twsl_local_identity_pooling")
TWSL_COMMUNICATION_QUALITY = 0.2
TWSL_GAMMA = 0.5


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


def _twsl_scores(positive: np.ndarray, negative: np.ndarray, ids: np.ndarray) -> np.ndarray:
    return np.asarray([
        local_opinion(
            float(positive[index]),
            float(negative[index]),
            TWSL_COMMUNICATION_QUALITY,
            TWSL_GAMMA,
        ).expectation
        for index in ids
    ], dtype=float)


def _new_accumulator() -> dict[str, float | int]:
    return {
        "early_adverse": 0.0,
        "early_total": 0.0,
        "early_fusion_errors": 0,
        "early_events": 0,
        "window_adverse": 0.0,
        "window_total": 0.0,
        "window_fusion_errors": 0,
        "window_events": 0,
    }


def run_cell(attack, trace, layout, multiplicity, seed):
    warm_domains, attacker_domains = domain_layout(multiplicity, layout)
    attacker_ids = np.arange(RECOMMENDERS, RECOMMENDERS + multiplicity, dtype=int)
    post_join_warm = np.arange(RECOMMENDERS - multiplicity, dtype=int)
    post_join_ids = np.concatenate((post_join_warm, attacker_ids))
    all_domains = np.concatenate((warm_domains, attacker_domains))
    identities = RECOMMENDERS + multiplicity
    brs = _ArrayBook(identities, 1)
    twsl_positive = np.zeros(identities, dtype=float)
    twsl_negative = np.zeros(identities, dtype=float)
    pending = deque()
    attack_offset = 0 if attack == "dataReplay" else 10_000_019
    layout_offset = 0 if layout == "concentrated" else 20_000_033
    rng = random.Random(seed * 1_000_003 + attack_offset + layout_offset + multiplicity * 1009)
    join_index = math.ceil(JOIN_FRACTION * len(trace))
    attack_stop = math.ceil(ATTACK_STOP_FRACTION * len(trace))
    early_stop = join_index + ADJUDICATION_DELAY
    predicted_false = {variant: set() for variant in VARIANTS}
    actual_false: set[int] = set()
    accumulators = {variant: _new_accumulator() for variant in VARIANTS}

    for event_index, (attacker, malicious_probability, uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, ids, honesty = pending.popleft()
            brs.update(0, ids, honesty)
            twsl_positive[ids] += honesty
            twsl_negative[ids] += 1.0 - honesty

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
        weights = {
            "brs_identity_pooling": np.asarray(brs.mean(0, recommender_ids), dtype=float) * reliability,
            "twsl_local_identity_pooling": _twsl_scores(
                twsl_positive, twsl_negative, recommender_ids
            ) * reliability,
        }
        for variant in VARIANTS:
            fusion = individual_fusion(opinions, domains, weights[variant])
            if _event_is_false(1.0 - malicious_probability, reliability, 0.5, fusion):
                predicted_false[variant].add(event_index)
            if join_index <= event_index < attack_stop:
                adverse, total, _, _ = domain_influence(
                    opinions, domains, weights[variant], truth, capped=False
                )
                accumulator = accumulators[variant]
                accumulator["window_adverse"] += adverse
                accumulator["window_total"] += total
                accumulator["window_fusion_errors"] += int(
                    abs(fusion[0] - (1.0 - truth)) < abs(fusion[0] - truth)
                )
                accumulator["window_events"] += 1
                if event_index < early_stop:
                    accumulator["early_adverse"] += adverse
                    accumulator["early_total"] += total
                    accumulator["early_fusion_errors"] += int(
                        abs(fusion[0] - (1.0 - truth)) < abs(fusion[0] - truth)
                    )
                    accumulator["early_events"] += 1

        delivered_truth = perturb_binary_truth(
            truth,
            seed=seed,
            event_index=event_index,
            error_rate=0.0,
            tag=f"identity-external:{attack}:{layout}:{multiplicity}",
        )
        honesty = 1.0 - np.abs(opinions - delivered_truth)
        pending.append((event_index + ADJUDICATION_DELAY, recommender_ids.copy(), honesty))

    rows = []
    for variant in VARIANTS:
        accumulator = accumulators[variant]
        rows.append({
            "attack": attack,
            "layout": layout,
            "multiplicity": multiplicity,
            "seed": seed,
            "variant": variant,
            "weighting": "brs_mean" if variant.startswith("brs") else "twsl_local_expectation",
            "domain_cap": 0,
            "early_adversarial_weight_share": accumulator["early_adverse"] / accumulator["early_total"],
            "early_fused_error_rate": accumulator["early_fusion_errors"] / accumulator["early_events"],
            "window_adversarial_weight_share": accumulator["window_adverse"] / accumulator["window_total"],
            "window_fused_error_rate": accumulator["window_fusion_errors"] / accumulator["window_events"],
            **_event_metrics(actual_false, predicted_false[variant], len(trace)),
            "early_events": accumulator["early_events"],
            "window_events": accumulator["window_events"],
            "messages": len(trace),
            "join_index": join_index,
            "attack_stop": attack_stop,
        })
    return rows


def summarize(rows: list[dict]) -> list[dict]:
    keys = ("attack", "layout", "multiplicity", "variant", "weighting", "domain_cap")
    groups = {}
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


def slope_summary(rows: list[dict]) -> list[dict]:
    index = {
        (row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]): row
        for row in rows
    }
    output = []
    for attack in ATTACKS:
        for layout in LAYOUTS:
            for variant in VARIANTS:
                slopes = [
                    index[(attack, layout, 7, seed, variant)]["early_adversarial_weight_share"]
                    - index[(attack, layout, 1, seed, variant)]["early_adversarial_weight_share"]
                    for seed in SEEDS
                ]
                output.append({
                    "attack": attack,
                    "layout": layout,
                    "variant": variant,
                    "paired_seeds": len(slopes),
                    "one_to_seven_increase_mean": mean(slopes),
                    "one_to_seven_increase_sd": stdev(slopes),
                    "positive_slope_count": sum(value > 0 for value in slopes),
                })
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=min(8, os.cpu_count() or 4))
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    traces = load_traces(args.predictions)
    jobs = [
        (attack, traces[attack], layout, multiplicity, seed)
        for attack in ATTACKS
        for layout in LAYOUTS
        for multiplicity in MULTIPLICITIES
        for seed in SEEDS
    ]
    rows = []
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(run_cell, *job): job for job in jobs}
        for index, future in enumerate(as_completed(futures), 1):
            rows.extend(future.result())
            if index % 10 == 0 or index == len(futures):
                print(f"identity baselines completed {index}/{len(futures)} cells", flush=True)
    rows.sort(key=lambda row: (row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]))
    summary = summarize(rows)
    slopes = slope_summary(rows)
    write_csv(args.output_dir / "IDENTITY_MULTIPLICITY_EXTERNAL_raw.csv", rows)
    write_csv(args.output_dir / "IDENTITY_MULTIPLICITY_EXTERNAL_summary.csv", summary)
    write_csv(args.output_dir / "IDENTITY_MULTIPLICITY_EXTERNAL_slopes.csv", slopes)
    manifest = {
        "protocol_status": "frozen before result computation",
        "publication_labels": {
            "brs_identity_pooling": "BRS identity-level pooling",
            "twsl_local_identity_pooling": "TWSL local-opinion identity-stage adaptation",
        },
        "predictions": str(args.predictions),
        "predictions_sha256": digest(args.predictions),
        "runner_sha256": digest(Path(__file__)),
        "twsl_core_sha256": digest(BASELINE_ROOT / "twsl_baseline" / "core.py"),
        "twsl_communication_quality": TWSL_COMMUNICATION_QUALITY,
        "seeds": list(SEEDS),
        "outputs": {path.name: digest(path) for path in sorted(args.output_dir.glob("*.csv"))},
    }
    (args.output_dir / "IDENTITY_MULTIPLICITY_EXTERNAL_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
