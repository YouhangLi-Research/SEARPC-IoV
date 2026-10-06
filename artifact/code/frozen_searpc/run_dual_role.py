#!/usr/bin/env python3
"""Run the preregistered public-evidence dual-role reputation ablation."""

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
from typing import Iterable, Sequence

import numpy as np
from scipy.stats import beta as beta_distribution

from durac.datasets import iter_veremi_json
from run_catch_baseline import BinaryMetrics, binary_metrics


SEEDS = (260825, 260826, 260827, 260828, 260829)
OVERLAPS = (0.0, 0.5, 1.0)
SAMPLE_STRIDE = 32
RECOMMENDERS = 9
DOMAINS = 8
OPINION_NOISE = 0.15
OPINION_ATTACK_PROBABILITY = 0.80
ADJUDICATION_DELAY = 50
LCB_QUANTILE = 0.05
ROLE_THRESHOLD = 0.50

SCRATCH_ROOT = Path(__file__).resolve().parents[4]
DATA_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase9"
PREDICTIONS = Path(
    "results/durac_phase9_context_external/DURAC_phase9_test_predictions.csv"
)
PROTOCOL = Path("SEARPC_DUAL_ROLE_PROTOCOL.md")
OUTPUT_DIR = Path("results/durac_phase11_dual_role")

ATTACKS = {
    "dataReplay": "InTAS_urban_2_dataReplay",
    "timeDelayAttack": "InTAS_urban_2_timeDelayAttack",
}
EXPECTED_MESSAGES = 406_801
EXPECTED_IDENTITIES = 1_019
EXPECTED_DATA_ATTACKERS = 203
EXPECTED_SAMPLED = 12_713
VARIANTS = ("single_role_lcb", "dual_role_mean", "dual_role_lcb")


def _digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _iter_phase9_records(path: Path):
    files = sorted(path.rglob("*.json"))
    if not files:
        raise ValueError(f"no VeReMi JSON files in {path}")
    for file_path in files:
        records = list(iter_veremi_json(file_path))
        records.sort(
            key=lambda record: (
                record.receive_time,
                record.send_time,
                record.message_id,
                record.sender_id,
            )
        )
        yield from records


def _prediction_rows(attack: str):
    with PREDICTIONS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["attack"] == attack:
                yield row


def load_trace(attack: str, folder: str):
    root = DATA_ROOT / folder / "Test" / "json"
    identities: set[str] = set()
    attackers: set[str] = set()
    sampled = []
    count = 0
    records = _iter_phase9_records(root)
    predictions = _prediction_rows(attack)
    for index, (record, prediction) in enumerate(zip(records, predictions)):
        if int(prediction["external_test_row"]) != index:
            raise ValueError(f"Phase 9 row index mismatch for {attack} at {index}")
        if int(prediction["attacker"]) != record.attacker:
            raise ValueError(f"Phase 9 label mismatch for {attack} at {index}")
        identities.add(record.sender_id)
        if record.attacker:
            attackers.add(record.sender_id)
        if index % SAMPLE_STRIDE == 0:
            sampled.append(
                (
                    record.sender_id,
                    int(record.attacker),
                    float(prediction["contextual_probability"]),
                    float(prediction["contextual_uncertainty"]),
                )
            )
        count += 1

    try:
        next(records)
        raise ValueError(f"unmatched VeReMi record after {count} rows")
    except StopIteration:
        pass
    try:
        next(predictions)
        raise ValueError(f"unmatched Phase 9 prediction after {count} rows")
    except StopIteration:
        pass

    if count != EXPECTED_MESSAGES:
        raise ValueError(f"{attack} message accounting mismatch: {count}")
    if len(identities) != EXPECTED_IDENTITIES:
        raise ValueError(f"{attack} identity accounting mismatch")
    if len(attackers) != EXPECTED_DATA_ATTACKERS:
        raise ValueError(f"{attack} attacker accounting mismatch")
    if len(sampled) != EXPECTED_SAMPLED:
        raise ValueError(f"{attack} sample accounting mismatch")

    ordered = tuple(sorted(identities))
    identity_to_index = {identity: index for index, identity in enumerate(ordered)}
    indexed_trace = tuple(
        (identity_to_index[sender], label, probability, uncertainty)
        for sender, label, probability, uncertainty in sampled
    )
    attacker_indices = frozenset(identity_to_index[item] for item in attackers)
    domains = tuple(_domain(identity) for identity in ordered)
    return indexed_trace, attacker_indices, domains


def _domain(identity: str) -> int:
    digest = hashlib.sha256(identity.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % DOMAINS


def select_opinion_attackers(
    data_attackers: frozenset[int], num_identities: int, overlap: float, seed: int
) -> frozenset[int]:
    rng = random.Random(seed * 1009 + int(round(overlap * 100)))
    count = len(data_attackers)
    overlap_count = round(count * overlap)
    shared = set(rng.sample(sorted(data_attackers), overlap_count))
    honest_data = sorted(set(range(num_identities)) - set(data_attackers))
    opinion_only = set(rng.sample(honest_data, count - overlap_count))
    return frozenset(shared | opinion_only)


def _weighted_median(values: Sequence[tuple[float, float]]) -> float:
    ordered = sorted(values)
    midpoint = sum(weight for _, weight in ordered) / 2.0
    cumulative = 0.0
    for value, weight in ordered:
        cumulative += weight
        if cumulative >= midpoint:
            return value
    return ordered[-1][0]


def domain_capped_fusion(
    values: np.ndarray, domains: np.ndarray, weights: np.ndarray
) -> tuple[float, float, float, int]:
    domain_points = []
    for domain in sorted(set(int(value) for value in domains)):
        mask = domains == domain
        pairs = [
            (float(value), float(weight))
            for value, weight in zip(values[mask], weights[mask])
            if weight > 0.0
        ]
        if not pairs:
            continue
        domain_points.append(
            (_weighted_median(pairs), max(weight for _, weight in pairs))
        )
    if not domain_points:
        return 0.5, 1.0, 0.0, 0
    fused = _weighted_median(domain_points)
    total = sum(weight for _, weight in domain_points)
    disagreement = sum(
        weight * abs(value - fused) for value, weight in domain_points
    ) / total
    return fused, disagreement, total, len(domain_points)


class _ArrayBook:
    def __init__(self, identities: int, roles: int) -> None:
        self.alpha = np.ones((roles, identities), dtype=float)
        self.beta = np.ones((roles, identities), dtype=float)

    def update(self, role: int, indices: np.ndarray, successes: np.ndarray, weights=None):
        if weights is None:
            weights = np.ones(len(indices), dtype=float)
        np.add.at(self.alpha[role], indices, weights * successes)
        np.add.at(self.beta[role], indices, weights * (1.0 - successes))

    def mean(self, role: int, indices):
        alpha = self.alpha[role, indices]
        beta = self.beta[role, indices]
        return alpha / (alpha + beta)

    def lcb(self, role: int, indices):
        return beta_distribution.ppf(
            LCB_QUANTILE, self.alpha[role, indices], self.beta[role, indices]
        )


def _event_is_false(
    credibility_probability: float,
    reliability: float,
    provider_score: float,
    fused: tuple[float, float, float, int],
) -> bool:
    value, disagreement, effective_weight, represented_domains = fused
    alpha = 1.0 + reliability * credibility_probability + provider_score
    beta = 1.0 + reliability * (1.0 - credibility_probability) + (1.0 - provider_score)
    if represented_domains:
        opinion_weight = min(1.0, effective_weight / represented_domains) * (
            1.0 - disagreement
        )
        alpha += opinion_weight * value
        beta += opinion_weight * (1.0 - value)
    return alpha / (alpha + beta) < 0.5


def _confusion(actual: set[int], predicted: set[int], universe: set[int]) -> BinaryMetrics:
    negative = universe - actual
    tp = len(actual & predicted)
    fn = len(actual - predicted)
    fp = len(negative & predicted)
    tn = len(negative - predicted)
    return binary_metrics(tp, tn, fp, fn)


def _event_metrics(actual: set[int], predicted: set[int], total: int) -> BinaryMetrics:
    universe = set(range(total))
    return _confusion(actual, predicted, universe)


def _active(event_index: int, total: int) -> bool:
    position = event_index / total
    return 0.15 <= position < 0.45 or 0.55 <= position < 0.85


def _sample_recommenders(rng: random.Random, provider: int, identities: int) -> np.ndarray:
    selected: set[int] = set()
    while len(selected) < RECOMMENDERS:
        candidate = rng.randrange(identities)
        if candidate != provider:
            selected.add(candidate)
    return np.fromiter(sorted(selected), dtype=int)


def _apply_pending(single: _ArrayBook, dual: _ArrayBook, pending_item) -> None:
    provider, truth, reliability, recommenders, opinions = pending_item
    single.update(
        0, np.asarray([provider]), np.asarray([truth]), np.asarray([reliability])
    )
    dual.update(
        0, np.asarray([provider]), np.asarray([truth]), np.asarray([reliability])
    )
    honesty = 1.0 - np.abs(opinions - truth)
    single.update(0, recommenders, honesty)
    dual.update(1, recommenders, honesty)


def run_cell(attack: str, trace, data_attackers, domains, overlap: float, seed: int):
    identities = len(domains)
    universe = set(range(identities))
    opinion_attackers = select_opinion_attackers(
        data_attackers, identities, overlap, seed
    )
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    single = _ArrayBook(identities, 1)
    dual = _ArrayBook(identities, 2)
    pending = deque()
    actual_false: set[int] = set()
    predicted_false = {variant: set() for variant in VARIANTS}

    for event_index, (provider, attacker, malicious_probability, uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            _apply_pending(single, dual, item)

        truth = 1.0 - attacker
        if attacker:
            actual_false.add(event_index)
        reliability = min(1.0, max(0.0, 1.0 - uncertainty))
        credibility_probability = 1.0 - malicious_probability
        recommenders = _sample_recommenders(rng, provider, identities)
        opinions = np.empty(RECOMMENDERS, dtype=float)
        active = _active(event_index, len(trace))
        for position, recommender in enumerate(recommenders):
            base = truth
            if (
                recommender in opinion_attackers
                and active
                and rng.random() < OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, OPINION_NOISE)))
        recommender_domains = np.asarray([domains[item] for item in recommenders])

        single_weights = single.lcb(0, recommenders) * reliability
        dual_lcb_weights = dual.lcb(1, recommenders) * reliability
        dual_mean_weights = dual.mean(1, recommenders) * reliability
        fusions = {
            "single_role_lcb": domain_capped_fusion(
                opinions, recommender_domains, single_weights
            ),
            "dual_role_mean": domain_capped_fusion(
                opinions, recommender_domains, dual_mean_weights
            ),
            "dual_role_lcb": domain_capped_fusion(
                opinions, recommender_domains, dual_lcb_weights
            ),
        }
        provider_scores = {
            "single_role_lcb": float(single.lcb(0, provider)),
            "dual_role_mean": float(dual.mean(0, provider)),
            "dual_role_lcb": float(dual.lcb(0, provider)),
        }
        for variant in VARIANTS:
            if _event_is_false(
                credibility_probability,
                reliability,
                provider_scores[variant],
                fusions[variant],
            ):
                predicted_false[variant].add(event_index)

        pending.append(
            (
                event_index + ADJUDICATION_DELAY,
                (provider, truth, reliability, recommenders, opinions),
            )
        )

    while pending:
        _, item = pending.popleft()
        _apply_pending(single, dual, item)

    scores = {
        "single_role_lcb": (
            single.lcb(0, np.arange(identities)),
            single.lcb(0, np.arange(identities)),
        ),
        "dual_role_mean": (
            dual.mean(0, np.arange(identities)),
            dual.mean(1, np.arange(identities)),
        ),
        "dual_role_lcb": (
            dual.lcb(0, np.arange(identities)),
            dual.lcb(1, np.arange(identities)),
        ),
    }
    rows = []
    data_only = set(data_attackers) - set(opinion_attackers)
    opinion_only = set(opinion_attackers) - set(data_attackers)
    for variant in VARIANTS:
        data_scores, opinion_scores = scores[variant]
        predicted_data = set(np.flatnonzero(data_scores < ROLE_THRESHOLD))
        predicted_opinion = set(np.flatnonzero(opinion_scores < ROLE_THRESHOLD))
        data_metrics = _confusion(set(data_attackers), predicted_data, universe)
        opinion_metrics = _confusion(set(opinion_attackers), predicted_opinion, universe)
        event_metrics = _event_metrics(
            actual_false, predicted_false[variant], len(trace)
        )
        rows.append(
            {
                "attack": attack,
                "overlap": overlap,
                "seed": seed,
                "variant": variant,
                "data_attacker_f1": data_metrics.malicious_f1,
                "data_attacker_recall": data_metrics.malicious_recall,
                "data_attacker_fpr": data_metrics.false_positive_rate,
                "opinion_attacker_f1": opinion_metrics.malicious_f1,
                "opinion_attacker_recall": opinion_metrics.malicious_recall,
                "opinion_attacker_fpr": opinion_metrics.false_positive_rate,
                "event_f1": event_metrics.malicious_f1,
                "event_macro_f1": event_metrics.macro_f1,
                "event_recall": event_metrics.malicious_recall,
                "event_fpr": event_metrics.false_positive_rate,
                "opinion_only_recall": (
                    len(opinion_only & predicted_opinion) / len(opinion_only)
                    if opinion_only
                    else math.nan
                ),
                "data_only_false_opinion_flag_rate": (
                    len(data_only & predicted_opinion) / len(data_only)
                    if data_only
                    else math.nan
                ),
                "mean_data_score_true_attackers": float(
                    np.mean(data_scores[list(data_attackers)])
                ),
                "mean_opinion_score_true_attackers": float(
                    np.mean(opinion_scores[list(opinion_attackers)])
                ),
                "messages": len(trace),
                "identities": identities,
                "data_attackers": len(data_attackers),
                "opinion_attackers": len(opinion_attackers),
            }
        )
    return rows


def _write_csv(path: Path, rows: Iterable[dict]) -> None:
    rows = list(rows)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _summary_rows(raw_rows):
    metric_names = [
        key
        for key in raw_rows[0]
        if key not in {
            "attack", "overlap", "seed", "variant", "messages", "identities",
            "data_attackers", "opinion_attackers",
        }
    ]
    groups = {}
    for row in raw_rows:
        groups.setdefault((row["attack"], row["overlap"], row["variant"]), []).append(row)
    summaries = []
    for (attack, overlap, variant), rows in sorted(groups.items()):
        summary = {"attack": attack, "overlap": overlap, "variant": variant, "repeats": len(rows)}
        for metric in metric_names:
            values = [float(row[metric]) for row in rows if math.isfinite(float(row[metric]))]
            summary[f"{metric}_mean"] = mean(values) if values else math.nan
            summary[f"{metric}_sd"] = stdev(values) if len(values) > 1 else (0.0 if values else math.nan)
        summaries.append(summary)
    return summaries


def _comparison_rows(raw_rows):
    indexed = {(row["attack"], row["overlap"], row["seed"], row["variant"]): row for row in raw_rows}
    rows = []
    for attack in ATTACKS:
        for overlap in OVERLAPS:
            deltas = {
                "opinion_f1": [], "event_macro_f1": [], "data_only_false_flag": [],
                "lcb_minus_mean_opinion_f1": [], "lcb_minus_mean_event_macro_f1": [],
            }
            for seed in SEEDS:
                single = indexed[(attack, overlap, seed, "single_role_lcb")]
                dual = indexed[(attack, overlap, seed, "dual_role_lcb")]
                dual_mean = indexed[(attack, overlap, seed, "dual_role_mean")]
                deltas["opinion_f1"].append(dual["opinion_attacker_f1"] - single["opinion_attacker_f1"])
                deltas["event_macro_f1"].append(dual["event_macro_f1"] - single["event_macro_f1"])
                if math.isfinite(dual["data_only_false_opinion_flag_rate"]):
                    deltas["data_only_false_flag"].append(
                        single["data_only_false_opinion_flag_rate"] - dual["data_only_false_opinion_flag_rate"]
                    )
                deltas["lcb_minus_mean_opinion_f1"].append(
                    dual["opinion_attacker_f1"] - dual_mean["opinion_attacker_f1"]
                )
                deltas["lcb_minus_mean_event_macro_f1"].append(
                    dual["event_macro_f1"] - dual_mean["event_macro_f1"]
                )
            row = {"attack": attack, "overlap": overlap}
            for name, values in deltas.items():
                row[f"{name}_mean"] = mean(values) if values else math.nan
                row[f"{name}_sd"] = stdev(values) if len(values) > 1 else (0.0 if values else math.nan)
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=min(10, os.cpu_count() or 4))
    args = parser.parse_args()
    if args.workers < 1:
        raise ValueError("workers must be positive")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    loaded = {}
    audit_rows = []
    print("[align frozen public evidence and sample every 32nd message]", flush=True)
    for attack, folder in ATTACKS.items():
        trace, data_attackers, domains = load_trace(attack, folder)
        loaded[attack] = (trace, data_attackers, domains)
        audit_rows.append(
            {
                "attack": attack,
                "complete_messages": EXPECTED_MESSAGES,
                "sampled_messages": len(trace),
                "identities": len(domains),
                "data_attackers": len(data_attackers),
                "sample_stride": SAMPLE_STRIDE,
                "label_alignment_pass": 1,
            }
        )

    futures = {}
    raw_rows = []
    print("[run paired single-role, dual-mean and dual-LCB cells]", flush=True)
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for attack, (trace, data_attackers, domains) in loaded.items():
            for overlap in OVERLAPS:
                for seed in SEEDS:
                    future = executor.submit(
                        run_cell, attack, trace, data_attackers, domains, overlap, seed
                    )
                    futures[future] = (attack, overlap, seed)
        for index, future in enumerate(as_completed(futures), 1):
            raw_rows.extend(future.result())
            print(f"  completed {index}/{len(futures)} paired cells", flush=True)

    raw_rows.sort(key=lambda row: (row["attack"], row["overlap"], row["seed"], row["variant"]))
    summaries = _summary_rows(raw_rows)
    comparisons = _comparison_rows(raw_rows)
    comparison_index = {(row["attack"], row["overlap"]): row for row in comparisons}

    stop = {
        "public_alignment_and_accounting_pass": 1,
        "dual_opinion_f1_gain_overlap_0_and_0_5_pass": int(
            all(
                comparison_index[(attack, overlap)]["opinion_f1_mean"] >= 0.10
                for attack in ATTACKS for overlap in (0.0, 0.5)
            )
        ),
        "dual_cross_role_contamination_reduction_pass": int(
            all(
                comparison_index[(attack, 0.0)]["data_only_false_flag_mean"] >= 0.20
                for attack in ATTACKS
            )
        ),
        "dual_overlap_1_noninferiority_pass": int(
            all(
                comparison_index[(attack, 1.0)]["opinion_f1_mean"] >= -0.02
                for attack in ATTACKS
            )
        ),
        "dual_event_macro_f1_noninferiority_pass": int(
            all(row["event_macro_f1_mean"] >= -0.02 for row in comparisons)
        ),
    }
    stop["all_dual_role_stop_lines_pass"] = int(all(stop.values()))
    lcb_cells = [
        row for row in comparisons
        if row["lcb_minus_mean_opinion_f1_mean"] > 0.0
        or row["lcb_minus_mean_event_macro_f1_mean"] > 0.0
    ]
    stop["lcb_measurable_benefit_cell_count"] = len(lcb_cells)

    _write_csv(OUTPUT_DIR / "DURAC_phase11_audit.csv", audit_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase11_raw.csv", raw_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase11_summary.csv", summaries)
    _write_csv(OUTPUT_DIR / "DURAC_phase11_comparison.csv", comparisons)
    _write_csv(OUTPUT_DIR / "DURAC_phase11_stop_lines.csv", [stop])
    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "phase9_predictions_sha256": _digest(PREDICTIONS),
        "seeds": SEEDS,
        "overlaps": OVERLAPS,
        "sample_stride": SAMPLE_STRIDE,
        "workers": args.workers,
        "outputs": {path.name: _digest(path) for path in sorted(OUTPUT_DIR.glob("*.csv"))},
    }
    with (OUTPUT_DIR / "DURAC_phase11_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    print("===== DURAC PHASE 11 DUAL-ROLE ABLATION =====")
    for row in comparisons:
        print(
            f"{row['attack']:18s} overlap={row['overlap']:.1f} "
            f"dual-single opinion_F1={row['opinion_f1_mean']:+.4f} "
            f"event_macro_F1={row['event_macro_f1_mean']:+.4f} "
            f"contamination_reduction={row['data_only_false_flag_mean']:+.4f}"
        )
    print(json.dumps(stop, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
