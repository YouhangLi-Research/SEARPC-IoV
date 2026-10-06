#!/usr/bin/env python3
"""Run the preregistered holdout authorization v3 three-state trust holdout."""

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
from typing import Iterable

import numpy as np
from scipy.stats import beta as beta_distribution
from scipy.special import betaincinv

from durac import (
    CONTEXTUAL_FEATURE_NAMES,
    TEMPORAL_FEATURE_NAMES,
    iter_veremi_contextual_directory,
    message_evidence_metrics,
    select_fpr_constrained_threshold,
)
from run_temporal_evaluation import (
    INSTANTANEOUS_FEATURE_NAMES,
    _calibrate,
    _fit_ensemble,
)
from run_context_evaluation import _load as _load_phase9
from authority import apply_malicious_authority_gate
from adjudication import perturb_binary_truth
from run_dual_role import (
    ADJUDICATION_DELAY,
    DOMAINS,
    LCB_QUANTILE,
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
    domain_capped_fusion,
    select_opinion_attackers,
)


SAMPLE_STRIDE = 8
TRUST_THRESHOLD = 0.5
FAILURE_STREAK = 3
RECOVERY_STREAK = 10
VARIANTS = (
    "single_role_three_state",
    "dual_role_mean_weight",
    "dual_role_three_state",
)

SCRATCH_ROOT = Path(__file__).resolve().parents[4]
DEVELOPMENT_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase8"
HOLDOUT_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase12"
NESTED_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase12_nested"
OUTPUT_DIR = Path("results/durac_phase12_v3_holdout")
PROTOCOL = Path("SEARPC_V3_HOLDOUT_PROTOCOL.md")

ATTACKS = {
    "dataReplay": {
        "development_folder": "InTAS_highway_2_dataReplay",
        "holdout_folder": "InTAS_urban_2_dataReplay",
        "nested_md5": "e1eacd4d1da6d465cebef14a1bf6966a",
        "nested_sha256": "9c5c99b3ca319bb050d3e6e1f24622638667b53a4e1da716bbc304fe1884a75c",
    },
    "timeDelayAttack": {
        "development_folder": "InTAS_highway_2_timeDelayAttack",
        "holdout_folder": "InTAS_urban_2_timeDelayAttack",
        "nested_md5": "9111ca4c309f8b0e2c302c609a5cb6a2",
        "nested_sha256": "bc8363aaaaa87e3e13f73ae0cd13f0589873a2d1fbbc78312d56518dfdff24e8",
    },
}


def _digest(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_holdout(path: Path):
    contextual_rows = []
    labels = []
    sender_ids = []
    for example in iter_veremi_contextual_directory(path):
        physical = example.record.physical_features()
        contextual_rows.append(
            [physical[name] for name in INSTANTANEOUS_FEATURE_NAMES]
            + [example.temporal_features[name] for name in TEMPORAL_FEATURE_NAMES]
            + [example.contextual_features[name] for name in CONTEXTUAL_FEATURE_NAMES]
        )
        labels.append(example.record.attacker)
        sender_ids.append(example.record.sender_id)
    matrix = np.asarray(contextual_rows, dtype=float)
    labels_array = np.asarray(labels, dtype=int)
    if matrix.shape != (
        len(labels),
        len(INSTANTANEOUS_FEATURE_NAMES)
        + len(TEMPORAL_FEATURE_NAMES)
        + len(CONTEXTUAL_FEATURE_NAMES),
    ):
        raise ValueError("Phase 12 contextual accounting mismatch")
    if not np.isfinite(matrix).all():
        raise ValueError("Phase 12 holdout contains non-finite features")
    return matrix, labels_array, tuple(sender_ids)


class _DynamicStates:
    def __init__(self, roles: int, identities: int) -> None:
        self.malicious = np.zeros((roles, identities), dtype=bool)
        # Use int32 because honest identities can accumulate many consecutive
        # successes in a long trace; int16 overflow would silently corrupt the
        # preregistered recovery state machine.
        self.failures = np.zeros((roles, identities), dtype=np.int32)
        self.successes = np.zeros((roles, identities), dtype=np.int32)

    def observe(self, role: int, indices: np.ndarray, outcomes: np.ndarray) -> None:
        for index, outcome in zip(indices, outcomes):
            index = int(index)
            if outcome < TRUST_THRESHOLD:
                self.failures[role, index] += 1
                self.successes[role, index] = 0
                if self.failures[role, index] >= FAILURE_STREAK:
                    self.malicious[role, index] = True
            else:
                self.failures[role, index] = 0
                self.successes[role, index] += 1
                if (
                    self.malicious[role, index]
                    and self.successes[role, index] >= RECOVERY_STREAK
                ):
                    self.malicious[role, index] = False
                    self.successes[role, index] = 0


def _bounds(book: _ArrayBook, role: int, indices):
    alpha = book.alpha[role, indices]
    beta = book.beta[role, indices]
    return (
        betaincinv(alpha, beta, LCB_QUANTILE),
        betaincinv(alpha, beta, 1.0 - LCB_QUANTILE),
    )


def _trusted(book: _ArrayBook, states: _DynamicStates, role: int, indices):
    lower, _ = _bounds(book, role, indices)
    return np.logical_and(lower >= TRUST_THRESHOLD, ~states.malicious[role, indices])


def _new_action_counts():
    return {
        "malicious_actions": 0,
        "honest_actions": 0,
        "malicious_trusted": 0,
        "honest_denied": 0,
        "state_tp": 0,
        "state_fn": 0,
        "state_fp": 0,
        "state_tn": 0,
        "trusted_actions": 0,
        "uncertain_actions": 0,
        "malicious_state_actions": 0,
    }


def _observe_actions(counts, actual_malicious, trusted, malicious_state):
    actual = np.asarray(actual_malicious, dtype=bool)
    trusted = np.asarray(trusted, dtype=bool)
    state = np.asarray(malicious_state, dtype=bool)
    counts["malicious_actions"] += int(np.sum(actual))
    counts["honest_actions"] += int(np.sum(~actual))
    counts["malicious_trusted"] += int(np.sum(actual & trusted))
    counts["honest_denied"] += int(np.sum((~actual) & (~trusted)))
    counts["state_tp"] += int(np.sum(actual & state))
    counts["state_fn"] += int(np.sum(actual & (~state)))
    counts["state_fp"] += int(np.sum((~actual) & state))
    counts["state_tn"] += int(np.sum((~actual) & (~state)))
    counts["trusted_actions"] += int(np.sum(trusted))
    counts["malicious_state_actions"] += int(np.sum(state))
    counts["uncertain_actions"] += int(np.sum((~trusted) & (~state)))


def _rates(prefix: str, counts):
    total = counts["malicious_actions"] + counts["honest_actions"]
    return {
        f"{prefix}_malicious_trusted_rate": (
            counts["malicious_trusted"] / counts["malicious_actions"]
            if counts["malicious_actions"]
            else math.nan
        ),
        f"{prefix}_honest_denied_rate": (
            counts["honest_denied"] / counts["honest_actions"]
            if counts["honest_actions"]
            else math.nan
        ),
        f"{prefix}_malicious_state_recall": (
            counts["state_tp"] / (counts["state_tp"] + counts["state_fn"])
            if counts["state_tp"] + counts["state_fn"]
            else math.nan
        ),
        f"{prefix}_malicious_state_fpr": (
            counts["state_fp"] / (counts["state_fp"] + counts["state_tn"])
            if counts["state_fp"] + counts["state_tn"]
            else math.nan
        ),
        f"{prefix}_trusted_coverage": counts["trusted_actions"] / total,
        f"{prefix}_uncertain_coverage": counts["uncertain_actions"] / total,
        f"{prefix}_malicious_state_coverage": counts["malicious_state_actions"] / total,
    }


def _apply_pending(single_book, single_states, dual_book, dual_states, item):
    provider, truth, reliability, recommenders, opinions = item
    provider_index = np.asarray([provider], dtype=int)
    provider_truth = np.asarray([truth], dtype=float)
    provider_weight = np.asarray([reliability], dtype=float)
    single_book.update(0, provider_index, provider_truth, provider_weight)
    dual_book.update(0, provider_index, provider_truth, provider_weight)
    single_states.observe(0, provider_index, provider_truth)
    dual_states.observe(0, provider_index, provider_truth)
    honesty = 1.0 - np.abs(opinions - truth)
    single_book.update(0, recommenders, honesty)
    dual_book.update(1, recommenders, honesty)
    single_states.observe(0, recommenders, honesty)
    dual_states.observe(1, recommenders, honesty)


def _event_metrics(actual: set[int], predicted: set[int], total: int):
    tp = len(actual & predicted)
    fn = len(actual - predicted)
    benign = set(range(total)) - actual
    fp = len(benign & predicted)
    tn = len(benign - predicted)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    malicious_f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_precision = tn / (tn + fn) if tn + fn else 0.0
    benign_recall = tn / (tn + fp) if tn + fp else 0.0
    benign_f1 = (
        2 * benign_precision * benign_recall / (benign_precision + benign_recall)
        if benign_precision + benign_recall
        else 0.0
    )
    return {
        "event_recall": recall,
        "event_fpr": fp / (fp + tn) if fp + tn else 0.0,
        "event_f1": malicious_f1,
        "event_macro_f1": (malicious_f1 + benign_f1) / 2,
    }


def run_cell(attack, trace, data_attackers, domains, overlap, seed, adjudication_delay=ADJUDICATION_DELAY, adjudication_error=0.0):
    identities = len(domains)
    opinion_attackers = select_opinion_attackers(
        frozenset(data_attackers), identities, overlap, seed
    )
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    single_book = _ArrayBook(identities, 1)
    dual_book = _ArrayBook(identities, 2)
    single_states = _DynamicStates(1, identities)
    dual_states = _DynamicStates(2, identities)
    pending = deque()
    actual_false = set()
    predicted_false = {variant: set() for variant in VARIANTS}
    action_counts = {
        variant: {"data": _new_action_counts(), "opinion": _new_action_counts()}
        for variant in VARIANTS
    }

    for event_index, (provider, attacker, malicious_probability, message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            _apply_pending(single_book, single_states, dual_book, dual_states, item)

        truth = 1.0 - attacker
        if attacker:
            actual_false.add(event_index)
        recommenders = _sample_recommenders(rng, provider, identities)
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

        single_provider_trusted = bool(_trusted(single_book, single_states, 0, provider))
        dual_provider_trusted = bool(_trusted(dual_book, dual_states, 0, provider))
        single_opinion_trusted = _trusted(single_book, single_states, 0, recommenders)
        dual_opinion_trusted = _trusted(dual_book, dual_states, 1, recommenders)

        for variant in VARIANTS:
            if variant == "single_role_three_state":
                provider_trusted = single_provider_trusted
                provider_state = single_states.malicious[0, provider]
                opinion_trusted = single_opinion_trusted
                opinion_state = single_states.malicious[0, recommenders]
            else:
                provider_trusted = dual_provider_trusted
                provider_state = dual_states.malicious[0, provider]
                opinion_trusted = dual_opinion_trusted
                opinion_state = dual_states.malicious[1, recommenders]
            _observe_actions(
                action_counts[variant]["data"],
                np.asarray([bool(attacker)]),
                np.asarray([provider_trusted]),
                np.asarray([provider_state]),
            )
            _observe_actions(
                action_counts[variant]["opinion"], inverted, opinion_trusted, opinion_state
            )

        single_lcb, single_ucb = _bounds(single_book, 0, provider)
        dual_lcb, dual_ucb = _bounds(dual_book, 0, provider)
        single_provider_mean = float(single_book.mean(0, provider))
        dual_provider_mean = float(dual_book.mean(0, provider))
        base_reliability = min(1.0, max(0.0, 1.0 - message_uncertainty))
        reliabilities = {
            "single_role_three_state": base_reliability * (1.0 - float(single_ucb - single_lcb)),
            "dual_role_mean_weight": base_reliability * (1.0 - float(dual_ucb - dual_lcb)),
            "dual_role_three_state": base_reliability * (1.0 - float(dual_ucb - dual_lcb)),
        }
        opinion_weights = {
            # Three-state variants now enforce the authority decision: a
            # failure-locked malicious recommender has zero fusion authority.
            # The mean-weight ablation is intentionally left ungated because
            # it is not the frozen three-state main method.
            "single_role_three_state": apply_malicious_authority_gate(
                single_book.lcb(0, recommenders),
                single_states.malicious[0, recommenders],
            ),
            "dual_role_mean_weight": dual_book.mean(1, recommenders),
            "dual_role_three_state": apply_malicious_authority_gate(
                dual_book.lcb(1, recommenders),
                dual_states.malicious[1, recommenders],
            ),
        }
        provider_means = {
            "single_role_three_state": single_provider_mean,
            "dual_role_mean_weight": dual_provider_mean,
            "dual_role_three_state": dual_provider_mean,
        }
        credibility_probability = 1.0 - malicious_probability
        for variant in VARIANTS:
            reliability = reliabilities[variant]
            fusion = domain_capped_fusion(
                opinions,
                recommender_domains,
                np.asarray(opinion_weights[variant]) * reliability,
            )
            if _event_is_false(
                credibility_probability,
                reliability,
                provider_means[variant],
                fusion,
            ):
                predicted_false[variant].add(event_index)

        delivered_truth = perturb_binary_truth(
            truth, seed=seed, event_index=event_index, error_rate=adjudication_error, tag=f'role:{attack}:{overlap}'
        )
        pending.append(
            (
                event_index + adjudication_delay,
                (provider, delivered_truth, base_reliability, recommenders, opinions),
            )
        )

    while pending:
        _, item = pending.popleft()
        _apply_pending(single_book, single_states, dual_book, dual_states, item)

    rows = []
    for variant in VARIANTS:
        rows.append(
            {
                "attack": attack,
                "overlap": overlap,
                "seed": seed,
                "variant": variant,
                **_rates("data", action_counts[variant]["data"]),
                **_rates("opinion", action_counts[variant]["opinion"]),
                **_event_metrics(actual_false, predicted_false[variant], len(trace)),
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


def _summaries(raw_rows):
    excluded = {"attack", "overlap", "seed", "variant", "messages", "identities", "data_attackers", "opinion_attackers"}
    metrics = [key for key in raw_rows[0] if key not in excluded]
    groups = {}
    for row in raw_rows:
        groups.setdefault((row["attack"], row["overlap"], row["variant"]), []).append(row)
    output = []
    for (attack, overlap, variant), rows in sorted(groups.items()):
        item = {"attack": attack, "overlap": overlap, "variant": variant, "repeats": len(rows)}
        for metric in metrics:
            values = [float(row[metric]) for row in rows if math.isfinite(float(row[metric]))]
            item[f"{metric}_mean"] = mean(values) if values else math.nan
            item[f"{metric}_sd"] = stdev(values) if len(values) > 1 else (0.0 if values else math.nan)
        output.append(item)
    return output


def _comparisons(raw_rows):
    indexed = {(row["attack"], row["overlap"], row["seed"], row["variant"]): row for row in raw_rows}
    output = []
    for attack in ATTACKS:
        for overlap in OVERLAPS:
            values = {
                "dual_vs_single_opinion_trusted_relative_reduction": [],
                "dual_minus_single_opinion_honest_denied": [],
                "dual_minus_single_event_macro_f1": [],
                "dual_minus_single_opinion_state_fpr": [],
                "lcb_vs_mean_opinion_trusted_relative_reduction": [],
                "lcb_minus_mean_event_macro_f1": [],
            }
            for seed in SEEDS:
                single = indexed[(attack, overlap, seed, "single_role_three_state")]
                dual_mean = indexed[(attack, overlap, seed, "dual_role_mean_weight")]
                dual = indexed[(attack, overlap, seed, "dual_role_three_state")]
                single_rate = single["opinion_malicious_trusted_rate"]
                mean_rate = dual_mean["opinion_malicious_trusted_rate"]
                dual_rate = dual["opinion_malicious_trusted_rate"]
                values["dual_vs_single_opinion_trusted_relative_reduction"].append(
                    (single_rate - dual_rate) / single_rate if single_rate > 0 else float(dual_rate == 0)
                )
                values["dual_minus_single_opinion_honest_denied"].append(
                    dual["opinion_honest_denied_rate"] - single["opinion_honest_denied_rate"]
                )
                values["dual_minus_single_event_macro_f1"].append(
                    dual["event_macro_f1"] - single["event_macro_f1"]
                )
                values["dual_minus_single_opinion_state_fpr"].append(
                    dual["opinion_malicious_state_fpr"] - single["opinion_malicious_state_fpr"]
                )
                values["lcb_vs_mean_opinion_trusted_relative_reduction"].append(
                    (mean_rate - dual_rate) / mean_rate if mean_rate > 0 else float(dual_rate == 0)
                )
                values["lcb_minus_mean_event_macro_f1"].append(
                    dual["event_macro_f1"] - dual_mean["event_macro_f1"]
                )
            row = {"attack": attack, "overlap": overlap}
            for metric, samples in values.items():
                row[f"{metric}_mean"] = mean(samples)
                row[f"{metric}_sd"] = stdev(samples)
            output.append(row)
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, default=min(10, os.cpu_count() or 4))
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    integrity_rows = []
    for attack, definition in ATTACKS.items():
        nested = (
            NESTED_ROOT / definition["holdout_folder"] / "Validation" / f"{definition['holdout_folder']}.zip"
        )
        md5 = _digest(nested, "md5")
        sha256 = _digest(nested)
        if md5 != definition["nested_md5"] or sha256 != definition["nested_sha256"]:
            raise ValueError(f"nested holdout archive mismatch for {attack}")
        integrity_rows.append({"attack": attack, "md5": md5, "sha256": sha256, "pass": 1})

    loaded = {"Train": {}, "Validation": {}, "Holdout": {}}
    holdout_metadata = {}
    audit_rows = []
    print("[load frozen highway development and untouched urban Validation]", flush=True)
    for split in ("Train", "Validation"):
        for attack, definition in ATTACKS.items():
            root = DEVELOPMENT_ROOT / definition["development_folder"] / split / "json"
            _, contextual, labels, audit = _load_phase9(root)
            loaded[split][attack] = (contextual, labels)
            audit_rows.append({
                "split": split.lower(), "attack": attack, "messages": len(labels),
                "attack_messages": int(np.sum(labels)), "identities": audit.sender_ids,
            })
    for attack, definition in ATTACKS.items():
        root = HOLDOUT_ROOT / definition["holdout_folder"] / "Validation" / "json"
        matrix, labels, sender_ids = _load_holdout(root)
        loaded["Holdout"][attack] = (matrix, labels)
        holdout_metadata[attack] = sender_ids
        audit_rows.append({
            "split": "urban_validation_holdout", "attack": attack,
            "messages": len(labels), "attack_messages": int(np.sum(labels)),
            "identities": len(set(sender_ids)),
        })

    x_train = np.concatenate([loaded["Train"][attack][0] for attack in ATTACKS])
    y_train = np.concatenate([loaded["Train"][attack][1] for attack in ATTACKS])
    x_validation = np.concatenate([loaded["Validation"][attack][0] for attack in ATTACKS])
    y_validation = np.concatenate([loaded["Validation"][attack][1] for attack in ATTACKS])
    x_holdout = np.concatenate([loaded["Holdout"][attack][0] for attack in ATTACKS])
    y_holdout = np.concatenate([loaded["Holdout"][attack][1] for attack in ATTACKS])

    print("[fit unchanged contextual ensemble and highway-only calibration]", flush=True)
    raw_validation, raw_holdout, _, uncertainty_holdout = _fit_ensemble(
        x_train, y_train, x_validation, x_holdout, 3000
    )
    calibration, calibrated_validation, calibrated_holdout, calibration_rows = _calibrate(
        raw_validation, raw_holdout, y_validation
    )
    threshold = select_fpr_constrained_threshold(
        y_validation, calibrated_validation, maximum_fpr=0.05
    )

    evidence_rows = []
    traces = {}
    start = 0
    prediction_rows = []
    for attack in ATTACKS:
        labels = loaded["Holdout"][attack][1]
        stop = start + len(labels)
        probabilities = calibrated_holdout[start:stop]
        uncertainties = uncertainty_holdout[start:stop]
        metrics = message_evidence_metrics(labels, probabilities, threshold=threshold)
        evidence_rows.append({
            "attack": attack, "calibration": calibration, "threshold": threshold,
            **asdict(metrics),
        })
        sender_ids = holdout_metadata[attack]
        identities = tuple(sorted(set(sender_ids)))
        identity_index = {identity: index for index, identity in enumerate(identities)}
        data_attackers = {
            identity_index[sender]
            for sender, label in zip(sender_ids, labels)
            if label
        }
        if len(data_attackers) > len(identities) - len(data_attackers):
            raise ValueError("not enough honest identities for zero-overlap opinion overlay")
        trace = []
        for index, (sender, label, probability, uncertainty) in enumerate(
            zip(sender_ids, labels, probabilities, uncertainties)
        ):
            prediction_rows.append({
                "attack": attack, "holdout_row": index, "attacker": int(label),
                "contextual_probability": float(probability),
                "contextual_uncertainty": float(uncertainty),
            })
            if index % SAMPLE_STRIDE == 0:
                trace.append((identity_index[sender], int(label), float(probability), float(uncertainty)))
        domains = tuple(_domain(identity) for identity in identities)
        traces[attack] = (tuple(trace), frozenset(data_attackers), domains)
        start = stop

    print("[run paired v3 three-state ablations]", flush=True)
    raw_rows = []
    futures = {}
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        for attack, (trace, data_attackers, domains) in traces.items():
            for overlap in OVERLAPS:
                for seed in SEEDS:
                    future = executor.submit(run_cell, attack, trace, data_attackers, domains, overlap, seed)
                    futures[future] = (attack, overlap, seed)
        for index, future in enumerate(as_completed(futures), 1):
            raw_rows.extend(future.result())
            print(f"  completed {index}/{len(futures)} paired cells", flush=True)

    raw_rows.sort(key=lambda row: (row["attack"], row["overlap"], row["seed"], row["variant"]))
    summaries = _summaries(raw_rows)
    comparisons = _comparisons(raw_rows)
    summary_index = {(row["attack"], row["overlap"], row["variant"]): row for row in summaries}
    comparison_index = {(row["attack"], row["overlap"]): row for row in comparisons}
    lcb_improvement_cells = sum(
        row["lcb_vs_mean_opinion_trusted_relative_reduction_mean"] > 0 for row in comparisons
    )
    stop = {
        "integrity_alignment_accounting_pass": 1,
        "dual_opinion_authorization_reduction_pass": int(all(
            comparison_index[(attack, overlap)]["dual_vs_single_opinion_trusted_relative_reduction_mean"] >= 0.15
            for attack in ATTACKS for overlap in (0.0, 0.5)
        )),
        "malicious_state_fpr_pass": int(all(
            summary_index[(attack, overlap, "dual_role_three_state")][f"{role}_malicious_state_fpr_mean"] <= 0.05
            for attack in ATTACKS for overlap in OVERLAPS for role in ("data", "opinion")
        )),
        "event_macro_f1_noninferiority_pass": int(all(
            row["dual_minus_single_event_macro_f1_mean"] >= -0.02 for row in comparisons
        )),
        "honest_opinion_denial_noninferiority_pass": int(all(
            row["dual_minus_single_opinion_honest_denied_mean"] <= 0.05 for row in comparisons
        )),
        "overlap_1_authorization_noninferiority_pass": int(all(
            summary_index[(attack, 1.0, "dual_role_three_state")]["opinion_malicious_trusted_rate_mean"]
            <= summary_index[(attack, 1.0, "single_role_three_state")]["opinion_malicious_trusted_rate_mean"] + 0.05
            for attack in ATTACKS
        )),
        "lcb_weighting_benefit_pass": int(
            lcb_improvement_cells >= 4
            and all(row["lcb_minus_mean_event_macro_f1_mean"] >= -0.02 for row in comparisons)
        ),
        "lcb_improvement_cells": lcb_improvement_cells,
    }
    stop["all_phase12_stop_lines_pass"] = int(
        all(value for key, value in stop.items() if key != "lcb_improvement_cells")
    )

    _write_csv(OUTPUT_DIR / "DURAC_phase12_integrity.csv", integrity_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_audit.csv", audit_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_calibration.csv", calibration_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_message_metrics.csv", evidence_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_holdout_predictions.csv", prediction_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_raw.csv", raw_rows)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_summary.csv", summaries)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_comparison.csv", comparisons)
    _write_csv(OUTPUT_DIR / "DURAC_phase12_stop_lines.csv", [stop])
    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "seeds": SEEDS,
        "sample_stride": SAMPLE_STRIDE,
        "threshold": threshold,
        "calibration": calibration,
        "outputs": {path.name: _digest(path) for path in sorted(OUTPUT_DIR.glob("*.csv"))},
    }
    with (OUTPUT_DIR / "DURAC_phase12_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    print("===== DURAC PHASE 12 V3 HOLDOUT =====")
    for row in comparisons:
        print(
            f"{row['attack']:18s} overlap={row['overlap']:.1f} "
            f"dual_auth_reduction={row['dual_vs_single_opinion_trusted_relative_reduction_mean']:+.4f} "
            f"honest_denial_delta={row['dual_minus_single_opinion_honest_denied_mean']:+.4f} "
            f"event_macro_delta={row['dual_minus_single_event_macro_f1_mean']:+.4f}"
        )
    print(json.dumps(stop, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
