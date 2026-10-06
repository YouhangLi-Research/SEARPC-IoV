#!/usr/bin/env python3
"""Receiver-file clustered bootstrap for the frozen matched external baselines comparison."""

from __future__ import annotations

from dataclasses import asdict
import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_sample_weight

from durac import iter_veremi_json, message_evidence_metrics, select_fpr_constrained_threshold
from run_temporal_evaluation import (
    SEED,
    _calibrate,
    _digest,
    _fit_ensemble,
    _hist_model,
    _write_csv,
)
from run_context_evaluation import ATTACKS, EXTERNAL_ROOT
from run_matched_external_baselines import _load_registered_data


ROOT = Path(__file__).resolve().parent
OUT = ROOT / "results/durac_phase21_clustered_bootstrap"
PROTOCOL = ROOT / "SEARPC_CLUSTERED_BOOTSTRAP_PROTOCOL.md"
PHASE20_METRICS = ROOT / "results/durac_phase20_matched_external_baselines/SEARPC_external_metrics.csv"
BOOTSTRAP_SEED = 260826
DEFAULT_REPLICATES = 2_000
METHODS = ("random_forest", "single_hgbdt", "durac_ensemble")
METRICS = ("macro_f1", "malicious_recall", "false_positive_rate", "pr_auc", "brier_score", "ece_15")
DIRECTION = {
    "macro_f1": 1.0,
    "malicious_recall": 1.0,
    "false_positive_rate": -1.0,
    "pr_auc": 1.0,
    "brier_score": -1.0,
    "ece_15": -1.0,
}


def _receiver_keys(root: Path, attack: str) -> np.ndarray:
    keys: list[str] = []
    for file_path in sorted(root.rglob("*.json")):
        count = sum(1 for _ in iter_veremi_json(file_path))
        key = f"{attack}::{file_path.relative_to(root).as_posix()}"
        keys.extend([key] * count)
    return np.asarray(keys, dtype=object)


def _stratified_cluster_weights(
    cluster_attacks: np.ndarray,
    replicates: int,
    rng: np.random.Generator,
) -> np.ndarray:
    if replicates < 1:
        raise ValueError("replicates must be positive")
    attacks = np.asarray(cluster_attacks, dtype=object)
    weights = np.zeros((replicates, len(attacks)), dtype=np.int16)
    rows = np.arange(replicates)
    for attack in sorted(set(attacks.tolist())):
        positions = np.flatnonzero(attacks == attack)
        if len(positions) < 2:
            raise ValueError("each attack must contain at least two clusters")
        draws = rng.integers(0, len(positions), size=(replicates, len(positions)))
        selected = positions[draws]
        np.add.at(
            weights,
            (np.repeat(rows, len(positions)), selected.reshape(-1)),
            1,
        )
    return weights


def _cluster_codes(keys: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    unique, codes = np.unique(np.asarray(keys, dtype=object), return_inverse=True)
    attacks = np.asarray([str(key).split("::", 1)[0] for key in unique], dtype=object)
    return unique, codes.astype(int), attacks


def _metric_arrays(
    labels: np.ndarray,
    probabilities: np.ndarray,
    threshold: float,
    codes: np.ndarray,
    cluster_count: int,
    weights: np.ndarray,
) -> dict[str, np.ndarray]:
    y = np.asarray(labels, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    predicted = p >= threshold
    positive = y == 1
    negative = ~positive

    totals = np.zeros((cluster_count, 6), dtype=float)
    np.add.at(totals[:, 0], codes, predicted & positive)   # TP
    np.add.at(totals[:, 1], codes, (~predicted) & positive)  # FN
    np.add.at(totals[:, 2], codes, predicted & negative)   # FP
    np.add.at(totals[:, 3], codes, (~predicted) & negative)  # TN
    np.add.at(totals[:, 4], codes, (p - y) ** 2)           # Brier numerator
    np.add.at(totals[:, 5], codes, 1.0)                    # messages
    aggregate = weights @ totals
    tp, fn, fp, tn, brier_sum, messages = aggregate.T

    precision = np.divide(tp, tp + fp, out=np.zeros_like(tp), where=(tp + fp) > 0)
    recall = np.divide(tp, tp + fn, out=np.zeros_like(tp), where=(tp + fn) > 0)
    malicious_f1 = np.divide(
        2.0 * precision * recall,
        precision + recall,
        out=np.zeros_like(tp),
        where=(precision + recall) > 0,
    )
    negative_precision = np.divide(tn, tn + fn, out=np.zeros_like(tn), where=(tn + fn) > 0)
    negative_recall = np.divide(tn, tn + fp, out=np.zeros_like(tn), where=(tn + fp) > 0)
    negative_f1 = np.divide(
        2.0 * negative_precision * negative_recall,
        negative_precision + negative_recall,
        out=np.zeros_like(tn),
        where=(negative_precision + negative_recall) > 0,
    )

    bins = np.minimum(np.digitize(p, np.linspace(0.0, 1.0, 16)[1:-1], right=False), 14)
    calibration = np.zeros((cluster_count, 15, 3), dtype=float)
    np.add.at(calibration[:, :, 0], (codes, bins), 1.0)
    np.add.at(calibration[:, :, 1], (codes, bins), y)
    np.add.at(calibration[:, :, 2], (codes, bins), p)
    bin_count = weights @ calibration[:, :, 0]
    bin_positive = weights @ calibration[:, :, 1]
    bin_probability = weights @ calibration[:, :, 2]
    ece = np.sum(np.abs(bin_probability - bin_positive), axis=1) / messages

    unique_scores, score_codes = np.unique(p, return_inverse=True)
    descending_codes = len(unique_scores) - 1 - score_codes
    positives_by_score = np.zeros((cluster_count, len(unique_scores)), dtype=float)
    negatives_by_score = np.zeros_like(positives_by_score)
    np.add.at(positives_by_score, (codes, descending_codes), positive)
    np.add.at(negatives_by_score, (codes, descending_codes), negative)
    weighted_positive = weights @ positives_by_score
    weighted_negative = weights @ negatives_by_score
    cumulative_tp = np.cumsum(weighted_positive, axis=1)
    cumulative_fp = np.cumsum(weighted_negative, axis=1)
    ranked_precision = np.divide(
        cumulative_tp,
        cumulative_tp + cumulative_fp,
        out=np.zeros_like(cumulative_tp),
        where=(cumulative_tp + cumulative_fp) > 0,
    )
    total_positive = cumulative_tp[:, -1]
    pr_auc = np.divide(
        np.sum(weighted_positive * ranked_precision, axis=1),
        total_positive,
        out=np.zeros_like(total_positive),
        where=total_positive > 0,
    )

    return {
        "macro_f1": (malicious_f1 + negative_f1) / 2.0,
        "malicious_recall": recall,
        "false_positive_rate": np.divide(fp, fp + tn, out=np.zeros_like(fp), where=(fp + tn) > 0),
        "pr_auc": pr_auc,
        "brier_score": brier_sum / messages,
        "ece_15": ece,
    }


def _point_row(scope: str, attack: str, method: str, values: dict[str, np.ndarray]) -> list[dict]:
    rows = []
    for metric in METRICS:
        samples = values[metric][1:]
        rows.append(
            {
                "scope": scope,
                "attack": attack,
                "method": method,
                "metric": metric,
                "estimate": float(values[metric][0]),
                "ci95_low": float(np.percentile(samples, 2.5)),
                "ci95_high": float(np.percentile(samples, 97.5)),
                "bootstrap_replicates": len(samples),
            }
        )
    return rows


def _write_predictions(
    path: Path,
    attacks: np.ndarray,
    receiver_keys: np.ndarray,
    labels: np.ndarray,
    predictions: dict[str, np.ndarray],
) -> None:
    fields = ["attack", "receiver_file", "attacker", *METHODS]
    with gzip.open(path, "wt", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(fields)
        for index in range(len(labels)):
            writer.writerow(
                [
                    attacks[index],
                    receiver_keys[index],
                    int(labels[index]),
                    *(float(predictions[method][index]) for method in METHODS),
                ]
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES)
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    replicates = 50 if args.quick else args.replicates
    OUT.mkdir(parents=True, exist_ok=True)

    loaded, _, _ = _load_registered_data()
    pooled = {
        split: (
            np.concatenate([loaded[split][attack][0] for attack in ATTACKS]),
            np.concatenate([loaded[split][attack][1] for attack in ATTACKS]),
        )
        for split in ("Train", "Validation", "Test")
    }
    x_train, y_train = pooled["Train"]
    x_validation, y_validation = pooled["Validation"]
    x_test, y_test = pooled["Test"]

    raw: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    forest = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=5,
        class_weight="balanced_subsample",
        random_state=SEED,
        n_jobs=-1,
    )
    forest.fit(x_train, y_train)
    raw["random_forest"] = (forest.predict_proba(x_validation)[:, 1], forest.predict_proba(x_test)[:, 1])
    hgbdt = _hist_model(SEED)
    hgbdt.fit(x_train, y_train, sample_weight=compute_sample_weight("balanced", y_train))
    raw["single_hgbdt"] = (hgbdt.predict_proba(x_validation)[:, 1], hgbdt.predict_proba(x_test)[:, 1])
    durac_validation, durac_test, _, _ = _fit_ensemble(x_train, y_train, x_validation, x_test, 3000)
    raw["durac_ensemble"] = (durac_validation, durac_test)

    predictions: dict[str, np.ndarray] = {}
    thresholds: dict[str, float] = {}
    calibrations: dict[str, str] = {}
    for method in METHODS:
        calibration, validation, test, _ = _calibrate(raw[method][0], raw[method][1], y_validation)
        calibrations[method] = calibration
        predictions[method] = test
        thresholds[method] = select_fpr_constrained_threshold(y_validation, validation, maximum_fpr=0.05)

    receiver_parts = []
    attack_parts = []
    slices: dict[str, slice] = {}
    start = 0
    for attack, definition in ATTACKS.items():
        root = EXTERNAL_ROOT / definition["external_folder"] / "Test" / "json"
        keys = _receiver_keys(root, attack)
        expected = len(loaded["Test"][attack][1])
        if len(keys) != expected:
            raise ValueError(f"receiver-file accounting mismatch for {attack}: {len(keys)} != {expected}")
        receiver_parts.append(keys)
        attack_parts.append(np.repeat(attack, expected))
        slices[attack] = slice(start, start + expected)
        start += expected
    receiver_keys = np.concatenate(receiver_parts)
    row_attacks = np.concatenate(attack_parts)

    phase20_rows = list(csv.DictReader(PHASE20_METRICS.open(encoding="utf-8")))
    verification_rows = []
    for method in METHODS:
        for attack in ("all", *ATTACKS):
            selection = slice(None) if attack == "all" else slices[attack]
            observed = asdict(message_evidence_metrics(y_test[selection], predictions[method][selection], threshold=thresholds[method]))
            scope = "pooled_external_test" if attack == "all" else "attack_external_test"
            registered = next(
                row for row in phase20_rows
                if row["scope"] == scope and row["attack"] == attack and row["method"] == method and row["representation"] == "calibrated"
            )
            maximum_error = max(abs(float(registered[metric]) - float(observed[metric])) for metric in METRICS)
            verification_rows.append({"scope": scope, "attack": attack, "method": method, "maximum_absolute_error": maximum_error, "pass": int(maximum_error <= 1e-12)})
    if not all(row["pass"] for row in verification_rows):
        raise ValueError("Phase 21 failed to reproduce a Phase 20 point estimate")

    prediction_path = OUT / "SEARPC_clustered_receiver_predictions.csv.gz"
    _write_predictions(prediction_path, row_attacks, receiver_keys, y_test, predictions)

    interval_rows: list[dict] = []
    difference_rows: list[dict] = []
    cluster_rows: list[dict] = []
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    scopes = [("pooled_external_test", "all", np.arange(len(y_test)))] + [
        ("attack_external_test", attack, np.arange(slices[attack].start, slices[attack].stop))
        for attack in ATTACKS
    ]
    for scope, attack, indices in scopes:
        keys = receiver_keys[indices]
        unique_keys, codes, cluster_attacks = _cluster_codes(keys)
        bootstrap = _stratified_cluster_weights(cluster_attacks, replicates, rng)
        weights = np.vstack([np.ones((1, len(unique_keys)), dtype=np.int16), bootstrap])
        cluster_rows.append({
            "scope": scope,
            "attack": attack,
            "messages": len(indices),
            "receiver_file_clusters": len(unique_keys),
            "bootstrap_replicates": replicates,
        })
        method_values: dict[str, dict[str, np.ndarray]] = {}
        for method in METHODS:
            values = _metric_arrays(
                y_test[indices], predictions[method][indices], thresholds[method], codes, len(unique_keys), weights
            )
            method_values[method] = values
            interval_rows.extend(_point_row(scope, attack, method, values))
        for baseline in ("random_forest", "single_hgbdt"):
            for metric in METRICS:
                difference = DIRECTION[metric] * (method_values["durac_ensemble"][metric] - method_values[baseline][metric])
                samples = difference[1:]
                difference_rows.append({
                    "scope": scope,
                    "attack": attack,
                    "baseline": baseline,
                    "metric": metric,
                    "direction": "positive_means_DURAC_better",
                    "oriented_difference": float(difference[0]),
                    "ci95_low": float(np.percentile(samples, 2.5)),
                    "ci95_high": float(np.percentile(samples, 97.5)),
                    "supports_DURAC_advantage": int(float(np.percentile(samples, 2.5)) > 0.0),
                    "bootstrap_replicates": replicates,
                })

    paths = {
        "clusters": OUT / "SEARPC_clustered_cluster_accounting.csv",
        "verification": OUT / "SEARPC_clustered_point_verification.csv",
        "intervals": OUT / "SEARPC_clustered_method_intervals.csv",
        "differences": OUT / "SEARPC_clustered_paired_differences.csv",
        "predictions": prediction_path,
    }
    _write_csv(paths["clusters"], cluster_rows)
    _write_csv(paths["verification"], verification_rows)
    _write_csv(paths["intervals"], interval_rows)
    _write_csv(paths["differences"], difference_rows)
    manifest = {
        "protocol_status": "frozen receiver-file clustered bootstrap",
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "phase20_metrics_sha256": _digest(PHASE20_METRICS),
        "bootstrap_seed": BOOTSTRAP_SEED,
        "bootstrap_replicates": replicates,
        "cluster_unit": "official receiver/source JSON file",
        "attack_stratified": True,
        "paired_across_methods": True,
        "calibrations": calibrations,
        "thresholds": thresholds,
        "phase20_reproduction_pass": all(row["pass"] for row in verification_rows),
        "outputs": {name: {"path": str(path.relative_to(ROOT)), "sha256": _digest(path)} for name, path in paths.items()},
    }
    manifest_path = OUT / "SEARPC_clustered_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "clusters": cluster_rows}, indent=2))


if __name__ == "__main__":
    main()
