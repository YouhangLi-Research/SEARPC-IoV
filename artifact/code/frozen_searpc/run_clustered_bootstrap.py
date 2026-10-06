#!/usr/bin/env python3
"""Recompute the clustered bootstrap clustered bootstrap from bundled predictions.

The official VeReMi archives are not redistributed.  The release therefore
ships the exact calibrated per-message probabilities and receiver/source-file
cluster keys used by the paper.  This runner fully regenerates the clustered
bootstrap intervals and paired differences from those bundled data.  A raw-data
training path remains available through the legacy module when the official
archives are supplied separately.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
from pathlib import Path
import shutil

import numpy as np

from durac import message_evidence_metrics
from run_clustered_bootstrap_raw import (
    BOOTSTRAP_SEED,
    DEFAULT_REPLICATES,
    DIRECTION,
    METHODS,
    METRICS,
    _cluster_codes,
    _metric_arrays,
    _point_row,
    _stratified_cluster_weights,
)
from run_temporal_evaluation import _write_csv


SCRIPT_DIR = Path(__file__).resolve().parent
EXPERIMENT_ROOT = SCRIPT_DIR.parents[1]
PROTOCOL = EXPERIMENT_ROOT / "protocols" / "frozen" / "SEARPC_CLUSTERED_BOOTSTRAP_PROTOCOL.md"
PREDICTIONS = EXPERIMENT_ROOT / "data" / "derived" / "SEARPC_clustered_receiver_predictions.csv.gz"
CANONICAL_DIR = EXPERIMENT_ROOT / "results" / "rq1"
OUT = EXPERIMENT_ROOT / "results" / "recomputed" / "rq1_phase21"
THRESHOLDS = {
    "durac_ensemble": 0.5333333333333333,
    "random_forest": 0.5229357798165137,
    "single_hgbdt": 0.47368421052631576,
}
CALIBRATIONS = {method: "isotonic" for method in METHODS}


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_predictions(path: Path):
    attacks: list[str] = []
    keys: list[str] = []
    labels: list[int] = []
    predictions = {method: [] for method in METHODS}
    with gzip.open(path, "rt", newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            attacks.append(row["attack"])
            keys.append(row["receiver_file"])
            labels.append(int(row["attacker"]))
            for method in METHODS:
                predictions[method].append(float(row[method]))
    return (
        np.asarray(attacks, dtype=object),
        np.asarray(keys, dtype=object),
        np.asarray(labels, dtype=int),
        {method: np.asarray(values, dtype=float) for method, values in predictions.items()},
    )


def recompute(*, prediction_path: Path, output_dir: Path, replicates: int,
              compare_canonical: bool) -> None:
    if replicates < 1:
        raise ValueError("replicates must be positive")
    output_dir.mkdir(parents=True, exist_ok=True)
    row_attacks, receiver_keys, labels, predictions = _load_predictions(prediction_path)
    attack_names = tuple(dict.fromkeys(row_attacks.tolist()))

    interval_rows: list[dict] = []
    difference_rows: list[dict] = []
    cluster_rows: list[dict] = []
    verification_rows: list[dict] = []
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    scopes: list[tuple[str, str, np.ndarray]] = [
        ("pooled_external_test", "all", np.arange(len(labels)))
    ]
    scopes.extend(
        ("attack_external_test", attack, np.flatnonzero(row_attacks == attack))
        for attack in attack_names
    )

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
                labels[indices], predictions[method][indices], THRESHOLDS[method],
                codes, len(unique_keys), weights,
            )
            method_values[method] = values
            interval_rows.extend(_point_row(scope, attack, method, values))
            direct = message_evidence_metrics(
                labels[indices], predictions[method][indices], threshold=THRESHOLDS[method]
            )
            maximum_error = max(
                abs(float(getattr(direct, metric)) - float(values[metric][0]))
                for metric in METRICS
            )
            verification_rows.append({
                "scope": scope,
                "attack": attack,
                "method": method,
                "maximum_absolute_error": maximum_error,
                "pass": int(maximum_error <= 1e-12),
            })
        for baseline in ("random_forest", "single_hgbdt"):
            for metric in METRICS:
                difference = DIRECTION[metric] * (
                    method_values["durac_ensemble"][metric]
                    - method_values[baseline][metric]
                )
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
        "clusters": output_dir / "SEARPC_clustered_cluster_accounting.csv",
        "verification": output_dir / "SEARPC_clustered_point_verification.csv",
        "intervals": output_dir / "SEARPC_clustered_method_intervals.csv",
        "differences": output_dir / "SEARPC_clustered_paired_differences.csv",
        "predictions": output_dir / "SEARPC_clustered_receiver_predictions.csv.gz",
    }
    _write_csv(paths["clusters"], cluster_rows)
    _write_csv(paths["verification"], verification_rows)
    _write_csv(paths["intervals"], interval_rows)
    _write_csv(paths["differences"], difference_rows)
    shutil.copyfile(prediction_path, paths["predictions"])

    comparison = {}
    if compare_canonical and replicates == DEFAULT_REPLICATES:
        canonical_map = {
            "clusters": CANONICAL_DIR / "SEARPC_clustered_cluster_accounting.csv",
            "intervals": CANONICAL_DIR / "SEARPC_clustered_method_intervals.csv",
            "differences": CANONICAL_DIR / "SEARPC_clustered_paired_differences.csv",
        }
        for name, canonical in canonical_map.items():
            generated = paths[name]
            comparison[name] = {
                "generated_sha256": _digest(generated),
                "canonical_sha256": _digest(canonical),
                "exact_match": _digest(generated) == _digest(canonical),
            }
        (output_dir / "SEARPC_clustered_canonical_comparison.json").write_text(
            json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    manifest = {
        "mode": "bundled calibrated predictions",
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "prediction_sha256": _digest(prediction_path),
        "bootstrap_seed": BOOTSTRAP_SEED,
        "bootstrap_replicates": replicates,
        "cluster_unit": "official receiver/source JSON file",
        "attack_stratified": True,
        "paired_across_methods": True,
        "calibrations": CALIBRATIONS,
        "thresholds": THRESHOLDS,
        "point_metric_reproduction_pass": all(row["pass"] for row in verification_rows),
        "outputs": {name: {"path": str(path), "sha256": _digest(path)} for name, path in paths.items()},
    }
    manifest_path = output_dir / "SEARPC_clustered_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "comparison": comparison,
                      "clusters": cluster_rows}, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Regenerate RQ1 clustered-bootstrap results from bundled predictions."
    )
    parser.add_argument("--predictions", type=Path, default=PREDICTIONS)
    parser.add_argument("--output-dir", type=Path, default=OUT)
    parser.add_argument("--replicates", type=int, default=DEFAULT_REPLICATES)
    parser.add_argument("--quick", action="store_true", help="use 50 bootstrap replicates")
    parser.add_argument("--compare-canonical", action="store_true")
    args = parser.parse_args(argv)
    recompute(
        prediction_path=args.predictions,
        output_dir=args.output_dir,
        replicates=50 if args.quick else args.replicates,
        compare_canonical=args.compare_canonical,
    )


if __name__ == "__main__":
    main()
