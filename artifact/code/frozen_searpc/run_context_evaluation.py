#!/usr/bin/env python3
"""Preregistered context evaluation receiver-context cross-environment test."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path

import numpy as np

from durac import (
    CONTEXTUAL_FEATURE_NAMES,
    TEMPORAL_FEATURE_NAMES,
    audit_veremi_directory,
    iter_veremi_contextual_directory,
    message_evidence_metrics,
    select_fpr_constrained_threshold,
    uncertainty_diagnostics,
)
from run_temporal_evaluation import (
    INSTANTANEOUS_FEATURE_NAMES,
    PROHIBITED_RAW_FEATURES,
    SEED,
    _calibrate,
    _digest,
    _fit_ensemble,
    _write_csv,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[4]
DEVELOPMENT_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_DEVELOPMENT_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase8",
    )
)
EXTERNAL_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_EXTERNAL_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase9",
    )
)
ARCHIVE_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_PHASE9_ARCHIVE_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase9_archives",
    )
)
OUTPUT_DIR = Path("results/durac_phase9_context_external")
PROTOCOL = Path("SEARPC_CONTEXT_EXTERNAL_PROTOCOL.md")
DATASET_IMPLEMENTATION = Path("durac/datasets.py")
EVIDENCE_IMPLEMENTATION = Path("durac/message_evidence.py")

ATTACKS = {
    "dataReplay": {
        "development_folder": "InTAS_highway_2_dataReplay",
        "external_folder": "InTAS_urban_2_dataReplay",
        "md5": "3f3d752b4169475ebc5cb17fd8fa59cd",
    },
    "timeDelayAttack": {
        "development_folder": "InTAS_highway_2_timeDelayAttack",
        "external_folder": "InTAS_urban_2_timeDelayAttack",
        "md5": "c5fa8415f36807639e52ddcc5f473878",
    },
}


def _load(root: Path):
    audit = audit_veremi_directory(root)
    if audit.feature_names != INSTANTANEOUS_FEATURE_NAMES:
        raise ValueError("instantaneous schema differs from the frozen schema")
    temporal_names = INSTANTANEOUS_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES
    contextual_names = temporal_names + CONTEXTUAL_FEATURE_NAMES
    if PROHIBITED_RAW_FEATURES & set(contextual_names):
        raise ValueError("a prohibited raw field reached a design matrix")

    temporal_rows = []
    contextual_rows = []
    labels = []
    for example in iter_veremi_contextual_directory(root):
        physical = example.record.physical_features()
        temporal = [physical[name] for name in INSTANTANEOUS_FEATURE_NAMES] + [
            example.temporal_features[name] for name in TEMPORAL_FEATURE_NAMES
        ]
        contextual = temporal + [
            example.contextual_features[name] for name in CONTEXTUAL_FEATURE_NAMES
        ]
        temporal_rows.append(temporal)
        contextual_rows.append(contextual)
        labels.append(example.record.attacker)

    x_temporal = np.asarray(temporal_rows, dtype=float)
    x_contextual = np.asarray(contextual_rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    if x_temporal.shape != (audit.messages, len(temporal_names)):
        raise ValueError("temporal matrix does not account for every message")
    if x_contextual.shape != (audit.messages, len(contextual_names)):
        raise ValueError("context matrix does not account for every message")
    if not np.isfinite(x_temporal).all() or not np.isfinite(x_contextual).all():
        raise ValueError("a matrix contains a non-finite value")
    return x_temporal, x_contextual, y, audit


def _metric_row(scope, attack, method, calibration, labels, probabilities, threshold):
    return {
        "scope": scope,
        "attack": attack,
        "method": method,
        "calibration": calibration,
        "messages": int(len(labels)),
        "attack_rate": float(np.mean(labels)),
        **asdict(
            message_evidence_metrics(
                labels, probabilities, threshold=threshold
            )
        ),
    }


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    archive_rows = []
    for attack, definition in ATTACKS.items():
        archive = ARCHIVE_ROOT / f"{definition['external_folder']}.zip"
        observed_md5 = _digest(archive, "md5")
        if observed_md5 != definition["md5"]:
            raise ValueError(f"official archive MD5 mismatch for {attack}")
        archive_rows.append(
            {
                "attack": attack,
                "archive": archive.name,
                "official_md5": definition["md5"],
                "observed_md5": observed_md5,
                "sha256": _digest(archive),
                "md5_pass": 1,
            }
        )

    loaded: dict[str, dict[str, tuple]] = {
        "Train": {},
        "Validation": {},
        "Test": {},
    }
    audit_rows = []
    print("[load highway development and unseen urban Test]", flush=True)
    for split in ("Train", "Validation", "Test"):
        for attack, definition in ATTACKS.items():
            if split == "Test":
                root = EXTERNAL_ROOT / definition["external_folder"] / "Test" / "json"
                environment = "urban_2_external"
            else:
                root = DEVELOPMENT_ROOT / definition["development_folder"] / split / "json"
                environment = "highway_2_development"
            print(f"  {split:10s} {attack:18s} {environment}", flush=True)
            x_temporal, x_contextual, y, audit = _load(root)
            loaded[split][attack] = (x_temporal, x_contextual, y)
            audit_rows.append(
                {
                    "split": split.lower(),
                    "environment": environment,
                    "attack": attack,
                    "json_files": audit.json_files,
                    "messages": audit.messages,
                    "attack_messages": audit.attack_messages,
                    "attack_rate": audit.attack_rate,
                    "sender_ids": audit.sender_ids,
                    "sender_aliases": audit.sender_aliases,
                    "driver_profiles": "|".join(audit.driver_profiles),
                    "temporal_feature_count": len(INSTANTANEOUS_FEATURE_NAMES)
                    + len(TEMPORAL_FEATURE_NAMES),
                    "contextual_feature_count": len(CONTEXTUAL_FEATURE_NAMES),
                    "prohibited_feature_count": len(
                        PROHIBITED_RAW_FEATURES
                        & set(
                            INSTANTANEOUS_FEATURE_NAMES
                            + TEMPORAL_FEATURE_NAMES
                            + CONTEXTUAL_FEATURE_NAMES
                        )
                    ),
                }
            )

    pooled = {}
    test_slices = {}
    for split in ("Train", "Validation", "Test"):
        pooled[split] = tuple(
            np.concatenate([loaded[split][attack][index] for attack in ATTACKS])
            for index in range(3)
        )
        if split == "Test":
            start = 0
            for attack in ATTACKS:
                length = len(loaded[split][attack][2])
                test_slices[attack] = slice(start, start + length)
                start += length

    x_t_train, x_c_train, y_train = pooled["Train"]
    x_t_validation, x_c_validation, y_validation = pooled["Validation"]
    x_t_test, x_c_test, y_test = pooled["Test"]

    print("[fit Phase 8 temporal baseline]", flush=True)
    t_raw_val, t_raw_test, _, t_uncertainty_test = _fit_ensemble(
        x_t_train, y_train, x_t_validation, x_t_test, 2000
    )
    print("[fit Phase 9 contextual ensemble]", flush=True)
    c_raw_val, c_raw_test, _, c_uncertainty_test = _fit_ensemble(
        x_c_train, y_train, x_c_validation, x_c_test, 3000
    )

    print("[validation-only calibration and threshold selection]", flush=True)
    t_cal_name, t_cal_val, t_cal_test, t_cal_rows = _calibrate(
        t_raw_val, t_raw_test, y_validation
    )
    c_cal_name, c_cal_val, c_cal_test, c_cal_rows = _calibrate(
        c_raw_val, c_raw_test, y_validation
    )
    probability_sets = {
        "temporal_raw": (t_raw_val, t_raw_test, "none"),
        "temporal_calibrated": (t_cal_val, t_cal_test, t_cal_name),
        "contextual_raw": (c_raw_val, c_raw_test, "none"),
        "contextual_calibrated": (c_cal_val, c_cal_test, c_cal_name),
    }
    thresholds = {
        method: select_fpr_constrained_threshold(
            y_validation, validation_probability, maximum_fpr=0.05
        )
        for method, (validation_probability, _, _) in probability_sets.items()
    }

    metric_rows = []
    for method, (validation_probability, test_probability, calibration) in probability_sets.items():
        threshold = thresholds[method]
        metric_rows.append(
            _metric_row(
                "pooled_validation", "all", method, calibration,
                y_validation, validation_probability, threshold,
            )
        )
        metric_rows.append(
            _metric_row(
                "pooled_external_test", "all", method, calibration,
                y_test, test_probability, threshold,
            )
        )
        for attack, attack_slice in test_slices.items():
            metric_rows.append(
                _metric_row(
                    "attack_external_test", attack, method, calibration,
                    y_test[attack_slice], test_probability[attack_slice], threshold,
                )
            )

    calibration_rows = [
        {"method": "temporal", **row, "selected": int(row["calibration"] == t_cal_name)}
        for row in t_cal_rows
    ] + [
        {"method": "contextual", **row, "selected": int(row["calibration"] == c_cal_name)}
        for row in c_cal_rows
    ]
    indexed = {
        (row["scope"], row["attack"], row["method"]): row
        for row in metric_rows
    }
    temporal_pooled = indexed[
        ("pooled_external_test", "all", "temporal_calibrated")
    ]
    context_pooled = indexed[
        ("pooled_external_test", "all", "contextual_calibrated")
    ]
    context_raw_pooled = indexed[
        ("pooled_external_test", "all", "contextual_raw")
    ]
    comparison_rows = []
    noninferiority_pass = True
    improvement_pass = True
    per_attack_operating_pass = True
    for attack in ATTACKS:
        temporal = indexed[
            ("attack_external_test", attack, "temporal_calibrated")
        ]
        context = indexed[
            ("attack_external_test", attack, "contextual_calibrated")
        ]
        improvement = context["pr_auc"] - temporal["pr_auc"]
        attack_noninferior = context["pr_auc"] >= temporal["pr_auc"] - 0.01
        attack_improved = improvement >= 0.05
        operating = (
            context["malicious_recall"] >= 0.60
            and context["false_positive_rate"] <= 0.05
        )
        noninferiority_pass &= attack_noninferior
        improvement_pass &= attack_improved
        per_attack_operating_pass &= operating
        comparison_rows.append(
            {
                "attack": attack,
                "temporal_pr_auc": temporal["pr_auc"],
                "contextual_pr_auc": context["pr_auc"],
                "contextual_minus_temporal_pr_auc": improvement,
                "noninferiority_pass": int(attack_noninferior),
                "improvement_0_05_pass": int(attack_improved),
                "contextual_recall": context["malicious_recall"],
                "contextual_fpr": context["false_positive_rate"],
                "operating_point_pass": int(operating),
            }
        )

    context_threshold = thresholds["contextual_calibrated"]
    uncertainty = uncertainty_diagnostics(
        y_test,
        c_cal_test,
        c_uncertainty_test,
        threshold=context_threshold,
    )
    uncertainty["temporal_mean_uncertainty"] = float(
        t_uncertainty_test.mean()
    )
    ece_reduction = (
        1.0 - context_pooled["ece_15"] / context_raw_pooled["ece_15"]
        if context_raw_pooled["ece_15"]
        else 0.0
    )
    accounting_pass = all(
        row["messages"]
        == len(loaded[row["split"].capitalize()][row["attack"]][2])
        for row in audit_rows
    )
    uncertainty_pass = (
        uncertainty["uncertainty_error_roc_auc"] >= 0.60
        or uncertainty["top_to_bottom_error_ratio"] >= 2.0
    )
    checks = {
        "archive_integrity_pass": all(row["md5_pass"] for row in archive_rows),
        "accounting_and_finite_pass": accounting_pass,
        "no_prohibited_features_and_state_isolation_pass": all(
            row["prohibited_feature_count"] == 0 for row in audit_rows
        ),
        "per_attack_pr_noninferiority_pass": noninferiority_pass,
        "both_attack_pr_improvement_pass": improvement_pass,
        "pooled_operating_point_pass": (
            context_pooled["malicious_recall"] >= 0.70
            and context_pooled["false_positive_rate"] <= 0.05
        ),
        "every_attack_operating_point_pass": per_attack_operating_pass,
        "ece_improvement_pass": ece_reduction >= 0.10,
        "uncertainty_signal_pass": uncertainty_pass,
    }
    stop_row = {
        **{name: int(value) for name, value in checks.items()},
        "temporal_calibration": t_cal_name,
        "contextual_calibration": c_cal_name,
        "temporal_threshold": thresholds["temporal_calibrated"],
        "contextual_threshold": context_threshold,
        "temporal_pooled_test_pr_auc": temporal_pooled["pr_auc"],
        "contextual_pooled_test_pr_auc": context_pooled["pr_auc"],
        "contextual_minus_temporal_pr_auc": (
            context_pooled["pr_auc"] - temporal_pooled["pr_auc"]
        ),
        "contextual_raw_test_ece": context_raw_pooled["ece_15"],
        "contextual_calibrated_test_ece": context_pooled["ece_15"],
        "ece_relative_reduction": ece_reduction,
        "contextual_pooled_test_recall": context_pooled["malicious_recall"],
        "contextual_pooled_test_fpr": context_pooled["false_positive_rate"],
        **uncertainty,
        "all_phase9_stop_lines_pass": int(all(checks.values())),
    }

    prediction_rows = []
    for attack, attack_slice in test_slices.items():
        for local_index, global_index in enumerate(
            range(attack_slice.start, attack_slice.stop)
        ):
            prediction_rows.append(
                {
                    "attack": attack,
                    "external_test_row": local_index,
                    "attacker": int(y_test[global_index]),
                    "temporal_probability": float(t_cal_test[global_index]),
                    "contextual_probability": float(c_cal_test[global_index]),
                    "contextual_uncertainty": float(c_uncertainty_test[global_index]),
                }
            )

    paths = {
        "archives": OUTPUT_DIR / "DURAC_phase9_archive_integrity.csv",
        "audit": OUTPUT_DIR / "DURAC_phase9_dataset_audit.csv",
        "calibration": OUTPUT_DIR / "DURAC_phase9_calibration_selection.csv",
        "metrics": OUTPUT_DIR / "DURAC_phase9_metrics.csv",
        "attacks": OUTPUT_DIR / "DURAC_phase9_attack_comparison.csv",
        "uncertainty": OUTPUT_DIR / "DURAC_phase9_uncertainty.csv",
        "stop_lines": OUTPUT_DIR / "DURAC_phase9_stop_lines.csv",
        "test_predictions": OUTPUT_DIR / "DURAC_phase9_test_predictions.csv",
    }
    _write_csv(paths["archives"], archive_rows)
    _write_csv(paths["audit"], audit_rows)
    _write_csv(paths["calibration"], calibration_rows)
    _write_csv(paths["metrics"], metric_rows)
    _write_csv(paths["attacks"], comparison_rows)
    _write_csv(paths["uncertainty"], [uncertainty])
    _write_csv(paths["stop_lines"], [stop_row])
    _write_csv(paths["test_predictions"], prediction_rows)

    manifest = {
        "protocol_status": "preregistered Phase 9 urban external Test",
        "protocol_sha256": _digest(PROTOCOL),
        "dataset_implementation_sha256": _digest(DATASET_IMPLEMENTATION),
        "evidence_implementation_sha256": _digest(EVIDENCE_IMPLEMENTATION),
        "seed": SEED,
        "development_environment": "InTAS_highway_2 Train and Validation",
        "external_environment": "InTAS_urban_2 Test only",
        "attacks": list(ATTACKS),
        "instantaneous_features": list(INSTANTANEOUS_FEATURE_NAMES),
        "temporal_features": list(TEMPORAL_FEATURE_NAMES),
        "contextual_features": list(CONTEXTUAL_FEATURE_NAMES),
        "archive_sha256": {row["attack"]: row["sha256"] for row in archive_rows},
        "temporal_calibration": t_cal_name,
        "contextual_calibration": c_cal_name,
        "temporal_threshold": thresholds["temporal_calibrated"],
        "contextual_threshold": context_threshold,
        "all_phase9_stop_lines_pass": bool(stop_row["all_phase9_stop_lines_pass"]),
        "outputs": {
            name: {"path": str(path), "sha256": _digest(path)}
            for name, path in paths.items()
        },
    }
    manifest_path = OUTPUT_DIR / "DURAC_phase9_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("===== DURAC PHASE 9 URBAN EXTERNAL TEST =====")
    print(
        f"temporal   PR-AUC={temporal_pooled['pr_auc']:.4f} "
        f"recall={temporal_pooled['malicious_recall']:.3%} "
        f"FPR={temporal_pooled['false_positive_rate']:.3%}"
    )
    print(
        f"contextual PR-AUC={context_pooled['pr_auc']:.4f} "
        f"recall={context_pooled['malicious_recall']:.3%} "
        f"FPR={context_pooled['false_positive_rate']:.3%}"
    )
    for row in comparison_rows:
        print(
            f"{row['attack']:20s} delta_PR={row['contextual_minus_temporal_pr_auc']:+.4f} "
            f"recall={row['contextual_recall']:.3%} FPR={row['contextual_fpr']:.3%}"
        )
    print(
        f"calibration={c_cal_name} threshold={context_threshold:.8f} "
        f"ECE_reduction={ece_reduction:.3%}"
    )
    print(
        "uncertainty_error_auc="
        f"{uncertainty['uncertainty_error_roc_auc']:.4f} "
        f"top_bottom_ratio={uncertainty['top_to_bottom_error_ratio']:.3f}"
    )
    print(f"all_stop_lines_pass={bool(stop_row['all_phase9_stop_lines_pass'])}")
    print(f"[OK] {manifest_path.resolve()}")


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Phase 9 raw VeReMi contextual training/evaluation. Official raw archives must be supplied separately.')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
