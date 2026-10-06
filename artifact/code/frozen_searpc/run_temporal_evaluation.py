#!/usr/bin/env python3
"""Preregistered temporal evaluation temporal-evidence external experiment."""

from __future__ import annotations

from dataclasses import asdict
import csv
from hashlib import md5, sha256
import json
import os
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.utils.class_weight import compute_sample_weight

from durac import (
    IsotonicProbabilityCalibrator,
    PlattProbabilityCalibrator,
    TEMPORAL_FEATURE_NAMES,
    audit_veremi_directory,
    iter_veremi_temporal_directory,
    message_evidence_metrics,
    select_fpr_constrained_threshold,
    uncertainty_diagnostics,
)


SEED = 260825
PACKAGE_ROOT = Path(__file__).resolve().parents[4]
DATA_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_DEVELOPMENT_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase8",
    )
)
ARCHIVE_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_PHASE8_ARCHIVE_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase8_archives",
    )
)
OUTPUT_DIR = Path("results/durac_phase8_temporal_external")
PROTOCOL = Path("SEARPC_TEMPORAL_EXTERNAL_PROTOCOL.md")
DATASET_IMPLEMENTATION = Path("durac/datasets.py")
EVIDENCE_IMPLEMENTATION = Path("durac/message_evidence.py")

ATTACKS = {
    "constantSpeedOffset": {
        "folder": "InTAS_highway_2_constantSpeedOffset",
        "md5": "27a7d170fd937b65736d06054ba97bc4",
    },
    "dataReplay": {
        "folder": "InTAS_highway_2_dataReplay",
        "md5": "9515b57c25dd34304642654dd22df66b",
    },
    "randomPositionOffset": {
        "folder": "InTAS_highway_2_randomPositionOffset",
        "md5": "0b72ffd770351817deb18fa3ec630a61",
    },
    "timeDelayAttack": {
        "folder": "InTAS_highway_2_timeDelayAttack",
        "md5": "84f2002bc770b08be77a7457c2079d59",
    },
}

INSTANTANEOUS_FEATURE_NAMES = (
    "delivery_delay_s",
    "relative_distance",
    "relative_x",
    "relative_y",
    "relative_z",
    "sender_position_noise",
    "receiver_position_noise",
    "speed_difference",
    "sender_speed_noise",
    "receiver_speed_noise",
    "acceleration_difference",
    "sender_acceleration_noise",
    "receiver_acceleration_noise",
    "heading_difference",
    "sender_heading_noise",
    "receiver_heading_noise",
    "distance_to_road_edge",
)
PROHIBITED_RAW_FEATURES = frozenset(
    {
        "attacker",
        "sender_id",
        "sender_alias",
        "messageID",
        "receiver_filename",
        "receive_time",
        "send_time",
        "absolute_sender_position",
        "absolute_receiver_position",
        "attack_name",
        "split_name",
        "driver_profile",
    }
)


def _digest(path: Path, algorithm: str = "sha256") -> str:
    constructor = md5 if algorithm == "md5" else sha256
    hasher = constructor()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("rows cannot be empty")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _hist_model(random_state: int) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.05,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        random_state=random_state,
    )


def _load_attack_split(attack: str, split: str):
    root = DATA_ROOT / ATTACKS[attack]["folder"] / split / "json"
    audit = audit_veremi_directory(root)
    if audit.feature_names != INSTANTANEOUS_FEATURE_NAMES:
        raise ValueError("instantaneous schema differs from frozen Phase 7 schema")
    if PROHIBITED_RAW_FEATURES & set(audit.feature_names):
        raise ValueError("a prohibited raw feature reached the instantaneous matrix")
    temporal_schema = INSTANTANEOUS_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES
    if PROHIBITED_RAW_FEATURES & set(temporal_schema):
        raise ValueError("a prohibited raw feature reached the temporal matrix")

    instantaneous_rows = []
    temporal_rows = []
    labels = []
    for example in iter_veremi_temporal_directory(root):
        physical = example.record.physical_features()
        instantaneous = [physical[name] for name in INSTANTANEOUS_FEATURE_NAMES]
        temporal = instantaneous + [
            example.temporal_features[name] for name in TEMPORAL_FEATURE_NAMES
        ]
        instantaneous_rows.append(instantaneous)
        temporal_rows.append(temporal)
        labels.append(example.record.attacker)

    x_instantaneous = np.asarray(instantaneous_rows, dtype=float)
    x_temporal = np.asarray(temporal_rows, dtype=float)
    y = np.asarray(labels, dtype=int)
    if x_instantaneous.shape != (audit.messages, len(INSTANTANEOUS_FEATURE_NAMES)):
        raise ValueError("instantaneous matrix does not account for every message")
    if x_temporal.shape != (audit.messages, len(temporal_schema)):
        raise ValueError("temporal matrix does not account for every message")
    if not np.isfinite(x_instantaneous).all() or not np.isfinite(x_temporal).all():
        raise ValueError("a design matrix contains a non-finite value")
    return x_instantaneous, x_temporal, y, audit


def _fit_ensemble(x_train, y_train, x_validation, x_test, seed_offset: int):
    validation_members = []
    test_members = []
    for member in range(5):
        print(f"  member {member + 1}/5", flush=True)
        rng = np.random.default_rng(SEED + seed_offset + member)
        indices = rng.integers(0, len(y_train), size=len(y_train))
        member_y = y_train[indices]
        model = _hist_model(SEED + seed_offset + 100 + member)
        model.fit(
            x_train[indices],
            member_y,
            sample_weight=compute_sample_weight("balanced", member_y),
        )
        validation_members.append(model.predict_proba(x_validation)[:, 1])
        test_members.append(model.predict_proba(x_test)[:, 1])
    validation_array = np.asarray(validation_members)
    test_array = np.asarray(test_members)
    return (
        validation_array.mean(axis=0),
        test_array.mean(axis=0),
        validation_array.std(axis=0),
        test_array.std(axis=0),
    )


def _calibrate(raw_validation, raw_test, y_validation):
    calibrators = {
        "platt": PlattProbabilityCalibrator().fit(raw_validation, y_validation),
        "isotonic": IsotonicProbabilityCalibrator().fit(
            raw_validation, y_validation
        ),
    }
    rows = []
    candidates = {}
    for name in ("platt", "isotonic"):
        validation_probability = calibrators[name].predict(raw_validation)
        test_probability = calibrators[name].predict(raw_test)
        brier = float(np.mean((validation_probability - y_validation) ** 2))
        rows.append({"calibration": name, "validation_brier": brier})
        candidates[name] = (validation_probability, test_probability)
    selected = min(
        rows,
        key=lambda row: (
            row["validation_brier"],
            0 if row["calibration"] == "platt" else 1,
        ),
    )["calibration"]
    return selected, candidates[selected][0], candidates[selected][1], rows


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
        archive = ARCHIVE_ROOT / f"{definition['folder']}.zip"
        observed_md5 = _digest(archive, "md5")
        if observed_md5 != definition["md5"]:
            raise ValueError(f"official MD5 mismatch for {attack}")
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

    loaded: dict[str, dict[str, tuple]] = {}
    audit_rows = []
    print("[load and audit official external splits]", flush=True)
    for split in ("Train", "Validation", "Test"):
        loaded[split] = {}
        for attack in ATTACKS:
            print(f"  {split:10s} {attack}", flush=True)
            values = _load_attack_split(attack, split)
            loaded[split][attack] = values[:3]
            audit = values[3]
            audit_rows.append(
                {
                    "split": split.lower(),
                    "attack": attack,
                    "json_files": audit.json_files,
                    "messages": audit.messages,
                    "attack_messages": audit.attack_messages,
                    "attack_rate": audit.attack_rate,
                    "sender_ids": audit.sender_ids,
                    "sender_aliases": audit.sender_aliases,
                    "driver_profiles": "|".join(audit.driver_profiles),
                    "vector_encodings": "|".join(audit.vector_encodings),
                    "instantaneous_feature_count": len(INSTANTANEOUS_FEATURE_NAMES),
                    "temporal_feature_count": len(TEMPORAL_FEATURE_NAMES),
                    "prohibited_feature_count": len(
                        PROHIBITED_RAW_FEATURES
                        & set(INSTANTANEOUS_FEATURE_NAMES + TEMPORAL_FEATURE_NAMES)
                    ),
                }
            )

    pooled = {}
    attack_slices: dict[str, slice] = {}
    for split in ("Train", "Validation", "Test"):
        pooled[split] = tuple(
            np.concatenate([loaded[split][attack][index] for attack in ATTACKS])
            for index in range(3)
        )
        if split == "Test":
            start = 0
            for attack in ATTACKS:
                length = len(loaded[split][attack][2])
                attack_slices[attack] = slice(start, start + length)
                start += length

    x_i_train, x_t_train, y_train = pooled["Train"]
    x_i_validation, x_t_validation, y_validation = pooled["Validation"]
    x_i_test, x_t_test, y_test = pooled["Test"]

    print("[fit instantaneous five-member ensemble]", flush=True)
    i_raw_val, i_raw_test, _, i_uncertainty_test = _fit_ensemble(
        x_i_train, y_train, x_i_validation, x_i_test, 0
    )
    print("[fit temporal five-member ensemble]", flush=True)
    t_raw_val, t_raw_test, _, t_uncertainty_test = _fit_ensemble(
        x_t_train, y_train, x_t_validation, x_t_test, 1000
    )

    print("[select validation-only calibration and thresholds]", flush=True)
    i_cal_name, i_cal_val, i_cal_test, i_cal_rows = _calibrate(
        i_raw_val, i_raw_test, y_validation
    )
    t_cal_name, t_cal_val, t_cal_test, t_cal_rows = _calibrate(
        t_raw_val, t_raw_test, y_validation
    )
    probability_sets = {
        "instantaneous_raw": (i_raw_val, i_raw_test, "none"),
        "instantaneous_calibrated": (i_cal_val, i_cal_test, i_cal_name),
        "temporal_raw": (t_raw_val, t_raw_test, "none"),
        "temporal_calibrated": (t_cal_val, t_cal_test, t_cal_name),
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
                "pooled_test", "all", method, calibration,
                y_test, test_probability, threshold,
            )
        )
        for attack, attack_slice in attack_slices.items():
            metric_rows.append(
                _metric_row(
                    "attack_test", attack, method, calibration,
                    y_test[attack_slice], test_probability[attack_slice], threshold,
                )
            )

    calibration_rows = [
        {"method": "instantaneous", **row, "selected": int(row["calibration"] == i_cal_name)}
        for row in i_cal_rows
    ] + [
        {"method": "temporal", **row, "selected": int(row["calibration"] == t_cal_name)}
        for row in t_cal_rows
    ]

    temporal_threshold = thresholds["temporal_calibrated"]
    uncertainty = uncertainty_diagnostics(
        y_test,
        t_cal_test,
        t_uncertainty_test,
        threshold=temporal_threshold,
    )
    uncertainty["instantaneous_mean_uncertainty"] = float(
        i_uncertainty_test.mean()
    )

    indexed_metrics = {
        (row["scope"], row["attack"], row["method"]): row
        for row in metric_rows
    }
    instant_pooled = indexed_metrics[
        ("pooled_test", "all", "instantaneous_calibrated")
    ]
    temporal_pooled = indexed_metrics[
        ("pooled_test", "all", "temporal_calibrated")
    ]
    temporal_raw_pooled = indexed_metrics[
        ("pooled_test", "all", "temporal_raw")
    ]
    attack_comparison_rows = []
    improved_attacks = 0
    per_attack_operating_pass = True
    for attack in ATTACKS:
        instant = indexed_metrics[
            ("attack_test", attack, "instantaneous_calibrated")
        ]
        temporal = indexed_metrics[
            ("attack_test", attack, "temporal_calibrated")
        ]
        improvement = temporal["pr_auc"] - instant["pr_auc"]
        improved = improvement >= 0.02
        operating_pass = (
            temporal["malicious_recall"] >= 0.60
            and temporal["false_positive_rate"] <= 0.05
        )
        improved_attacks += int(improved)
        per_attack_operating_pass &= operating_pass
        attack_comparison_rows.append(
            {
                "attack": attack,
                "instantaneous_pr_auc": instant["pr_auc"],
                "temporal_pr_auc": temporal["pr_auc"],
                "temporal_minus_instantaneous_pr_auc": improvement,
                "pr_improvement_0_02_pass": int(improved),
                "temporal_recall": temporal["malicious_recall"],
                "temporal_fpr": temporal["false_positive_rate"],
                "per_attack_operating_point_pass": int(operating_pass),
            }
        )

    ece_reduction = (
        1.0 - temporal_pooled["ece_15"] / temporal_raw_pooled["ece_15"]
        if temporal_raw_pooled["ece_15"]
        else 0.0
    )
    accounting_pass = all(
        row["messages"] == len(loaded[row["split"].capitalize()][row["attack"]][2])
        for row in audit_rows
    )
    uncertainty_pass = (
        uncertainty["uncertainty_error_roc_auc"] >= 0.60
        or uncertainty["top_to_bottom_error_ratio"] >= 2.0
    )
    checks = {
        "archive_integrity_pass": all(row["md5_pass"] for row in archive_rows),
        "parser_accounting_and_finite_pass": accounting_pass,
        "no_prohibited_features_pass": all(
            row["prohibited_feature_count"] == 0 for row in audit_rows
        ),
        "pooled_pr_noninferiority_pass": (
            temporal_pooled["pr_auc"] >= instant_pooled["pr_auc"] - 0.01
        ),
        "two_attack_pr_improvement_pass": improved_attacks >= 2,
        "ece_improvement_pass": ece_reduction >= 0.10,
        "pooled_operating_point_pass": (
            temporal_pooled["malicious_recall"] >= 0.70
            and temporal_pooled["false_positive_rate"] <= 0.05
        ),
        "every_attack_operating_point_pass": per_attack_operating_pass,
        "uncertainty_signal_pass": uncertainty_pass,
    }
    stop_row = {
        **{name: int(value) for name, value in checks.items()},
        "instantaneous_calibration": i_cal_name,
        "temporal_calibration": t_cal_name,
        "instantaneous_threshold": thresholds["instantaneous_calibrated"],
        "temporal_threshold": temporal_threshold,
        "instantaneous_pooled_test_pr_auc": instant_pooled["pr_auc"],
        "temporal_pooled_test_pr_auc": temporal_pooled["pr_auc"],
        "temporal_minus_instantaneous_pr_auc": (
            temporal_pooled["pr_auc"] - instant_pooled["pr_auc"]
        ),
        "attacks_improved_by_0_02": improved_attacks,
        "temporal_raw_test_ece": temporal_raw_pooled["ece_15"],
        "temporal_calibrated_test_ece": temporal_pooled["ece_15"],
        "ece_relative_reduction": ece_reduction,
        "temporal_pooled_test_recall": temporal_pooled["malicious_recall"],
        "temporal_pooled_test_fpr": temporal_pooled["false_positive_rate"],
        **uncertainty,
        "all_phase8_stop_lines_pass": int(all(checks.values())),
    }

    prediction_rows = []
    for attack, attack_slice in attack_slices.items():
        for local_index, global_index in enumerate(
            range(attack_slice.start, attack_slice.stop)
        ):
            prediction_rows.append(
                {
                    "attack": attack,
                    "attack_test_row": local_index,
                    "attacker": int(y_test[global_index]),
                    "instantaneous_probability": float(i_cal_test[global_index]),
                    "temporal_probability": float(t_cal_test[global_index]),
                    "temporal_uncertainty": float(t_uncertainty_test[global_index]),
                }
            )

    paths = {
        "archives": OUTPUT_DIR / "DURAC_phase8_archive_integrity.csv",
        "audit": OUTPUT_DIR / "DURAC_phase8_dataset_audit.csv",
        "calibration": OUTPUT_DIR / "DURAC_phase8_calibration_selection.csv",
        "metrics": OUTPUT_DIR / "DURAC_phase8_metrics.csv",
        "attacks": OUTPUT_DIR / "DURAC_phase8_attack_comparison.csv",
        "uncertainty": OUTPUT_DIR / "DURAC_phase8_uncertainty.csv",
        "stop_lines": OUTPUT_DIR / "DURAC_phase8_stop_lines.csv",
        "test_predictions": OUTPUT_DIR / "DURAC_phase8_test_predictions.csv",
    }
    _write_csv(paths["archives"], archive_rows)
    _write_csv(paths["audit"], audit_rows)
    _write_csv(paths["calibration"], calibration_rows)
    _write_csv(paths["metrics"], metric_rows)
    _write_csv(paths["attacks"], attack_comparison_rows)
    _write_csv(paths["uncertainty"], [uncertainty])
    _write_csv(paths["stop_lines"], [stop_row])
    _write_csv(paths["test_predictions"], prediction_rows)

    manifest = {
        "protocol_status": "preregistered Phase 8 temporal external test",
        "protocol_sha256": _digest(PROTOCOL),
        "dataset_implementation_sha256": _digest(DATASET_IMPLEMENTATION),
        "evidence_implementation_sha256": _digest(EVIDENCE_IMPLEMENTATION),
        "seed": SEED,
        "attacks": list(ATTACKS),
        "instantaneous_features": list(INSTANTANEOUS_FEATURE_NAMES),
        "temporal_features": list(TEMPORAL_FEATURE_NAMES),
        "archive_sha256": {row["attack"]: row["sha256"] for row in archive_rows},
        "instantaneous_calibration": i_cal_name,
        "temporal_calibration": t_cal_name,
        "instantaneous_threshold": thresholds["instantaneous_calibrated"],
        "temporal_threshold": temporal_threshold,
        "all_phase8_stop_lines_pass": bool(stop_row["all_phase8_stop_lines_pass"]),
        "outputs": {
            name: {"path": str(path), "sha256": _digest(path)}
            for name, path in paths.items()
        },
    }
    manifest_path = OUTPUT_DIR / "DURAC_phase8_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("===== DURAC PHASE 8 TEMPORAL EXTERNAL =====")
    print(
        f"instantaneous PR-AUC={instant_pooled['pr_auc']:.4f} "
        f"recall={instant_pooled['malicious_recall']:.3%} "
        f"FPR={instant_pooled['false_positive_rate']:.3%}"
    )
    print(
        f"temporal      PR-AUC={temporal_pooled['pr_auc']:.4f} "
        f"recall={temporal_pooled['malicious_recall']:.3%} "
        f"FPR={temporal_pooled['false_positive_rate']:.3%}"
    )
    for row in attack_comparison_rows:
        print(
            f"{row['attack']:24s} delta_PR={row['temporal_minus_instantaneous_pr_auc']:+.4f} "
            f"recall={row['temporal_recall']:.3%} FPR={row['temporal_fpr']:.3%}"
        )
    print(
        f"calibration={t_cal_name} threshold={temporal_threshold:.8f} "
        f"ECE_reduction={ece_reduction:.3%}"
    )
    print(
        "uncertainty_error_auc="
        f"{uncertainty['uncertainty_error_roc_auc']:.4f} "
        f"top_bottom_ratio={uncertainty['top_to_bottom_error_ratio']:.3f}"
    )
    print(f"all_stop_lines_pass={bool(stop_row['all_phase8_stop_lines_pass'])}")
    print(f"[OK] {manifest_path.resolve()}")


if __name__ == "__main__":
    import sys
    if "--help" in sys.argv or "-h" in sys.argv:
        print('Phase 8 raw VeReMi training/evaluation. Official raw archives must be supplied separately.')
        print("Run without --help to execute the frozen source simulation.")
        raise SystemExit(0)
    main()
