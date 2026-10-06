#!/usr/bin/env python3
"""Run the preregistered official CaTCH strong-baseline comparison."""

from __future__ import annotations

import argparse
import csv
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Iterable


OFFICIAL_COMMIT = "acda994bae9966df6ae2f292a2945d8d91e249ce"
OFFICIAL_URL = "https://github.com/VeReMi-dataset/VeReMi-NextGen.git"
OFFICIAL_FILES = {
    "catch_checks.py": "7ad904463f24bb370e9e543d05a0278e6a0bb510d593b9e1aea76ab4b0b2a58a",
    "data_processing.py": "0190c163946354fd09ff8bace80a4ffa49402204cf0b7494b966b4bd3c3be82f",
    "data_structures.py": "3ac9192a0384876c34f87283a5a773edcaf31e7b74aad4adf779d2e63a481c4f",
    "legacy_checks.py": "4d8765db8072f501c288d0b3b8c7d687a57fbfeee45264be84fff8a78db88307",
    "main.py": "ae0df9f4439cbebebb9c4ef8a1ccc0474ec4abae39b4bb539f5cd1dbad107582",
    "mdm_lib.py": "364ed4d7c6936663b265ca440581aad70c68acf1fa6034e207a432563d9d3956",
}

PARAMETERS = {
    "MAX_PLAUSIBLE_RANGE": 309.270,
    "MAX_SA_RANGE": 150.0,
    "MAX_PLAUSIBLE_DIST_NEGATIVE": -2.742,
    "MAX_PLAUSIBLE_SPEED": 56.064,
    "MAX_PLAUSIBLE_ACCEL": 3.138,
    "MAX_PLAUSIBLE_DECEL": 6.131,
    "MAX_HEADING_CHANGE": 115.995,
    "MAX_DELTA_INTERSECTION": 3.757,
    "MAX_TIME_DELTA": 1.538,
    "POS_HEADING_TIME": 1.837,
    "MAX_MGT_RNG_UP": 1.168,
    "MAX_MGT_RNG_DOWN": 2.902,
    "MAX_SA_TIME": 2.1,
    "MAX_NON_ROUTE_SPEED": 0.490,
}

SCRATCH_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_OFFICIAL_REPO = SCRATCH_ROOT / "veremi_nextgen_official"
DATA_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase9"
ARCHIVE_ROOT = SCRATCH_ROOT / "datasets" / "veremi_nextgen_phase9_archives"
PHASE9_METRICS = Path("results/durac_phase9_context_external/DURAC_phase9_metrics.csv")
OUTPUT_DIR = Path("results/durac_phase10_catch_baseline")
PROTOCOL = Path("SEARPC_CATCH_PROTOCOL.md")

ATTACKS = {
    "dataReplay": {
        "folder": "InTAS_urban_2_dataReplay",
        "md5": "3f3d752b4169475ebc5cb17fd8fa59cd",
        "messages": 406_801,
    },
    "timeDelayAttack": {
        "folder": "InTAS_urban_2_timeDelayAttack",
        "md5": "c5fa8415f36807639e52ddcc5f473878",
        "messages": 406_801,
    },
}


@dataclass(frozen=True)
class BinaryMetrics:
    messages: int
    true_positive: int
    false_negative: int
    false_positive: int
    true_negative: int
    accuracy: float
    malicious_precision: float
    malicious_recall: float
    false_negative_rate: float
    false_positive_rate: float
    malicious_f1: float
    benign_f1: float
    macro_f1: float


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def binary_metrics(tp: int, tn: int, fp: int, fn: int) -> BinaryMetrics:
    messages = tp + tn + fp + fn
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    malicious_f1 = _ratio(2 * precision * recall, precision + recall)
    benign_precision = _ratio(tn, tn + fn)
    benign_recall = _ratio(tn, tn + fp)
    benign_f1 = _ratio(
        2 * benign_precision * benign_recall, benign_precision + benign_recall
    )
    return BinaryMetrics(
        messages=messages,
        true_positive=tp,
        false_negative=fn,
        false_positive=fp,
        true_negative=tn,
        accuracy=_ratio(tp + tn, messages),
        malicious_precision=precision,
        malicious_recall=recall,
        false_negative_rate=_ratio(fn, tp + fn),
        false_positive_rate=_ratio(fp, fp + tn),
        malicious_f1=malicious_f1,
        benign_f1=benign_f1,
        macro_f1=(malicious_f1 + benign_f1) / 2,
    )


def _digest(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_official_source(repo: Path) -> tuple[Path, list[dict]]:
    source = repo / "Generator" / "MBD_systems"
    observed_commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if observed_commit != OFFICIAL_COMMIT:
        raise ValueError(
            f"official commit mismatch: {observed_commit} != {OFFICIAL_COMMIT}"
        )
    rows = []
    for name, expected in OFFICIAL_FILES.items():
        observed = _digest(source / name)
        if observed != expected:
            raise ValueError(f"official SHA-256 mismatch for {name}")
        rows.append(
            {"file": name, "expected_sha256": expected, "observed_sha256": observed}
        )
    return source, rows


def _official_worker(
    json_path: str, source_dir: str, parameters: dict[str, float]
) -> dict:
    source = Path(source_dir)
    sys.path.insert(0, str(source))
    import pandas as pd
    import data_processing
    from data_structures import Parameters

    started = time.perf_counter()
    result = data_processing.process(
        Path(json_path), 0, Parameters(**parameters), pd.DataFrame(), Path(json_path).stem
    )
    if result is None:
        result = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    return {
        "file": Path(json_path).name,
        **{key: int(result[key]) for key in ("tp", "tn", "fp", "fn")},
        "elapsed_seconds": time.perf_counter() - started,
    }


def run_attack(
    attack: str, definition: dict, source: Path, workers: int
) -> tuple[list[dict], BinaryMetrics, float]:
    json_dir = (
        DATA_ROOT
        / definition["folder"]
        / "Test"
        / "json"
        / definition["folder"]
    )
    paths = sorted(json_dir.glob("*.json"))
    if not paths:
        raise FileNotFoundError(f"no Test JSON files found in {json_dir}")

    started = time.perf_counter()
    rows = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(
                _official_worker, str(path), str(source), dict(PARAMETERS)
            ): path.name
            for path in paths
        }
        for index, future in enumerate(as_completed(futures), 1):
            row = future.result()
            row["attack"] = attack
            rows.append(row)
            if index % 100 == 0 or index == len(paths):
                print(f"  {attack}: {index}/{len(paths)} receiver files", flush=True)
    wall_seconds = time.perf_counter() - started
    rows.sort(key=lambda row: row["file"])
    totals = {
        key: sum(row[key] for row in rows) for key in ("tp", "tn", "fp", "fn")
    }
    metrics = binary_metrics(
        totals["tp"], totals["tn"], totals["fp"], totals["fn"]
    )
    if metrics.messages != definition["messages"]:
        raise ValueError(
            f"{attack} accounting mismatch: {metrics.messages} != {definition['messages']}"
        )
    return rows, metrics, wall_seconds


def _write_csv(path: Path, rows: Iterable[dict]) -> None:
    rows = list(rows)
    if not rows:
        raise ValueError(f"refusing to write empty CSV: {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def load_durac_phase9() -> dict[str, dict]:
    selected = {}
    with PHASE9_METRICS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["method"] != "contextual_calibrated":
                continue
            if row["scope"] == "pooled_external_test":
                selected["all"] = row
            elif row["scope"] == "attack_external_test":
                selected[row["attack"]] = row
    required = {"all", *ATTACKS}
    if set(selected) != required:
        raise ValueError(f"missing frozen Phase 9 metrics: {required - set(selected)}")
    return selected


def _method_row(scope: str, attack: str, method: str, metrics: BinaryMetrics) -> dict:
    return {"scope": scope, "attack": attack, "method": method, **asdict(metrics)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--official-repo", type=Path, default=DEFAULT_OFFICIAL_REPO
    )
    parser.add_argument(
        "--workers", type=int, default=min(32, os.cpu_count() or 4)
    )
    args = parser.parse_args()
    if args.workers < 1:
        raise ValueError("workers must be positive")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    source, source_rows = verify_official_source(args.official_repo)
    archive_rows = []
    for attack, definition in ATTACKS.items():
        archive = ARCHIVE_ROOT / f"{definition['folder']}.zip"
        observed = _digest(archive, "md5")
        if observed != definition["md5"]:
            raise ValueError(f"archive MD5 mismatch for {attack}")
        archive_rows.append(
            {
                "attack": attack,
                "archive": archive.name,
                "expected_md5": definition["md5"],
                "observed_md5": observed,
            }
        )

    print("[run exact official CaTCH code with frozen highway_2 parameters]", flush=True)
    file_rows = []
    catch_metrics = {}
    timing_rows = []
    for attack, definition in ATTACKS.items():
        rows, metrics, wall_seconds = run_attack(
            attack, definition, source, args.workers
        )
        file_rows.extend(rows)
        catch_metrics[attack] = metrics
        timing_rows.append(
            {
                "attack": attack,
                "receiver_files": len(rows),
                "messages": metrics.messages,
                "wall_seconds": wall_seconds,
                "messages_per_second": metrics.messages / wall_seconds,
                "workers": args.workers,
            }
        )

    pooled_catch = binary_metrics(
        sum(metric.true_positive for metric in catch_metrics.values()),
        sum(metric.true_negative for metric in catch_metrics.values()),
        sum(metric.false_positive for metric in catch_metrics.values()),
        sum(metric.false_negative for metric in catch_metrics.values()),
    )
    catch_metrics["all"] = pooled_catch

    durac_rows = load_durac_phase9()
    metric_rows = []
    comparison_rows = []
    for attack in (*ATTACKS, "all"):
        scope = "pooled_external_test" if attack == "all" else "attack_external_test"
        catch = catch_metrics[attack]
        metric_rows.append(_method_row(scope, attack, "official_catch", catch))

        durac = durac_rows[attack]
        durac_metrics = binary_metrics(
            int(durac["true_positive"]),
            int(durac["true_negative"]),
            int(durac["false_positive"]),
            int(durac["false_negative"]),
        )
        metric_rows.append(
            _method_row(scope, attack, "durac_contextual_calibrated", durac_metrics)
        )
        comparison_rows.append(
            {
                "attack": attack,
                "durac_minus_catch_macro_f1": durac_metrics.macro_f1 - catch.macro_f1,
                "durac_minus_catch_malicious_f1": durac_metrics.malicious_f1 - catch.malicious_f1,
                "durac_minus_catch_recall": durac_metrics.malicious_recall - catch.malicious_recall,
                "durac_minus_catch_fpr": durac_metrics.false_positive_rate - catch.false_positive_rate,
                "macro_f1_practical_gain_pass": int(
                    durac_metrics.macro_f1 >= catch.macro_f1 + 0.05
                ),
                "recall_gain_pass": int(
                    durac_metrics.malicious_recall > catch.malicious_recall
                ),
                "fpr_noninferiority_pass": int(
                    durac_metrics.false_positive_rate
                    <= catch.false_positive_rate + 0.01
                ),
            }
        )

    attack_rows = [row for row in comparison_rows if row["attack"] != "all"]
    stop_row = {
        "official_source_integrity_pass": 1,
        "archive_integrity_pass": 1,
        "message_accounting_pass": int(pooled_catch.messages == 813_602),
        "both_attack_macro_f1_gain_pass": int(
            all(row["macro_f1_practical_gain_pass"] for row in attack_rows)
        ),
        "both_attack_recall_gain_pass": int(
            all(row["recall_gain_pass"] for row in attack_rows)
        ),
        "both_attack_fpr_noninferiority_pass": int(
            all(row["fpr_noninferiority_pass"] for row in attack_rows)
        ),
    }
    stop_row["all_phase10_stop_lines_pass"] = int(all(stop_row.values()))

    _write_csv(OUTPUT_DIR / "SEARPC_catch_official_source.csv", source_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_archive_integrity.csv", archive_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_file_counts.csv", file_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_metrics.csv", metric_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_comparison.csv", comparison_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_timing.csv", timing_rows)
    _write_csv(OUTPUT_DIR / "SEARPC_catch_stop_lines.csv", [stop_row])

    manifest = {
        "protocol_sha256": _digest(PROTOCOL),
        "runner_sha256": _digest(Path(__file__)),
        "phase9_metrics_sha256": _digest(PHASE9_METRICS),
        "official_url": OFFICIAL_URL,
        "official_commit": OFFICIAL_COMMIT,
        "parameters": PARAMETERS,
        "workers": args.workers,
        "outputs": {
            path.name: _digest(path)
            for path in sorted(OUTPUT_DIR.glob("*.csv"))
        },
    }
    with (OUTPUT_DIR / "SEARPC_catch_manifest.json").open(
        "w", encoding="utf-8"
    ) as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)

    print("===== DURAC PHASE 10 OFFICIAL CATCH BASELINE =====")
    for row in comparison_rows:
        print(
            f"{row['attack']:18s} "
            f"delta_macro_f1={row['durac_minus_catch_macro_f1']:+.4f} "
            f"delta_recall={row['durac_minus_catch_recall']:+.4f} "
            f"delta_fpr={row['durac_minus_catch_fpr']:+.4f}"
        )
    print(json.dumps(stop_row, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
