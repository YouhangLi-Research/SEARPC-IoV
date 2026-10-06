#!/usr/bin/env python3
"""Reproduce vehicle authorization and source-domain experiments from frozen inputs.

The scientific cell functions are imported unchanged. This entry point adds
input verification, portable paths, reproducible reporting, and provenance-bound
checkpoints. Smoke mode uses two seeds and the complete event traces.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import csv
from hashlib import sha256
import importlib.metadata
import json
import math
import os
from pathlib import Path
from statistics import mean, stdev
import sys
import time

import numpy as np
from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[1]
CODE_DIRS = tuple(ROOT / "artifact" / "code" / name for name in
                  ("participation_control", "scoped_evidence", "observable_selection", "frozen_searpc"))
for directory in reversed(CODE_DIRS):
    sys.path.insert(0, str(directory))

import run_durac_domain_cap_2x2 as domain
import run_conditional_trust as role_reporting
from run_holdout_authorization import run_cell as role_cell
from run_role_authorization import load_bundle

INPUTS = {
    "rq2_trace_bundle_exact.npz":
        "09d7fe87141f7467057e1176a09efff0a93167df5aa97b8d5715486c8cb79cc0",
    "SEARPC_holdout_holdout_predictions.csv":
        "58a93ef9159a7a090654c8b3adc4ffb5eeaabd7f895049e32c4911ec5c82b915",
}
SEEDS = tuple(range(260825, 260845))
ATTACKS = ("dataReplay", "timeDelayAttack")
OVERLAPS = (0.0, 0.5, 1.0)
FIGURE_DATA = ROOT / "figures" / "experimental" / "fig5_to_fig11" / "data"


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def verify_inputs() -> None:
    for name, expected in INPUTS.items():
        path = ROOT / "data" / "derived" / name
        if not path.is_file():
            raise FileNotFoundError(f"Required bundled input is missing: {name}")
        if digest(path) != expected:
            raise ValueError(f"Bundled input SHA-256 mismatch: {name}")


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_csv(path: Path, records: list[dict]) -> None:
    if not records:
        raise ValueError(f"No records to write: {path.name}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def exact_sign_flip(differences) -> float:
    """Enumerate the same two-sided exact test using arrays of signed sums."""
    nonzero = np.asarray([float(x) for x in differences if abs(x) > 1e-15])
    if not len(nonzero):
        return 1.0
    observed = abs(mean(nonzero.tolist()))
    signed_sums = np.zeros(1, dtype=float)
    for value in nonzero:
        signed_sums = np.concatenate((signed_sums - value, signed_sums + value))
    extreme = np.count_nonzero(np.abs(signed_sums) / len(nonzero) >= observed - 1e-15)
    return float(extreme / len(signed_sums))


def _job(kind: str, arguments: tuple) -> dict:
    started = time.perf_counter()
    if kind == "uniform":
        records = role_cell(*arguments)
    elif kind == "cold":
        records = role_reporting.run_cold_cell(*arguments)
    elif kind == "domain":
        records = domain.run_cell(*arguments)
    else:
        import identity_multiplicity_external as external
        records = external.run_cell(*arguments)
    return {"kind": kind, "elapsed_s": time.perf_counter() - started, "rows": records}


def provenance(stage: str, mode: str, seeds: tuple[int, ...]) -> dict:
    modules = (
        "run_holdout_authorization.py", "run_conditional_trust.py",
        "run_dual_role.py", "run_durac_domain_cap_2x2.py",
        "authority.py", "adjudication.py", "identity_multiplicity_external.py",
    )
    sources = {}
    for name in modules:
        for directory in CODE_DIRS:
            path = directory / name
            if path.is_file():
                sources[path.relative_to(ROOT).as_posix()] = digest(path)
                break
    core = ROOT / "artifact" / "baselines" / "TWSL_VeReMi_Adapted_Baseline" / "src" / "twsl_baseline" / "core.py"
    sources[core.relative_to(ROOT).as_posix()] = digest(core)
    return {
        "stage": stage, "mode": mode, "seeds": list(seeds),
        "input_sha256": INPUTS, "scientific_sources": sources,
        "wrapper_sha256": digest(Path(__file__)),
        "dependencies": {name: importlib.metadata.version(name) for name in
                         ("numpy", "scipy", "scikit-learn")},
        "python": sys.version.split()[0],
    }


def evaluate(jobs: list[tuple[str, tuple, str]], output: Path, record: dict,
             workers: int, resume: bool) -> list[dict]:
    output = output.resolve()
    record_path = output / "RUN_CONFIG.json"
    if output.exists() and any(output.iterdir()):
        if not resume:
            raise FileExistsError("Non-empty output directory; use --resume for a matching run")
        if not record_path.is_file() or json.loads(record_path.read_text()) != record:
            raise ValueError("Cannot resume: input, code, environment, or experiment grid differs")
    output.mkdir(parents=True, exist_ok=True)
    write_json(record_path, record)
    checkpoint_dir = output / "checkpoints"
    checkpoint_dir.mkdir(exist_ok=True)
    pending = []
    for kind, arguments, key in jobs:
        path = checkpoint_dir / f"{key}.json"
        if path.is_file():
            checkpoint = json.loads(path.read_text())
            expected_rows = {"uniform": 3, "cold": 2, "domain": 4, "external": 2}[kind]
            if checkpoint.get("key") != key or len(checkpoint.get("rows", [])) != expected_rows:
                raise ValueError(f"Invalid checkpoint: {path.name}")
        else:
            pending.append((kind, arguments, key))
    print(f"{record['stage']}: cells={len(jobs)}, cached={len(jobs)-len(pending)}, pending={len(pending)}", flush=True)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_job, kind, arguments): key for kind, arguments, key in pending}
        for count, future in enumerate(as_completed(futures), 1):
            key = futures[future]
            checkpoint = future.result()
            checkpoint["key"] = key
            write_json(checkpoint_dir / f"{key}.json", checkpoint)
            if count % 5 == 0 or count == len(pending):
                print(f"{record['stage']}: completed {count}/{len(pending)} pending cells", flush=True)
    records = []
    for _, _, key in jobs:
        records.extend(json.loads((checkpoint_dir / f"{key}.json").read_text())["rows"])
    return records


def compare_table(actual: list[dict], reference: Path, keys: tuple[str, ...],
                  metrics: tuple[str, ...] | None = None) -> dict:
    expected = read_csv(reference)
    indexed = {tuple(str(row[key]) for key in keys): row for row in actual}
    if len(indexed) != len(actual) or len(actual) != len(expected):
        raise AssertionError(f"Reference cardinality mismatch: {reference.name}")
    maximum_error = 0.0
    checked = 0
    for frozen in expected:
        key = tuple(frozen[item] for item in keys)
        if key not in indexed:
            raise AssertionError(f"Missing reference cell: {key}")
        observed = indexed[key]
        columns = metrics or tuple(column for column in frozen if column not in keys)
        for column in columns:
            left, right = float(observed[column]), float(frozen[column])
            if math.isnan(left) and math.isnan(right):
                continue
            if not math.isclose(left, right, rel_tol=1e-10, abs_tol=1e-12):
                raise AssertionError(f"Reference mismatch: {reference.name}, {key}, {column}: {left} != {right}")
            maximum_error = max(maximum_error, abs(left-right))
            checked += 1
    return {"reference": reference.relative_to(ROOT).as_posix(), "pass": True,
            "cells": len(expected), "values_checked": checked, "maximum_absolute_error": maximum_error}


def domain_intervals(records: list[dict]) -> list[dict]:
    grouped = {}
    for row in records:
        key = (row["attack"], row["layout"], row["variant"], row["multiplicity"])
        grouped.setdefault(key, []).append(float(row["early_adversarial_weight_share"]))
    output = []
    for (attack, layout, variant, multiplicity), values in sorted(grouped.items()):
        average = mean(values)
        margin = float(student_t.ppf(0.975, len(values)-1)) * stdev(values) / math.sqrt(len(values))
        output.append({"attack": attack, "layout": layout,
                       "metric": "early_adversarial_weight_share", "variant": variant,
                       "multiplicity": multiplicity, "mean": average,
                       "ci95_low": average-margin, "ci95_high": average+margin})
    return output


def role_run(output: Path, mode: str, workers: int, resume: bool) -> None:
    seeds = SEEDS if mode == "full" else SEEDS[:2]
    traces = load_bundle(ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz")
    jobs = []
    for attack in ATTACKS:
        trace, attackers, domains = traces[attack]
        for overlap in OVERLAPS:
            for seed in seeds:
                arguments = (attack, trace, attackers, domains, overlap, seed)
                key = f"uniform__{attack}__overlap{int(overlap*100)}__seed{seed}"
                jobs.append(("uniform", arguments, key))
        for seed in seeds:
            jobs.append(("cold", (attack, trace, attackers, domains, seed), f"cold__{attack}__seed{seed}"))
    record = provenance("role", mode, seeds)
    raw = evaluate(jobs, output, record, workers, resume)
    uniform = [row for row in raw if row["variant"] in ("single_role_three_state", "dual_role_three_state")]
    cold = [row for row in raw if row["variant"] == "dual_role_lcb_weight" or
            (row["variant"] == "dual_role_mean_weight" and "overlap" not in row)]
    uniform.sort(key=lambda row: (row["attack"], row["overlap"], row["seed"], row["variant"]))
    cold.sort(key=lambda row: (row["attack"], row["seed"], row["variant"]))
    previous_seeds = role_reporting.SEEDS
    role_reporting.SEEDS = seeds
    try:
        summary = role_reporting._summaries(uniform, ("attack", "overlap", "variant"))
        products = {
            "RQ2_uniform_raw.csv": uniform,
            "RQ2_uniform_summary.csv": summary,
            "RQ2_uniform_comparison.csv": role_reporting._uniform_comparisons(uniform),
            "RQ2_cold_raw.csv": cold,
            "RQ2_cold_summary.csv": role_reporting._summaries(cold, ("attack", "variant")),
            "RQ2_cold_comparison.csv": role_reporting._cold_comparisons(cold),
        }
    finally:
        role_reporting.SEEDS = previous_seeds
    for name, values in products.items():
        write_csv(output / name, values)
    reference = compare_table(summary, FIGURE_DATA / "RQ2_uniform_summary.csv",
                              ("attack", "overlap", "variant")) if mode == "full" else None
    searpc = [row for row in uniform if row["variant"] == "dual_role_three_state"]
    if any(row["data_malicious_trusted_rate"] != 0 for row in searpc):
        raise AssertionError("Observed malicious trusted authorization in a SEARPC cell")
    write_json(output / "VERIFICATION.json", {"mode": mode, "cells": len(jobs),
               "uniform_rows": len(uniform), "cold_rows": len(cold),
               "malicious_trusted_authorization_observed": False, "reference_comparison": reference})
    finish(output, record)


def domain_run(output: Path, mode: str, workers: int, resume: bool, external: bool) -> None:
    seeds = SEEDS if mode == "full" else SEEDS[:2]
    layouts = domain.LAYOUTS if mode == "full" else ("concentrated",)
    multiplicities = domain.MULTIPLICITIES if mode == "full" else (1, 7)
    traces = domain.load_traces(ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv")
    stage = "source-baselines" if external else "domain"
    kind = "external" if external else "domain"
    jobs = [(kind, (attack, traces[attack], layout, multiplicity, seed),
             f"{kind}__{attack}__{layout}__m{multiplicity}__seed{seed}")
            for attack in ATTACKS for layout in layouts for multiplicity in multiplicities for seed in seeds]
    record = provenance(stage, mode, seeds)
    records = evaluate(jobs, output, record, workers, resume)
    records.sort(key=lambda row: (row["attack"], row["layout"], row["multiplicity"], row["seed"], row["variant"]))
    if external:
        import identity_multiplicity_external as baseline
        summary = baseline.summarize(records)
        prefix = "IDENTITY_MULTIPLICITY_EXTERNAL"
        previous_seeds = baseline.SEEDS
        baseline.SEEDS = seeds
        try:
            if mode == "full":
                write_csv(output / f"{prefix}_slopes.csv", baseline.slope_summary(records))
        finally:
            baseline.SEEDS = previous_seeds
    else:
        summary = domain.summarize(records)
        prefix = "RQ3"
        # Expose the actual registered reporting grid, not the historical five-seed default.
        previous = domain.SEEDS, domain.LAYOUTS, domain.MULTIPLICITIES, domain.exact_sign_flip_pvalue
        domain.SEEDS, domain.LAYOUTS, domain.MULTIPLICITIES = seeds, layouts, multiplicities
        domain.exact_sign_flip_pvalue = exact_sign_flip
        try:
            write_csv(output / f"{prefix}_paired_effects.csv", domain.paired_effects(records))
        finally:
            domain.SEEDS, domain.LAYOUTS, domain.MULTIPLICITIES, domain.exact_sign_flip_pvalue = previous
    intervals = domain_intervals(records)
    write_csv(output / f"{prefix}_raw.csv", records)
    write_csv(output / f"{prefix}_summary.csv", summary)
    write_csv(output / f"{prefix}_summary_student_t.csv", intervals)
    frozen = FIGURE_DATA / ("IDENTITY_MULTIPLICITY_EXTERNAL_summary.csv" if external else "RQ3_summary_student_t.csv")
    comparison = None
    if mode == "full":
        if external:
            comparison = compare_table(summary, frozen, ("attack", "layout", "multiplicity", "variant", "weighting", "domain_cap"))
        else:
            comparison = compare_table(intervals, frozen, ("attack", "layout", "metric", "variant", "multiplicity"))
    write_json(output / "VERIFICATION.json", {"mode": mode, "cells": len(jobs),
               "rows": len(records), "reference_comparison": comparison})
    finish(output, record)


def finish(output: Path, record: dict) -> None:
    write_json(output / "OUTPUT_MANIFEST.json", {"configuration": record,
               "outputs": {path.name: digest(path) for path in sorted(output.glob("*.csv"))}})
    print(f"{record['stage']} {record['mode']}: PASS; outputs={output}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("inputs", "role", "domain", "source-baselines"))
    parser.add_argument("--mode", choices=("full", "smoke"), default="full")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--resume", action="store_true")
    arguments = parser.parse_args()
    if arguments.workers < 1:
        parser.error("--workers must be positive")
    verify_inputs()
    if arguments.stage == "inputs":
        bundle = load_bundle(ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz")
        traces = domain.load_traces(ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv")
        for attack in ATTACKS:
            trace, attackers, domains = bundle[attack]
            if len(trace) != 36382 or len(traces[attack]) != 36382:
                raise AssertionError("Unexpected sampled event count")
            if len(domains) != 1165 or len(attackers) != 233:
                raise AssertionError("Unexpected identity population")
            if not np.allclose(np.asarray([row[1:] for row in trace]), np.asarray(traces[attack]), rtol=0, atol=3e-16):
                raise AssertionError("Role/domain evidence alignment mismatch")
        print("Vehicle inputs: PASS (exact hashes; current loaders; two aligned 36,382-event traces)")
        return 0
    if arguments.output_dir is None:
        parser.error("--output-dir is required for an experiment")
    output = arguments.output_dir.resolve()
    if ROOT / "outputs" not in output.parents and (output == ROOT or ROOT in output.parents):
        parser.error("Repository outputs must be written below outputs/, not over distributed files")
    if arguments.stage == "role":
        role_run(output, arguments.mode, arguments.workers, arguments.resume)
    else:
        domain_run(output, arguments.mode, arguments.workers, arguments.resume,
                   external=arguments.stage == "source-baselines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
