#!/usr/bin/env python3
"""Validate manuscript-facing SEARPC traces and aggregate results."""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from hashlib import sha256
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifact"
FIGURE_DATA = ROOT / "figures" / "experimental" / "fig5_to_fig11" / "data"
YADAV = ARTIFACT / "results" / "shared7_baseline" / "yadav_shared7"
BRBC = ARTIFACT / "results" / "external_baselines" / "brbc_rq4"


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def close(actual: str | float, expected: float, tolerance: float = 1e-12) -> None:
    if not math.isclose(float(actual), expected, rel_tol=0.0, abs_tol=tolerance):
        raise AssertionError(f"expected {expected}, observed {actual}")


def verify_manifest(directory: Path, manifest_name: str, runner_name: str) -> None:
    manifest = json.loads((directory / manifest_name).read_text(encoding="utf-8"))
    for name, expected in manifest["outputs"].items():
        path = directory / name
        if not path.is_file() or digest(path) != expected:
            raise AssertionError(f"output hash mismatch: {path.relative_to(ROOT)}")
    runner = ARTIFACT / "code" / "participation_control" / runner_name
    if digest(runner) != manifest.get("current_runner_sha256", manifest["runner_sha256"]):
        raise AssertionError(f"runner hash mismatch: {runner_name}")


def verify_block_pairs(path: Path, expected_methods: set[str]) -> None:
    records = rows(path)
    if len(records) != 12_000:
        raise AssertionError(f"expected 12,000 method rows in {path.name}")
    counts = Counter(row["method"] for row in records)
    if set(counts) != expected_methods or any(count != 6_000 for count in counts.values()):
        raise AssertionError(f"unexpected method counts in {path.name}: {counts}")
    paired: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in records:
        paired[(row["repeat"], row["block"])].append(row)
    if len(paired) != 6_000:
        raise AssertionError(f"expected 6,000 paired blocks in {path.name}")
    repeats = Counter(key[0] for key in paired)
    if set(repeats) != {str(index) for index in range(1, 11)}:
        raise AssertionError(f"unexpected trace identifiers in {path.name}")
    if any(count != 600 for count in repeats.values()):
        raise AssertionError(f"each trace must contain 600 blocks in {path.name}")
    shared_fields = (
        "risk_score",
        "evidence_root",
        "seed_projection_root",
        "audit_plan_projection_root",
        "audit_plan_output_root",
        "registry_root",
        "beacon_digest",
        "audits",
        "audit_target_ids",
        "audit_behavior_outcomes",
        "final_Q",
    )
    for key, pair in paired.items():
        if len(pair) != 2 or {row["method"] for row in pair} != expected_methods:
            raise AssertionError(f"unpaired method rows at trace/block {key}")
        left, right = pair
        for field in shared_fields:
            if left[field] != right[field]:
                raise AssertionError(f"{field} mismatch at trace/block {key}")
        for row in pair:
            if row["audit_regime"] != "shared_exogenous_7" or row["audits"] != "7":
                raise AssertionError(f"audit-budget mismatch at trace/block {key}")
            if row["final_Q"] != "27":
                raise AssertionError(f"final-Q mismatch at trace/block {key}")
            if row["final_legal_commit"] != "1" or row["final_illegal_acceptance"] != "0":
                raise AssertionError(f"finality invariant failed at trace/block {key}")


def check_shared7() -> None:
    verify_manifest(YADAV, "YADAV_SHARED7_manifest.json", "yadav_shared7.py")
    verify_block_pairs(
        YADAV / "YADAV_SHARED7_block_level.csv",
        {"yadav_direct_history_shared_audits", "searpc_shared_audits"},
    )
    yadav_summary = {row["method"]: row for row in rows(YADAV / "YADAV_SHARED7_summary.csv")}
    close(yadav_summary["yadav_direct_history_shared_audits"]["risk_weighted_exposure"], 0.18822456756178702)
    close(yadav_summary["searpc_shared_audits"]["risk_weighted_exposure"], 0.08024999118835462)
    yadav_inference = next(
        row
        for row in rows(YADAV / "YADAV_SHARED7_paired_inference.csv")
        if row["metric"] == "risk_weighted_exposure"
    )
    close(yadav_inference["searpc_minus_yadav_mean"], -0.10796145484059444)
    if yadav_inference["searpc_lower_count"] != "10":
        raise AssertionError("SEARPC is not lower than Yadav in all ten traces")

    verify_manifest(BRBC, "BRBC_RQ4_manifest.json", "brbc_participation.py")
    verify_block_pairs(
        BRBC / "BRBC_RQ4_block_level.csv",
        {"brbc_eligibility", "searpc_core_shared_audits"},
    )
    brbc_summary = {row["method"]: row for row in rows(BRBC / "BRBC_RQ4_summary.csv")}
    close(brbc_summary["brbc_eligibility"]["risk_weighted_exposure"], 0.19857363730110067)
    close(brbc_summary["searpc_core_shared_audits"]["risk_weighted_exposure"], 0.08024999118835462)
    brbc_inference = next(
        row
        for row in rows(BRBC / "BRBC_RQ4_paired_inference.csv")
        if row["metric"] == "risk_weighted_exposure"
    )
    close(brbc_inference["searpc_minus_brbc_mean"], -0.11831012510364271)
    if brbc_inference["searpc_favorable_count"] != "10":
        raise AssertionError("SEARPC is not lower than BRBC in all ten traces")
    print("Shared-seven traces: PASS (6,000 paired blocks per comparison; k=13; Q=27)")


def check_role() -> None:
    records = rows(FIGURE_DATA / "RQ2_uniform_summary.csv")
    searpc = [row for row in records if row["variant"] == "dual_role_three_state"]
    if len(records) != 12 or len(searpc) != 6:
        raise AssertionError("unexpected role-authorization aggregate cardinality")
    if any(int(row["repeats"]) != 20 for row in records):
        raise AssertionError("role-authorization cells do not retain 20 seeds")
    if any(float(row["data_malicious_trusted_rate_mean"]) != 0.0 for row in searpc):
        raise AssertionError("malicious data-role trusted authorization was observed")
    print("Role authorization: PASS (six SEARPC cells; 20 seeds; no observed malicious trusted authorization)")


def check_domain() -> None:
    records = rows(FIGURE_DATA / "RQ3_summary_student_t.csv")
    if len(records) != 64:
        raise AssertionError("unexpected certified-domain aggregate cardinality")
    grouped: dict[tuple[str, str], dict[int, float]] = {}
    for row in records:
        if row["layout"] != "concentrated":
            continue
        grouped.setdefault((row["attack"], row["variant"]), {})[int(row["multiplicity"])] = float(row["mean"])
    increments = []
    for attack in ("dataReplay", "timeDelayAttack"):
        values = grouped[(attack, "lcb_cap")]
        increments.append(values[7] - values[1])
    if not all(0.0190 <= value <= 0.0192 for value in increments):
        raise AssertionError(f"unexpected SEARPC 1-to-7 increments: {increments}")
    print(f"Certified-domain control: PASS (1-to-7 increments {increments[0]:.6f}, {increments[1]:.6f})")


def check_system() -> None:
    records = rows(FIGURE_DATA / "SEARPC_process_per_launch.csv")
    if len(records) != 60:
        raise AssertionError("unexpected process-aggregate cardinality")
    if any(int(row["blocks"]) != 500 for row in records):
        raise AssertionError("process cells do not retain 500 measured blocks")
    if any(int(row["successful_commits"]) != 500 for row in records):
        raise AssertionError("a legal process launch failed to commit")
    q40 = {int(row["final_quorum"]) for row in records if int(row["process_count"]) == 40}
    if q40 != {27}:
        raise AssertionError(f"unexpected 40-process quorum: {q40}")
    print("Process prototype: PASS (60 launches; 500 blocks/cell; all legal commits; 40-process Q=27)")


def check_vehicle_raw() -> None:
    paths = (
        (ARTIFACT / "results" / "vehicle_role" / "RQ2_uniform_raw.csv", 240),
        (ARTIFACT / "results" / "vehicle_role" / "RQ2_cold_raw.csv", 80),
        (ARTIFACT / "results" / "vehicle_domain" / "RQ3_raw.csv", 1280),
        (ARTIFACT / "results" / "vehicle_source_baselines" / "IDENTITY_MULTIPLICITY_EXTERNAL_raw.csv", 640),
    )
    for path, expected in paths:
        records = rows(path)
        if len(records) != expected or {int(row["seed"]) for row in records} != set(range(260825, 260845)):
            raise AssertionError(f"Vehicle grid/seed accounting mismatch: {path.name}")
    from statistics import mean
    external = rows(paths[-1][0])
    domain = rows(paths[-2][0])
    labels = {"brs_identity_pooling": "BRS", "twsl_local_identity_pooling": "TWSL", "lcb_cap": "SEARPC"}
    grouped = defaultdict(list)
    for row in external + domain:
        if row["layout"] == "concentrated" and row["variant"] in labels:
            grouped[(labels[row["variant"]], row["attack"], int(row["multiplicity"]))].append(float(row["early_adversarial_weight_share"]))
    for reference in rows(ROOT / "results" / "PAPER_SOURCE_INFLUENCE_REFERENCE.csv"):
        key = reference["method"], reference["attack"]
        increment = mean(grouped[(*key, 7)]) - mean(grouped[(*key, 1)])
        close(increment, float(reference["influence_increment_1_to_7"]), float(reference["increment_absolute_tolerance"]))
        if reference["n7_early_adversarial_share"]:
            close(mean(grouped[(*key, 7)]), float(reference["n7_early_adversarial_share"]), float(reference["n7_absolute_tolerance"]))
    for folder in ("vehicle_role", "vehicle_domain", "vehicle_source_baselines"):
        directory = ARTIFACT / "results" / folder
        manifest = json.loads((directory / "OUTPUT_MANIFEST.json").read_text())
        for name, expected in manifest["outputs"].items():
            if digest(directory / name) != expected:
                raise AssertionError(f"Vehicle output hash mismatch: {folder}/{name}")
    print("Vehicle raw results: PASS (20 seeds; role/cold/domain/external grids; rounded manuscript source claims)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("role", "domain", "vehicle", "shared7", "system", "all"))
    args = parser.parse_args()
    selected = ("role", "domain", "vehicle", "shared7", "system") if args.stage == "all" else (args.stage,)
    functions = {
        "role": check_role,
        "domain": check_domain,
        "vehicle": check_vehicle_raw,
        "shared7": check_shared7,
        "system": check_system,
    }
    for stage in selected:
        functions[stage]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
