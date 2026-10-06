#!/usr/bin/env python3
"""Validate the frozen block-level Yadav and BRBC shared-seven traces."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from hashlib import sha256
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "artifact"
YADAV = EXP / "results" / "shared7_baseline" / "yadav_shared7"
BRBC = EXP / "results" / "external_baselines" / "brbc_rq4"


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def read_rows(path: Path) -> list[dict[str, str]]:
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
    runner = EXP / "code" / "participation_control" / runner_name
    if digest(runner) != manifest.get("current_runner_sha256", manifest["runner_sha256"]):
        raise AssertionError(f"runner hash mismatch: {runner_name}")


def verify_block_pairs(path: Path, expected_methods: set[str]) -> None:
    rows = read_rows(path)
    if len(rows) != 12_000:
        raise AssertionError(f"expected 12,000 method rows in {path.name}")
    counts = Counter(row["method"] for row in rows)
    if set(counts) != expected_methods or any(count != 6_000 for count in counts.values()):
        raise AssertionError(f"unexpected method counts in {path.name}: {counts}")
    keys = defaultdict(list)
    for row in rows:
        keys[(row["repeat"], row["block"])].append(row)
    if len(keys) != 6_000:
        raise AssertionError(f"expected 6,000 paired blocks in {path.name}")
    repeats = Counter(key[0] for key in keys)
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
    for key, pair in keys.items():
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


def verify_yadav() -> None:
    verify_manifest(
        YADAV,
        "YADAV_SHARED7_manifest.json",
        "yadav_shared7.py",
    )
    verify_block_pairs(
        YADAV / "YADAV_SHARED7_block_level.csv",
        {"yadav_direct_history_shared_audits", "searpc_shared_audits"},
    )
    summary = {
        row["method"]: row
        for row in read_rows(YADAV / "YADAV_SHARED7_summary.csv")
    }
    close(summary["yadav_direct_history_shared_audits"]["risk_weighted_exposure"], 0.18822456756178702)
    close(summary["searpc_shared_audits"]["risk_weighted_exposure"], 0.08024999118835462)
    close(summary["yadav_direct_history_shared_audits"]["mean_total_wire_messages"], 558.881)
    close(summary["searpc_shared_audits"]["mean_total_wire_messages"], 393.60966666666667)
    inference = next(
        row
        for row in read_rows(YADAV / "YADAV_SHARED7_paired_inference.csv")
        if row["metric"] == "risk_weighted_exposure"
    )
    close(inference["searpc_minus_yadav_mean"], -0.10796145484059444)
    close(inference["ci95_low"], -0.11741881707010585)
    close(inference["ci95_high"], -0.09891123459264532)
    close(inference["exact_sign_flip_p"], 0.001953125)
    if inference["searpc_lower_count"] != "10":
        raise AssertionError("Yadav comparison is not favorable in all ten traces")
    validation = read_rows(YADAV / "YADAV_SHARED7_validation.csv")[0]
    if validation["all_pairing_and_protocol_checks_pass"] != "1":
        raise AssertionError("Yadav pairing/protocol validation failed")


def verify_brbc() -> None:
    verify_manifest(
        BRBC,
        "BRBC_RQ4_manifest.json",
        "brbc_participation.py",
    )
    verify_block_pairs(
        BRBC / "BRBC_RQ4_block_level.csv",
        {"brbc_eligibility", "searpc_core_shared_audits"},
    )
    summary = {
        row["method"]: row
        for row in read_rows(BRBC / "BRBC_RQ4_summary.csv")
    }
    close(summary["brbc_eligibility"]["risk_weighted_exposure"], 0.19857363730110067)
    close(summary["searpc_core_shared_audits"]["risk_weighted_exposure"], 0.08024999118835462)
    close(summary["brbc_eligibility"]["mean_total_wire_messages"], 581.267)
    close(summary["searpc_core_shared_audits"]["mean_total_wire_messages"], 393.60966666666667)
    inference = next(
        row
        for row in read_rows(BRBC / "BRBC_RQ4_paired_inference.csv")
        if row["metric"] == "risk_weighted_exposure"
    )
    close(inference["searpc_minus_brbc_mean"], -0.11831012510364271)
    close(inference["ci95_low"], -0.12809086948062998)
    close(inference["ci95_high"], -0.11017599366405495)
    close(inference["exact_sign_flip_p"], 0.001953125)
    if inference["searpc_favorable_count"] != "10":
        raise AssertionError("BRBC comparison is not favorable in all ten traces")


def main() -> int:
    verify_yadav()
    verify_brbc()
    print("SEARPC shared-seven raw-trace validation: PASS (12,000 method rows per comparison)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
