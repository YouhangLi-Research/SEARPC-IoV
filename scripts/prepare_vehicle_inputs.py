#!/usr/bin/env python3
"""Export current-format role arrays from official urban logs and frozen predictions.

This optional provenance path requires the official extracted VeReMi NextGen
urban Train logs. Normal role/domain reproduction uses the bundled input files
and does not need raw archives or model retraining.
"""

from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
for name in reversed(("participation_control", "scoped_evidence", "observable_selection", "frozen_searpc")):
    sys.path.insert(0, str(ROOT / "artifact" / "code" / name))

from run_dual_role import _domain
from run_holdout_authorization import _load_holdout

EXPECTED_PREDICTION_HASH = "58a93ef9159a7a090654c8b3adc4ffb5eeaabd7f895049e32c4911ec5c82b915"
ATTACKS = {"dataReplay": "InTAS_urban_2_dataReplay",
           "timeDelayAttack": "InTAS_urban_2_timeDelayAttack"}


def digest(path):
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--urban-root", type=Path, required=True,
                        help="root containing the two InTAS_urban_2_* scenario directories")
    parser.add_argument("--predictions", type=Path,
                        default=ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Refusing to overwrite an existing NPZ")
    if digest(args.predictions) != EXPECTED_PREDICTION_HASH:
        raise ValueError("Frozen prediction hash mismatch")
    grouped = {attack: [] for attack in ATTACKS}
    with args.predictions.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            grouped[row["attack"]].append(row)
    arrays = {}
    alignment = {}
    for attack, folder in ATTACKS.items():
        _, labels, senders = _load_holdout(args.urban_root / folder / "Train" / "json")
        rows = grouped[attack]
        if len(rows) != 291050 or len(labels) != 291050:
            raise ValueError(f"Raw/prediction row accounting mismatch: {attack}")
        identities = tuple(sorted(set(senders)))
        index = {identity: i for i, identity in enumerate(identities)}
        for position, row in enumerate(rows):
            if int(row["holdout_row"]) != position or int(row["attacker"]) != int(labels[position]):
                raise ValueError(f"Raw/prediction ordering or label mismatch: {attack}, {position}")
        selected = np.arange(0, len(rows), 8)
        arrays[f"{attack}__provider_index"] = np.asarray([index[senders[i]] for i in selected], dtype=np.int32)
        arrays[f"{attack}__attacker"] = np.asarray(labels[selected], dtype=np.int8)
        arrays[f"{attack}__prob"] = np.asarray([float(rows[i]["contextual_probability"]) for i in selected])
        arrays[f"{attack}__uncertainty"] = np.asarray([float(rows[i]["contextual_uncertainty"]) for i in selected])
        arrays[f"{attack}__domains"] = np.asarray([_domain(identity) for identity in identities], dtype=np.int8)
        arrays[f"{attack}__data_attackers"] = np.asarray(sorted({index[sender] for sender, label in zip(senders, labels) if int(label)}), dtype=np.int32)
        alignment[attack] = {"raw_rows": len(rows), "sampled_events": len(selected), "identities": len(identities)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(args.output, **arrays)
    reference = ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz"
    equivalent = True
    with np.load(reference, allow_pickle=False) as frozen:
        for key, values in arrays.items():
            equal = np.array_equal(values, frozen[key]) if np.issubdtype(values.dtype, np.integer) else np.allclose(values, frozen[key], rtol=0, atol=3e-16)
            equivalent = equivalent and equal
    metadata = {"source_prediction_sha256": EXPECTED_PREDICTION_HASH,
                "export_sha256": digest(args.output), "sample_stride": 8,
                "alignment": alignment, "reference_arrays_equivalent": bool(equivalent),
                "comparison_float_absolute_tolerance": 3e-16}
    args.output.with_suffix(".json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))
    if not equivalent:
        raise AssertionError("Rebuilt arrays differ from the bundled reference")


if __name__ == "__main__":
    main()
