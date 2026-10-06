#!/usr/bin/env python3
"""Raw-data loader shared by the matched external baselines/21 message-evidence experiments.

Raw VeReMi archives are intentionally not redistributed.  When they are placed
under the documented development/external roots (or supplied through the
SEARPC_VEREMI_DEVELOPMENT_ROOT and SEARPC_VEREMI_EXTERNAL_ROOT environment
variables), this loader reconstructs the exact contextual matrices expected by
clustered bootstrap.  The packaged prediction-based clustered bootstrap mode does not require these
archives.
"""

from __future__ import annotations

import os
from pathlib import Path

from run_context_evaluation import ATTACKS, _load


PACKAGE_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DEVELOPMENT_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_DEVELOPMENT_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase8",
    )
)
DEFAULT_EXTERNAL_ROOT = Path(
    os.environ.get(
        "SEARPC_VEREMI_EXTERNAL_ROOT",
        PACKAGE_ROOT / "external_data" / "veremi_nextgen_phase9",
    )
)


def _load_registered_data(
    development_root: Path | None = None,
    external_root: Path | None = None,
):
    development_root = Path(development_root or DEFAULT_DEVELOPMENT_ROOT)
    external_root = Path(external_root or DEFAULT_EXTERNAL_ROOT)
    loaded: dict[str, dict[str, tuple]] = {"Train": {}, "Validation": {}, "Test": {}}
    audits = []
    test_slices = {}
    start = 0
    for split in ("Train", "Validation", "Test"):
        for attack, definition in ATTACKS.items():
            if split == "Test":
                root = external_root / definition["external_folder"] / split / "json"
            else:
                root = development_root / definition["development_folder"] / split / "json"
            if not root.exists():
                raise FileNotFoundError(
                    "Raw VeReMi data are not bundled. Missing: "
                    f"{root}. Use Phase 21 --from-predictions for the bundled "
                    "recomputation path, or set SEARPC_VEREMI_DEVELOPMENT_ROOT/"
                    "SEARPC_VEREMI_EXTERNAL_ROOT to official extracted archives."
                )
            _, contextual, labels, audit = _load(root)
            loaded[split][attack] = (contextual, labels)
            audits.append(audit)
            if split == "Test":
                test_slices[attack] = slice(start, start + len(labels))
                start += len(labels)
    return loaded, audits, test_slices


__all__ = ["_load_registered_data"]
