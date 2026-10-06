#!/usr/bin/env python3
"""Optional official-data entry for the frozen highway-to-urban evidence backend.

The normal artifact rerun starts from bundled calibrated predictions. This
entry refits the existing backend when the official logs and registered nested
urban archives are supplied, without changing scientific thresholds or seeds.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for name in reversed(("participation_control", "scoped_evidence", "observable_selection", "frozen_searpc")):
    sys.path.insert(0, str(ROOT / "artifact" / "code" / name))

import run_conditional_trust as backend


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development-root", type=Path, required=True)
    parser.add_argument("--urban-root", type=Path, required=True)
    parser.add_argument("--nested-archive-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    for path in (args.development_root, args.urban_root, args.nested_archive_root):
        if not path.is_dir():
            raise FileNotFoundError(path)
    output = args.output_dir.resolve()
    if output == ROOT or (ROOT in output.parents and ROOT / "outputs" not in output.parents):
        parser.error("Repository outputs must be placed below outputs/")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Refusing to overwrite a non-empty output directory")
    backend.DEVELOPMENT_ROOT = args.development_root.resolve()
    backend.HOLDOUT_ROOT = args.urban_root.resolve()
    backend.NESTED_ROOT = args.nested_archive_root.resolve()
    backend.OUTPUT_DIR = output
    backend.PROTOCOL = ROOT / "artifact" / "protocols" / "frozen" / "SEARPC_CONDITIONAL_TRUST_PROTOCOL.md"
    if not backend.PROTOCOL.is_file():
        raise FileNotFoundError(backend.PROTOCOL)
    sys.argv = [str(Path(backend.__file__)), "--workers", str(args.workers)]
    backend.main()


if __name__ == "__main__":
    main()
