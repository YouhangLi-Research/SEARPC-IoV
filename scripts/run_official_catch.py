#!/usr/bin/env python3
"""Run the pinned official CaTCH adapter with explicit external input paths."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "artifact" / "code" / "frozen_searpc"))
import run_catch_baseline as catch


def contextual_reference():
    """Recover the unchanged backend counts recorded in the original comparison."""
    path = ROOT / "artifact" / "results" / "rq1" / "SEARPC_catch_metrics.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = [row for row in csv.DictReader(handle) if row["method"] == "durac_contextual_calibrated"]
    indexed = {row["attack"]: row for row in rows}
    if set(indexed) != {"all", "dataReplay", "timeDelayAttack"}:
        raise ValueError("Frozen contextual comparison counts are incomplete")
    return indexed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official-repo", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    for path in (args.official_repo, args.data_root, args.archive_root):
        if not path.is_dir():
            raise FileNotFoundError(path)
    output = args.output_dir.resolve()
    if output == ROOT or (ROOT in output.parents and ROOT / "outputs" not in output.parents):
        parser.error("Repository outputs must be below outputs/")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Refusing to overwrite a non-empty destination")
    catch.DATA_ROOT = args.data_root.resolve()
    catch.ARCHIVE_ROOT = args.archive_root.resolve()
    catch.OUTPUT_DIR = output
    catch.PROTOCOL = ROOT / "artifact" / "protocols" / "frozen" / "SEARPC_CATCH_PROTOCOL.md"
    catch.PHASE9_METRICS = ROOT / "artifact" / "results" / "rq1" / "SEARPC_catch_metrics.csv"
    catch.load_durac_phase9 = contextual_reference
    sys.argv = [str(Path(catch.__file__)), "--official-repo", str(args.official_repo.resolve()), "--workers", str(args.workers)]
    catch.main()


if __name__ == "__main__":
    main()
