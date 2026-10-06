from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .io import (
    load_config,
    parse_timestamp,
    read_interactions,
    read_local_opinions,
    read_trajectories,
    sha256_file,
    write_local_opinions,
    write_manifest,
    write_reputation_series,
    write_reputations,
)
from .pipeline import build_local_opinions, compute_reputations


SOURCE = {
    "title": "Blockchain for Secure and Efficient Data Sharing in Vehicular Edge Computing and Networks",
    "authors": "J. Kang et al.",
    "venue": "IEEE Internet of Things Journal 6(3), 4660-4670, 2019",
    "doi": "10.1109/JIOT.2018.2875542",
    "implemented_equations": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
}


def _implementation_identity(config) -> dict[str, object]:
    adapted = config.evaluation_protocol == "veremi_adapted"
    return {
        "official_author_code": False,
        "implementation_origin": "independent_reimplementation",
        "evaluation_protocol": config.evaluation_protocol,
        "status": (
            "veremi_adapted_reimplementation"
            if adapted
            else "paper_aligned_reimplementation"
        ),
        "adaptation_assumptions": {
            "finite_synchronized_history_window": config.history_window_seconds,
            "lcs_position_tolerance": config.lcs_position_tolerance,
            "missing_trajectory_policy": config.missing_trajectory_policy,
            "communication_quality_default": config.communication_quality_default,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="twsl-baseline",
        description="Independent paper-aligned TWSL reputation baseline",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="derive opinions from interactions and trajectories")
    run.add_argument("--interactions", required=True)
    run.add_argument("--trajectories", required=True)
    run.add_argument("--config", required=True)
    run.add_argument("--out-dir", required=True)
    run.add_argument("--snapshot-time")

    series = subparsers.add_parser(
        "series", help="compute the paper's periodic reputation updates"
    )
    series.add_argument("--interactions", required=True)
    series.add_argument("--trajectories", required=True)
    series.add_argument("--config", required=True)
    series.add_argument("--out-dir", required=True)
    series.add_argument("--start-time")
    series.add_argument("--end-time")

    fuse = subparsers.add_parser("fuse", help="fuse externally prepared local opinion vectors")
    fuse.add_argument("--opinions", required=True)
    fuse.add_argument("--config", required=True)
    fuse.add_argument("--out-dir", required=True)
    return parser


def _run(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    interactions = read_interactions(args.interactions, config)
    trajectories = read_trajectories(args.trajectories)
    snapshot_time = (
        parse_timestamp(args.snapshot_time)
        if args.snapshot_time
        else max(item.timestamp for item in interactions)
    )
    local_records = build_local_opinions(
        interactions, trajectories, config, snapshot_time
    )
    results = compute_reputations(local_records, config.gamma)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_local_opinions(out_dir / "local_opinions.csv", local_records)
    write_reputations(out_dir / "twsl_reputations.csv", results)
    write_manifest(
        out_dir / "manifest.json",
        {
            "implementation_version": __version__,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": SOURCE,
            "configuration": config.as_dict(),
            "paper_text_weight_conflict": config.paper_text_weight_conflict,
            "input_sha256": {
                "interactions": sha256_file(args.interactions),
                "trajectories": sha256_file(args.trajectories),
                "config": sha256_file(args.config),
            },
            "snapshot_time": snapshot_time,
            "interaction_rows": len(interactions),
            "trajectory_rows": len(trajectories),
            "local_opinion_rows": len(local_records),
            "reputation_rows": len(results),
            **_implementation_identity(config),
        },
    )


def _series(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    interactions = read_interactions(args.interactions, config)
    trajectories = read_trajectories(args.trajectories)
    if not interactions:
        raise ValueError("series mode requires at least one interaction")
    start = (
        parse_timestamp(args.start_time)
        if args.start_time
        else min(item.timestamp for item in interactions)
    )
    end = (
        parse_timestamp(args.end_time)
        if args.end_time
        else max(item.timestamp for item in interactions)
    )
    if end < start:
        raise ValueError("end time must not precede start time")
    snapshots: list[float] = []
    current = start + config.update_period_seconds
    while current <= end + 1e-9:
        snapshots.append(current)
        current += config.update_period_seconds
    if not snapshots:
        snapshots = [end]

    rows = []
    for snapshot in snapshots:
        local_records = build_local_opinions(
            interactions, trajectories, config, snapshot
        )
        rows.extend(
            (snapshot, record)
            for record in compute_reputations(local_records, config.gamma)
        )
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_reputation_series(out_dir / "twsl_reputation_series.csv", rows)
    write_manifest(
        out_dir / "manifest.json",
        {
            "implementation_version": __version__,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": SOURCE,
            "configuration": config.as_dict(),
            "paper_text_weight_conflict": config.paper_text_weight_conflict,
            "input_sha256": {
                "interactions": sha256_file(args.interactions),
                "trajectories": sha256_file(args.trajectories),
                "config": sha256_file(args.config),
            },
            "series_start_time": start,
            "series_end_time": end,
            "snapshot_count": len(snapshots),
            "reputation_rows": len(rows),
            **_implementation_identity(config),
        },
    )


def _fuse(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    local_records = read_local_opinions(args.opinions, config)
    results = compute_reputations(local_records, config.gamma)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    write_reputations(out_dir / "twsl_reputations.csv", results)
    write_manifest(
        out_dir / "manifest.json",
        {
            "implementation_version": __version__,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "source": SOURCE,
            "configuration": config.as_dict(),
            "paper_text_weight_conflict": config.paper_text_weight_conflict,
            "input_sha256": {
                "opinions": sha256_file(args.opinions),
                "config": sha256_file(args.config),
            },
            "local_opinion_rows": len(local_records),
            "reputation_rows": len(results),
            "external_weight_policy": "strict_eq10_validation",
            **_implementation_identity(config),
        },
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        _run(args)
    elif args.command == "series":
        _series(args)
    else:
        _fuse(args)
    return 0
