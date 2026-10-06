#!/usr/bin/env python3
"""Unified command-line entry point for the SEARPC reproducibility artifact."""

from __future__ import annotations

import argparse
import filecmp
import importlib
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent
ARTIFACT = ROOT / "artifact"
FIGURES = ROOT / "figures" / "experimental"
PYTHON_DIRS = (
    ARTIFACT / "code" / "participation_control",
    ARTIFACT / "code" / "scoped_evidence",
    ARTIFACT / "code" / "observable_selection",
    ARTIFACT / "code" / "frozen_searpc",
    ARTIFACT / "baselines" / "TWSL_VeReMi_Adapted_Baseline" / "src",
)


def _environment() -> dict[str, str]:
    env = os.environ.copy()
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = os.pathsep.join(
        [*(str(path) for path in PYTHON_DIRS), *(item for item in [current] if item)]
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.setdefault("MPLBACKEND", "Agg")
    return env


def _run(*parts: object, cwd: Path = ROOT, extra_env: dict[str, str] | None = None) -> None:
    command = [str(part) for part in parts]
    env = _environment()
    if extra_env:
        env.update(extra_env)
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def _require_empty(path: Path) -> Path:
    path = path.expanduser().resolve()
    if path.exists() and any(path.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _output_dir(command: str, supplied: Path | None) -> Path:
    if supplied is not None:
        return _require_empty(supplied)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = ROOT / "outputs" / f"{command}-{stamp}-{os.getpid()}"
    return _require_empty(candidate)


def _compare(reference_dir: Path, generated_dir: Path, names: tuple[str, ...]) -> None:
    for name in names:
        reference = reference_dir / name
        generated = generated_dir / name
        if not generated.is_file() or not filecmp.cmp(reference, generated, shallow=False):
            raise AssertionError(f"generated file differs from reference: {name}")
        print(f"byte-identical: {name}")


def doctor() -> None:
    if not ((3, 10) <= sys.version_info[:2] < (3, 14)):
        raise RuntimeError("SEARPC requires Python 3.10–3.13")
    modules = {
        "numpy": "numpy",
        "scipy": "scipy",
        "scikit-learn": "sklearn",
        "matplotlib": "matplotlib",
        "pandas": "pandas",
        "cryptography": "cryptography",
        "Pillow": "PIL",
    }
    missing: list[str] = []
    versions: list[tuple[str, str]] = []
    for label, module_name in modules.items():
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            missing.append(label)
            continue
        versions.append((label, str(getattr(module, "__version__", "available"))))
    required_files = (
        ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz",
        ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv",
        ROOT / "scripts" / "run_vehicle_experiments.py",
        ROOT / "scripts" / "paper_results.py",
        ROOT / "scripts" / "run_brs_authorization.py",
        ROOT / "scripts" / "check_adjudication_delivery.py",
        ARTIFACT / "code" / "participation_control" / "fsm_sensitivity.py",
        ARTIFACT / "code" / "participation_control" / "run_participation.py",
        ARTIFACT / "code" / "participation_control" / "yadav_shared7.py",
        ARTIFACT / "code" / "participation_control" / "brbc_participation.py",
        ARTIFACT / "code" / "participation_control" / "equal_audit_budget.py",
        ARTIFACT / "code" / "scoped_evidence" / "run_process_measurements.py",
        ARTIFACT / "results" / "participation_control" / "rq4_protocol_closed" / "RQ4_risk_stream.csv",
        ROOT / "figures" / "experimental" / "fig5_to_fig11" / "data" / "RQ2_uniform_summary.csv",
        ROOT / "MANIFEST.sha256",
    )
    absent = [str(path.relative_to(ROOT)) for path in required_files if not path.is_file()]
    print(f"Python: {platform.python_version()} ({platform.platform()})")
    for label, version in versions:
        print(f"  {label}: {version}")
    if missing or absent:
        if missing:
            print("Missing packages:", ", ".join(missing))
        if absent:
            print("Missing artifact files:", ", ".join(absent))
        raise SystemExit(2)
    print("Environment and required artifact files: PASS")


def checks() -> None:
    _run(sys.executable, ROOT / "scripts" / "run_vehicle_experiments.py", "inputs")
    _run(sys.executable, "-m", "unittest", "discover", "-s", ROOT / "tests", "-v")
    _run(
        sys.executable,
        ARTIFACT / "scripts" / "run_plain_function_tests.py",
        ARTIFACT / "tests" / "participation_control" / "test_authority_projections.py",
    )
    _run(
        sys.executable,
        ARTIFACT / "scripts" / "run_plain_function_tests.py",
        ARTIFACT / "tests" / "participation_control" / "test_external_baselines.py",
    )
    _run(
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "-s",
        ARTIFACT / "baselines" / "TWSL_VeReMi_Adapted_Baseline" / "tests",
        "-v",
    )
    _run(sys.executable, ROOT / "scripts" / "validate_results.py", "all")
    _run(sys.executable, ROOT / "scripts" / "verify_release.py")
    print("SEARPC verification suite: PASS")


def canonical(output: Path) -> None:
    risk_stream = ARTIFACT / "results" / "content_risk" / "content_risk" / "CONTENT_RISK.csv"
    _run(
        sys.executable,
        ARTIFACT / "code" / "participation_control" / "run_participation.py",
        "--risk-stream",
        risk_stream,
        "--output-dir",
        output,
    )
    names = (
        "RQ4_block_level.csv",
        "RQ4_paired_bootstrap.csv",
        "RQ4_risk_stream.csv",
        "RQ4_summary.csv",
    )
    _compare(ARTIFACT / "results" / "participation_control" / "rq4_protocol_closed", output, names)


def shared7(output: Path) -> None:
    yadav_out = output / "yadav"
    brbc_out = output / "brbc"
    yadav_out.mkdir()
    brbc_out.mkdir()
    risk_stream = ARTIFACT / "results" / "participation_control" / "rq4_protocol_closed" / "RQ4_risk_stream.csv"
    _run(
        sys.executable,
        ARTIFACT / "code" / "participation_control" / "yadav_shared7.py",
        "--risk-stream",
        risk_stream,
        "--output-dir",
        yadav_out,
    )
    _run(
        sys.executable,
        ARTIFACT / "code" / "participation_control" / "brbc_participation.py",
        "--risk-stream",
        risk_stream,
        "--output-dir",
        brbc_out,
    )
    _compare(
        ARTIFACT / "results" / "shared7_baseline" / "yadav_shared7",
        yadav_out,
        (
            "YADAV_SHARED7_block_level.csv",
            "YADAV_SHARED7_paired_inference.csv",
            "YADAV_SHARED7_per_trace.csv",
            "YADAV_SHARED7_risk_stream.csv",
            "YADAV_SHARED7_summary.csv",
            "YADAV_SHARED7_validation.csv",
        ),
    )
    _compare(
        ARTIFACT / "results" / "external_baselines" / "brbc_rq4",
        brbc_out,
        (
            "BRBC_RQ4_block_level.csv",
            "BRBC_RQ4_paired_inference.csv",
            "BRBC_RQ4_risk_stream.csv",
            "BRBC_RQ4_summary.csv",
        ),
    )
    print("Shared-seven deterministic reproduction: PASS")


def audit_budget(output: Path) -> None:
    """Reproduce audit-resource attribution without changing the scientific runner."""
    _run(
        sys.executable,
        ARTIFACT / "code" / "participation_control" / "equal_audit_budget.py",
        "--risk-stream",
        ARTIFACT / "results" / "participation_control" / "rq4_protocol_closed" / "RQ4_risk_stream.csv",
        "--output-dir",
        output,
    )
    _compare(
        ARTIFACT / "results" / "participation_control" / "equal_audit_budget",
        output,
        ("AUDIT_BUDGET_summary.csv",),
    )
    print("Audit-budget attribution reproduction: PASS")


def figures(output: Path) -> None:
    _run(
        sys.executable,
        FIGURES / "fig4" / "plot_fig4_current.py",
        "--outdir",
        output / "figure4",
    )
    _run(
        sys.executable,
        FIGURES / "fig5_to_fig11" / "run_all.py",
        extra_env={"SEARPC_FIGURE_OUTPUT_DIR": str(output / "figures5-11")},
    )
    print(f"Figures written to {output}")


def aggregate_check(stage: str) -> None:
    _run(sys.executable, ROOT / "scripts" / "validate_results.py", stage)


def vehicle_run(stage: str, output: Path, *, workers: int, resume: bool,
                mode: str = "full") -> None:
    command: list[object] = [sys.executable, ROOT / "scripts" / "run_vehicle_experiments.py",
                            stage, "--mode", mode, "--output-dir", output,
                            "--workers", workers]
    if resume:
        command.append("--resume")
    _run(*command)


def vehicle_output(command: str, supplied: Path | None, resume: bool) -> Path:
    if resume:
        if supplied is None:
            raise ValueError("--resume requires the original --output-dir")
        return supplied.expanduser().resolve()
    return _output_dir(command, supplied)


def message_evidence(output: Path, quick: bool) -> None:
    command: list[object] = [
        sys.executable, ARTIFACT / "code" / "frozen_searpc" / "run_clustered_bootstrap.py",
        "--predictions", FIGURES / "fig5_to_fig11" / "data" / "SEARPC_clustered_receiver_predictions.csv.gz",
        "--output-dir", output, "--compare-canonical",
    ]
    if quick:
        command.append("--quick")
    _run(*command)
    if not quick:
        import csv
        expected = ARTIFACT / "results" / "rq1" / "SEARPC_clustered_method_intervals.csv"
        generated = output / expected.name
        with expected.open(newline="", encoding="utf-8") as source:
            left = list(csv.DictReader(source))
        with generated.open(newline="", encoding="utf-8") as source:
            right = list(csv.DictReader(source))
        if len(left) != len(right):
            raise AssertionError("Message-evidence interval count mismatch")
        import math
        for frozen, observed in zip(left, right):
            for key, value in frozen.items():
                try:
                    equal = math.isclose(float(value), float(observed[key]), rel_tol=1e-10, abs_tol=1e-12)
                except ValueError:
                    equal = value == observed[key]
                if not equal:
                    raise AssertionError(f"Message-evidence reference mismatch in {key}")
    print("Message-evidence prediction-based reproduction: PASS")


def content_risk(output: Path) -> None:
    generated = output / "CONTENT_RISK.csv"
    _run(sys.executable, ARTIFACT / "code" / "participation_control" / "generate_content_risk.py",
         "--bundle", ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz",
         "--output", generated)
    _compare(ARTIFACT / "results" / "content_risk" / "content_risk", output, (generated.name,))
    print("Vehicle-to-protocol risk stream: PASS")


def system_run(output: Path, full: bool) -> None:
    command: list[object] = [
        sys.executable,
        ARTIFACT / "code" / "scoped_evidence" / "run_process_measurements.py",
    ]
    if full:
        command.extend(("--repeats", 5, "--blocks", 500, "--warmup", 5))
    else:
        command.append("--quick")
    command.extend(("--output-dir", output))
    _run(*command)


def adjudication(output: Path) -> None:
    _run(sys.executable, ROOT / "scripts/check_adjudication_delivery.py", "--output-dir", output)


def fsm_sensitivity(output: Path) -> None:
    _run(sys.executable, ARTIFACT / "code/participation_control/fsm_sensitivity.py",
         "--risk-stream", ARTIFACT / "results/participation_control/rq4_protocol_closed/RQ4_risk_stream.csv",
         "--output-dir", output)
    _compare(ARTIFACT / "results/participation_control/fsm_sensitivity", output,
             ("FSM_SENSITIVITY_summary.csv",))


def paper_results(output: Path | None = None, figure_output: Path | None = None) -> None:
    command = [sys.executable, ROOT / "scripts/paper_results.py"]
    if output is not None:
        command.extend(("--output-dir", output))
    if figure_output is not None:
        command.extend(("--figure-output", figure_output))
    _run(*command)


def data_check(data_root: Path) -> None:
    data_root = data_root.expanduser().resolve()
    if not data_root.is_dir():
        raise FileNotFoundError(data_root)
    candidates = [
        path
        for pattern in ("*.json", "*.json.gz", "*.zip")
        for path in data_root.rglob(pattern)
        if path.is_file()
    ]
    if not candidates:
        raise RuntimeError(f"no VeReMi-style JSON, JSON.GZ, or ZIP files found below {data_root}")
    total = sum(path.stat().st_size for path in candidates)
    print(f"Dataset root: {data_root}")
    print(f"Recognized files: {len(candidates)}")
    print(f"Total recognized bytes: {total}")
    print("Dataset presence check: PASS")


def _add_output_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="empty output directory; defaults to a new directory below outputs/",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="check the environment and required files")
    subparsers.add_parser("check", help="run tests and validate packaged results")
    paper_parser = subparsers.add_parser("paper-check", help="verify manuscript tables and figure correspondence")
    paper_parser.add_argument("--figure-output", type=Path)
    subparsers.add_parser("vehicle-inputs", help="verify bundled vehicle input hashes and alignment")
    replay_parser = subparsers.add_parser("safety-replay", help="replay a registered SEARPC/TWSL authorization sweep")
    _add_output_argument(replay_parser)
    replay_parser.add_argument("--method", choices=("SEARPC", "TWSL"), required=True)
    replay_parser.add_argument("--attack", choices=("dataReplay", "timeDelayAttack"), required=True)
    replay_parser.add_argument("--mode", choices=("original5", "full20"), default="full20")
    replay_parser.add_argument("--raw-root", type=Path, default=ROOT / "external_data" / "twsl_phase13_raw")
    for name, help_text in (
        ("role", "rerun all 20-seed role-authorization and cold-start cells"),
        ("domain", "rerun all 20-seed certified-domain mechanism cells"),
        ("source-baselines", "rerun stage-matched BRS and TWSL source-control comparisons"),
        ("vehicle-smoke", "run two-seed role/domain/source-baseline checks on complete traces"),
        ("vehicle", "rerun role, domain, and external source baselines"),
    ):
        child = subparsers.add_parser(name, help=help_text)
        _add_output_argument(child)
        child.add_argument("--workers", type=int, default=min(4, os.cpu_count() or 1))
        child.add_argument("--resume", action="store_true", help="resume the same provenance-bound run")
    for name, help_text in (
        ("canonical", "rerun and byte-compare the canonical participation experiment"),
        ("shared7", "rerun and byte-compare the Yadav and BRBC shared-seven comparisons"),
        ("audit-budget", "rerun shared, equal-budget, and adaptive audit attribution"),
        ("adjudication", "verify canonical adjudication delivery"),
        ("fsm-sensitivity", "rerun the 3x3 RSU lifecycle sensitivity grid"),
        ("brs-authorization", "rerun the 20-seed pooled Beta authorization threshold grid"),
        ("paper-results", "export and verify manuscript result tables"),
        ("figures", "regenerate Figures 4–11"),
        ("content-risk", "rebuild and compare the vehicle-derived protocol risk stream"),
        ("message-evidence", "recompute message metrics and 2,000 clustered-bootstrap replicates"),
        ("message-smoke", "recompute message metrics with 50 bootstrap replicates"),
        ("safety-coverage", "recompute safety/coverage reports from per-seed authorization counts"),
        ("system-smoke", "run the fast process-prototype smoke test"),
        ("system-full", "run the full 16/40-process paper configuration"),
        ("all", "run checks, deterministic experiments, figures, and process smoke test"),
        ("all-full", "run all bundled-input experiments and the full process configuration"),
    ):
        child = subparsers.add_parser(name, help=help_text)
        _add_output_argument(child)
    subparsers.add_parser("role-check", help="validate the role-authorization aggregate")
    subparsers.add_parser("domain-check", help="validate the certified-domain aggregate")
    subparsers.add_parser("system-check", help="validate the frozen process aggregate")
    data_parser = subparsers.add_parser("data-check", help="check a local VeReMi NextGen data directory")
    data_parser.add_argument("data_root", type=Path)
    args = parser.parse_args()

    if args.command == "doctor":
        doctor()
    elif args.command == "check":
        checks()
    elif args.command == "paper-check":
        paper_results(figure_output=args.figure_output)
    elif args.command == "paper-results":
        paper_results(_output_dir(args.command, args.output_dir))
    elif args.command == "adjudication":
        adjudication(_output_dir(args.command, args.output_dir))
    elif args.command == "fsm-sensitivity":
        fsm_sensitivity(_output_dir(args.command, args.output_dir))
    elif args.command == "brs-authorization":
        output = _output_dir(args.command, args.output_dir)
        _run(sys.executable, ROOT / "scripts/run_brs_authorization.py", "--output-dir", output)
        _compare(ARTIFACT / "results/brs_authorization", output,
                 ("BRS_authorization_raw.csv", "BRS_authorization_summary.csv"))
    elif args.command == "vehicle-inputs":
        _run(sys.executable, ROOT / "scripts" / "run_vehicle_experiments.py", "inputs")
    elif args.command == "safety-replay":
        if args.method == "TWSL" and not args.raw_root.is_dir():
            raise FileNotFoundError("TWSL trajectory replay requires --raw-root; see docs/DATA.md")
        output = _output_dir("safety-replay", args.output_dir)
        _run(sys.executable, ARTIFACT / "code" / "extensions" / "run_searpc_twsl_pareto.py",
             "--method", args.method, "--attack", args.attack, "--mode", args.mode,
             "--legacy-root", ARTIFACT / "code" / "participation_control",
             "--predictions", ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv",
             "--trace-bundle", ROOT / "data" / "derived" / "rq2_trace_bundle_exact.npz",
             "--raw-root", args.raw_root.resolve(),
             "--protocol", ARTIFACT / "protocols" / "extensions" / "PARETO_PROTOCOL_FROZEN.md",
             "--output-dir", output)
        import pandas as pd
        generated = pd.read_csv(output / f"{args.method}_{args.attack}_{args.mode}_pareto_raw.csv")
        reference = pd.read_csv(ARTIFACT / "results/safety_coverage/pareto_raw.csv")
        reference = reference[(reference.method == args.method) & (reference.attack == args.attack)]
        if args.mode == "original5":
            reference = reference[reference.seed < 260830]
        keys = ["method", "attack", "overlap", "seed", "threshold"]
        generated = generated[reference.columns].sort_values(keys).reset_index(drop=True)
        reference = reference.sort_values(keys).reset_index(drop=True)
        pd.testing.assert_frame_equal(generated, reference, check_dtype=False,
                                      check_exact=False, rtol=1e-12, atol=1e-12)
        print(f"Authorization threshold replay: PASS ({len(reference)} reference rows)")
    elif args.command in ("role", "domain", "source-baselines"):
        vehicle_run(args.command, vehicle_output(args.command, args.output_dir, args.resume),
                    workers=args.workers, resume=args.resume)
    elif args.command in ("vehicle", "vehicle-smoke"):
        base = vehicle_output(args.command, args.output_dir, args.resume)
        for stage in ("role", "domain", "source-baselines"):
            vehicle_run(stage, base / stage, workers=args.workers, resume=args.resume,
                        mode="smoke" if args.command == "vehicle-smoke" else "full")
    elif args.command == "role-check":
        aggregate_check("role")
    elif args.command == "domain-check":
        aggregate_check("domain")
    elif args.command == "system-check":
        aggregate_check("system")
    elif args.command == "data-check":
        data_check(args.data_root)
    elif args.command == "canonical":
        canonical(_output_dir("canonical", args.output_dir))
    elif args.command == "shared7":
        shared7(_output_dir("shared7", args.output_dir))
    elif args.command == "audit-budget":
        audit_budget(_output_dir("audit-budget", args.output_dir))
    elif args.command == "figures":
        figures(_output_dir("figures", args.output_dir))
    elif args.command in ("message-evidence", "message-smoke"):
        message_evidence(_output_dir(args.command, args.output_dir), quick=args.command == "message-smoke")
    elif args.command == "content-risk":
        content_risk(_output_dir("content-risk", args.output_dir))
    elif args.command == "safety-coverage":
        _run(sys.executable, ROOT / "scripts" / "recompute_safety_coverage.py",
             "--output-dir", _output_dir("safety-coverage", args.output_dir))
    elif args.command == "system-smoke":
        system_run(_output_dir("system-smoke", args.output_dir), full=False)
    elif args.command == "system-full":
        system_run(_output_dir("system-full", args.output_dir), full=True)
    elif args.command == "all":
        base = _output_dir("all", args.output_dir)
        checks()
        canonical(_require_empty(base / "canonical"))
        shared7(_require_empty(base / "shared7"))
        audit_budget(_require_empty(base / "audit-budget"))
        adjudication(_require_empty(base / "adjudication"))
        figures(_require_empty(base / "figures"))
        paper_results(figure_output=base / "figures")
        system_run(_require_empty(base / "system-smoke"), full=False)
        print(f"Complete SEARPC verification outputs: {base}")
    elif args.command == "all-full":
        base = _output_dir("all-full", args.output_dir)
        checks()
        for stage in ("role", "domain", "source-baselines"):
            vehicle_run(stage, base / stage, workers=min(4, os.cpu_count() or 1), resume=False)
        message_evidence(_require_empty(base / "message-evidence"), quick=False)
        _run(sys.executable, ROOT / "scripts" / "recompute_safety_coverage.py",
             "--output-dir", _require_empty(base / "safety-coverage"))
        for attack in ("dataReplay", "timeDelayAttack"):
            _run(sys.executable, ROOT / "run.py", "safety-replay", "--method", "SEARPC",
                 "--attack", attack, "--mode", "full20", "--output-dir", base / "safety-replay" / attack)
        content_risk(_require_empty(base / "content-risk"))
        canonical(_require_empty(base / "canonical"))
        shared7(_require_empty(base / "shared7"))
        audit_budget(_require_empty(base / "audit-budget"))
        adjudication(_require_empty(base / "adjudication"))
        fsm_sensitivity(_require_empty(base / "fsm-sensitivity"))
        _run(sys.executable, ROOT / "scripts/run_brs_authorization.py", "--output-dir", base / "brs-authorization")
        _compare(ARTIFACT / "results/brs_authorization", base / "brs-authorization",
                 ("BRS_authorization_raw.csv", "BRS_authorization_summary.csv"))
        figures(_require_empty(base / "figures"))
        paper_results(figure_output=base / "figures")
        system_run(_require_empty(base / "system-full"), full=True)
        print(f"All bundled-input experiments: PASS; outputs={base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
