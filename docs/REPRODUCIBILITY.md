# Reproducing the SEARPC results

## Environment and validation

Install `requirements-verified.txt` with Python 3.12, or `requirements.txt` with another supported Python version (3.10–3.13).

```bash
python run.py doctor
python run.py vehicle-inputs
python run.py check
python run.py paper-check
```

The checks verify input hashes, event alignment, role/source grids, evidence authority, replay handling, registry commitments, baseline adapters, signature membership, local certificate thresholds, and the release file manifest. `paper-check` compares the manuscript's Tables XI–XXI with their source results and checks the indexed artwork.

## Full experiment workflow

```bash
python run.py all-full --output-dir outputs/full-run
```

The workflow runs the vehicle grids, the pooled-Beta authorization grid, clustered message evaluation, security–coverage replay and reporting, vehicle-derived risk construction, canonical participation, shared-seven baselines, audit-budget attribution, adjudication checks, lifecycle sensitivity, figure generation, and the full process configuration.

Individual commands support independent runs:

| Command | Outputs / scale |
| --- | --- |
| `role --workers 4` | 120 authorization cells and 40 cold-start cells; 20 seeds |
| `brs-authorization` | 120 paired pooled-Beta cells; 91 readout thresholds |
| `domain --workers 4` | 320 source-domain cells; four mechanism configurations per cell |
| `source-baselines --workers 4` | 320 cells; BRS and TWSL source comparisons |
| `message-evidence` | Metrics, intervals, paired differences; 2,000 clustered bootstrap resamples |
| `safety-coverage` | Five frontier/budget reports from 21,840 authorization-count rows |
| `content-risk` | 6,000-row vehicle-derived risk stream |
| `canonical` | Block-level results, risk stream, paired inference, and method summary |
| `shared7` | Ten paired traces each for Yadav/SEARPC and BRBC/SEARPC |
| `audit-budget` | Shared, equal-budget, and adaptive regimes; 90,000 block-method rows |
| `adjudication` | 36 controlled-stream error/delay cases |
| `fsm-sensitivity` | 3×3 parameter grid; ten 600-block trajectories per cell |
| `system-full` | 16/40 processes; 60 configuration-launch rows; 30,000 measured blocks |
| `paper-results` | Tables XI–XXI exported as CSV, with source correspondence checks |
| `figures` | Figures 4–11 in PNG and PDF |

Prefix commands with `python run.py`. Generated files go to new directories below `outputs/`; `--output-dir PATH` selects an empty destination. Source references remain in `artifact/results/` and the experimental figure data directory.

## Vehicle inputs and checkpoints

Role/source cells consume the complete 36,382-event trace for each attack. The exact NPZ bundle and 291,050-row per-attack holdout prediction table are in `data/derived/`. Highway Train/Validation partitions supply model fitting and calibration; urban partitions supply the separate evaluation inputs.

```bash
python run.py vehicle --workers 4 --output-dir outputs/vehicle-run
python run.py vehicle --workers 4 --output-dir outputs/vehicle-run --resume
```

Checkpoint reuse verifies inputs, source files, seeds, Python, and numerical dependencies. Worker count may change. `vehicle-smoke` uses two seeds with the complete event traces.

## Security–coverage replay

```bash
python run.py safety-replay --method SEARPC --attack dataReplay --mode full20
python run.py safety-replay --method SEARPC --attack timeDelayAttack --mode full20
```

The 91 readout thresholds span 0.05–0.95. Online update rules retain threshold 0.50. `full20` uses seeds 260825–260844; `original5` uses 260825–260829. The TWSL trajectory replay accepts `--raw-root`; its official-data layout is specified in `DATA.md`.

## Numerical verification

Deterministic protocol outputs use byte comparisons. Vehicle aggregates use `abs_tol=1e-12` and `rel_tol=1e-10` for floating-point interchange. Manuscript table checks use the displayed decimal precision. The process summary is recomputed from the included 30,000 block records, with p50/p95 calculated per launch before taking the five-launch median.

New process runs measure latency on the execution host. The distributed per-block and per-launch records reproduce Table XXI and Figure 11 exactly at their reported precision. Communication uses 1 KB = 1000 bytes.

## Figure reproduction

```bash
python run.py figures --output-dir outputs/paper-figures
python run.py paper-check --figure-output outputs/paper-figures
```

Figure 4 is written to `figure4/`; Figures 5–11 are written to `figures5-11/`. The figure index identifies the primary manuscript panels among the generated panels. Figures 1–3 are diagram source artwork in `figures/framework/`.

## Official-data workflows

`scripts/prepare_vehicle_inputs.py`, `scripts/retrain_vehicle_backend.py`, and `scripts/run_official_catch.py` provide explicit input/export, model-fitting, and pinned-source evaluation entries. Each accepts `--help`. The registered archive layouts and checksums are documented in `DATA.md`.
