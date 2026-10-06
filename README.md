# SEARPC

**Secure Interaction in Vehicular Consortium Blockchains through Scoped Evidence Authorization and RSU Participation Control**

SEARPC translates vehicle evidence and delivered RSU audits into executable authorization and participation decisions. It separates data-provider and opinion-provider histories, bounds the contribution of identities from a common certified domain, and reconfigures fixed-size RSU candidates from canonical audit records. Final confirmation retains the registered validator set and fixed BFT quorum.

This repository contains the implementation, experiment inputs, baseline adapters, per-seed and per-block results, statistical analysis, figure sources, and accompanying manuscript. The paper's result tables and experimental figures are linked to their machine-readable sources.

## Contents

- [Method overview and contributions](#method-overview-and-contributions)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Recommended reproduction workflow](#recommended-reproduction-workflow)
- [Reproduce the experiments](#reproduce-the-experiments)
- [Outputs and numerical verification](#outputs-and-numerical-verification)
- [Results](#results)
- [Repository structure](#repository-structure)
- [Data and figure sources](#data-and-figure-sources)
- [Resources and execution planning](#resources-and-execution-planning)
- [Troubleshooting and repository updates](#troubleshooting-and-repository-updates)
- [Reproduction documentation](#reproduction-documentation)
- [Citation and license](#citation-and-license)

## Method overview and contributions

Vehicular interaction involves distinct decisions: whether a vehicle may provide data, how much weight its opinion receives, and whether an RSU remains eligible for fast participation. SEARPC connects these decisions to the evidence available at their respective decision points. Vehicle-side evidence controls authorization and recommendation influence; canonical RSU audits control future participation. Both operate alongside a fixed final-confirmation quorum.

The implementation comprises three connected components:

1. **Message evidence and scoped authorization.** Calibrated message probabilities and evidence reliability are combined with separate data-provider and opinion-provider histories. Conservative readouts determine role-specific permissions. Opinion history does not automatically grant data-provider authority.
2. **Certified-domain aggregation.** Eligible opinions are aggregated within their certified source domains before cross-domain fusion. Domain weighting limits the influence gained by adding correlated identities. The event summary combines calibrated message evidence, data-role history, and domain recommendations.
3. **Canonical-audit-driven participation control.** Delivered audit records update RSU eligibility through Active, Quarantine, and Probation states. Same-size candidate reconfiguration changes participation opportunities while retaining the registered final validator population and quorum.

The accompanying evaluation examines malicious authorization and benign coverage, identity-multiplicity effects, audit-driven participation and matched-resource baselines, and executable certificate-handoff costs. The artifact provides the implementations, adapted baselines, experiment specifications, granular results, and plotting sources needed to inspect those claims.

## Installation

Use Python 3.10–3.13. The verified environment is CPython 3.12.14 on Linux x86_64; exact dependency versions are in `requirements-verified.txt`.

Unpack the release archive and open the `SEARPC-IoV` directory:

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-verified.txt
python run.py doctor
```

For other supported Python versions, install `requirements.txt`. Conda and Docker definitions are also provided.

### Obtaining the repository

A release archive contains the full bundled inputs and result files. When cloning the Git repository, install Git LFS and retrieve the two tracked result files:

```bash
git lfs install
git clone https://github.com/YouhangLi-Research/SEARPC-IoV.git
cd SEARPC-IoV
git lfs pull
```

Run subsequent commands from the repository root, where `run.py` is located. The included derived inputs support the main reproduction workflow without downloading the original traffic archives.

### Alternative environments

For Conda:

```bash
conda env create -f environment.yml
conda activate searpc
python run.py doctor
```

For Docker, build from the repository root:

```bash
docker build -t searpc-iov .
docker run --rm searpc-iov
```

The image's default command runs the verification suite. The Conda definition and Docker image use the compatible dependency ranges in the repository; `requirements-verified.txt` records the exact verified Python environment.

## Quick start

```bash
python run.py check
python run.py paper-check
python run.py paper-results
python run.py figures
```

`check` runs the mechanism, adapter, input-alignment, certificate, and result-integrity checks. `paper-check` verifies the numerical correspondence of Tables XI–XXI and the indexed figure assets. `paper-results` exports those tables from the result sources. `figures` generates Figures 4–11 as PNG and PDF panels.

## Recommended reproduction workflow

### 1. Validate the environment and distributed artifact

```bash
python run.py doctor
python run.py vehicle-inputs
python run.py check
python run.py paper-check
```

These commands check dependency availability, input hashes and event alignment, functional behavior, granular result consistency, file integrity, and manuscript correspondence. A successful `paper-check` reports **11 tables, 227 cells, and 28 experimental panels**. No raw traffic archive or model refitting is required for this step.

### 2. Export the paper tables and regenerate the experimental figures

```bash
python run.py paper-results --output-dir outputs/paper-tables
python run.py figures --output-dir outputs/paper-figures
python run.py paper-check --figure-output outputs/paper-figures
```

The table export contains `Table_XI.csv` through `Table_XXI.csv` and `PAPER_CORRESPONDENCE.json`, which records the checked cells and source hashes. Figure 4 is written under `outputs/paper-figures/figure4/`; Figures 5–11 are written under `outputs/paper-figures/figures5-11/`. [The figure index](figures/FIGURE_INDEX.md) maps generated panels to the manuscript.

Figure regeneration reads the distributed result sources. Experiment reruns write to their own output directories; they do not replace the publication reference data used by the plotting scripts.

### 3. Rerun experiments with the bundled inputs

```bash
python run.py all-full --output-dir outputs/full-run
```

This runs the vehicle authorization and source-domain grids, message evaluation, security–coverage analyses, content-risk construction, canonical participation, external selection baselines, audit-budget attribution, adjudication delivery, lifecycle sensitivity, pooled-Beta authorization, figure generation, and full process measurements. Outputs are grouped by experiment beneath `outputs/full-run/`.

To inspect a single mechanism, use its individual command in the table below. For a smaller initial execution check:

```bash
python run.py vehicle-smoke --workers 2 --output-dir outputs/vehicle-smoke
python run.py message-smoke --output-dir outputs/message-smoke
python run.py system-smoke --output-dir outputs/system-smoke
```

The vehicle smoke run uses two seeds on complete event traces; the message smoke run uses 50 bootstrap resamples. Use the full commands for the paper's registered experiment scales.

### 4. Reconstruct inputs or refit the message backend from official data

[Data acquisition and preprocessing](docs/DATA.md) provides the archive layouts, registered checksums, and commands for `scripts/prepare_vehicle_inputs.py`, `scripts/retrain_vehicle_backend.py`, and `scripts/run_official_catch.py`. The trajectory-based TWSL replay also requires its documented raw receiver and mobility logs. Keep externally downloaded archives outside the repository.

## Reproduce the experiments

| Evaluation | Paper location | Command |
| --- | --- | --- |
| Message discrimination and calibration | Tables XI–XII; Figure 5 | `python run.py message-evidence` |
| Role authorization and cold start | Tables XIII, XV; Figure 6 | `python run.py role --workers 4` |
| Pooled BRS authorization | Tables XIII–XIV | `python run.py brs-authorization` |
| Security–coverage frontier | Table XIV; Figure 7 | `python run.py safety-coverage` |
| Certified-domain aggregation | Tables XVI–XVII; Figure 8 | `python run.py domain --workers 4` |
| BRS/TWSL source comparisons | Table XVIII | `python run.py source-baselines --workers 4` |
| Shared-seven participant selection | Table XIX; Figure 9 | `python run.py shared7` |
| Vehicle-derived content-risk stream | Protocol input | `python run.py content-risk` |
| Canonical participation and ablations | Table XX; Figures 9–10 | `python run.py canonical` |
| Equal-audit resource attribution | Section 4.4.3 | `python run.py audit-budget` |
| Adjudication delivery | Section 4.4.3 | `python run.py adjudication` |
| Lifecycle parameter sensitivity | Section 4.4.3 | `python run.py fsm-sensitivity` |
| Fixed-quorum process measurements | Table XXI; Figure 11 | `python run.py system-full` |
| All experimental figures | Figures 4–11 | `python run.py figures` |

The role, domain, and source-baseline grids contain 160, 320, and 320 cells, respectively, with 20 paired seeds and 36,382 events per attack trace. Message evaluation uses 813,602 predictions and 2,000 receiver-cluster bootstrap resamples. Participant-selection comparisons use ten paired 40-RSU trajectories, `k=13`, and `Q=27`. The process configuration uses 16 and 40 processes, five independent launches, five warm-up blocks, and 500 measured blocks per configuration: 30,000 measured blocks in total.

```bash
# Complete bundled-input workflow
python run.py all-full

# Functional vehicle and process checks
python run.py vehicle-smoke --workers 4
python run.py system-smoke

# SEARPC threshold replay; repeat with --attack timeDelayAttack
python run.py safety-replay --method SEARPC --attack dataReplay --mode full20
```

Commands write to a new directory below `outputs/`. Use `--output-dir PATH` for a specific empty destination. Long vehicle runs support checkpoints:

```bash
python run.py vehicle --workers 4 --output-dir outputs/vehicle-run
python run.py vehicle --workers 4 --output-dir outputs/vehicle-run --resume
```

## Outputs and numerical verification

By default, an experiment creates a new timestamped directory under `outputs/`. A supplied `--output-dir` must be empty for a new run. Long vehicle runs can reuse their original directory with `--resume`; checkpoint reuse checks input and execution provenance.

| Output family | Representative files | How to inspect it |
| --- | --- | --- |
| Vehicle role and source-domain grids | Per-seed raw CSVs, summary CSVs, interval CSVs, `OUTPUT_MANIFEST.json`, `VERIFICATION.json` | Compare the aggregate and interval reports with the corresponding Tables XIII–XVIII |
| Message discrimination | `SEARPC_clustered_method_intervals.csv` and paired comparison reports | Inspect discrimination and calibration metrics for Tables XI–XII |
| Vehicle-derived protocol input | `CONTENT_RISK.csv` | Compare the generated risk stream with the registered reference |
| Canonical participation | `RQ4_block_level.csv`, `RQ4_summary.csv`, `RQ4_paired_bootstrap.csv`, `RQ4_risk_stream.csv` | Inspect per-block decisions, aggregate exposure, and paired inference |
| Shared-seven baselines | Separate `yadav/` and `brbc/` output directories | Inspect matched traces, method summaries, and paired differences |
| Paper tables | `Table_XI.csv`–`Table_XXI.csv`, `PAPER_CORRESPONDENCE.json` | Inspect manuscript values and source hashes |
| Experimental figures | PNG and PDF panels in `figure4/` and `figures5-11/` | Use the figure index and `paper-check --figure-output` |
| Process measurements | Per-block CSVs, per-launch statistics, measurement manifest | Inspect commit status, quorum, latency, and accounted bytes |

Deterministic protocol commands compare generated files against the distributed reference CSVs. Vehicle aggregates are checked using numerical tolerances and the paper's displayed precision. Message evaluation uses receiver-cluster bootstrap intervals and paired comparisons. The measurement summaries are recomputed from block records by calculating statistics for each launch, then taking the median across five launches.

Two complementary checks are available:

```bash
# Scientific and functional consistency, plus distributed file integrity
python run.py check

# Numerical correspondence to the manuscript and indexed figure assets
python run.py paper-check
```

[Result definitions](docs/RESULTS.md) explain metric denominators, units, evidence levels, and the interpretation of the comparisons. [The verification record](docs/VERIFICATION.md) summarizes the included experimental grids and records.

## Results

| Evaluation | Reported SEARPC result |
| --- | --- |
| Malicious data-provider authorization | Zero observed trusted authorization in six attack-overlap conditions |
| Same-domain 1→7 identity expansion | Influence increment about 0.019; 0.560–0.628 below BRS/TWSL |
| Shared-seven participant selection | Risk-weighted exposure 8.025%; 10.797–11.832 percentage points below Yadav/BRBC |
| Same-size reconfiguration | Exposure 8.285%→5.732%; equal-audit-budget benefit 0.615 percentage points |
| 40-process Fetch measurements | Five-launch p95 median 115.62→70.56 ms; communication 1428.9→1019.6 KB/block |

Communication uses **1 KB = 1000 bytes**. Process latency is measured over same-host TCP execution; launch-level p95 values are summarized by their median. The included block records reproduce the paper's measurement summaries and plotted launch distributions. New process executions measure the same configuration on the local machine.

The process prototype implements block-integrity checks, Ed25519 signature verification, availability handling, and fixed-quorum certificate handoff. The canonical audit and RSU lifecycle are evaluated in the separate paired protocol trajectories. BFT locking, view changes, and conflicting-proposal handling belong to the integrated base protocol.

## Repository structure

```text
SEARPC-IoV/
├── run.py                     # experiment and verification commands
├── data/derived/              # registered vehicle inputs
├── artifact/code/             # scientific implementation and runners
├── artifact/baselines/        # published-method adapters
├── artifact/protocols/        # experiment specifications
├── artifact/results/          # per-seed results, block records, and summaries
├── figures/                   # framework artwork and experimental plotting code
├── paper/                     # manuscript source and PDF
├── results/                   # result index and release verification
├── scripts/                   # data, table, and validation utilities
└── docs/                      # detailed reproduction and data instructions
```

## Data and figure sources

Vehicle experiments use VeReMi NextGen. The release includes the registered event arrays, calibrated holdout predictions, urban-test predictions, and authorization counts used by the reported analyses. [Data instructions](docs/DATA.md) describe the official archives, model-training entry, pinned CaTCH source, and trajectory-based TWSL replay.

Figures 1–3 are supplied as final PDF artwork with SVG and PNG derivatives. Figures 4–11 are generated from the distributed result data. [The figure index](figures/FIGURE_INDEX.md) identifies every manuscript panel and its source asset.

## Resources and execution planning

The bundled analysis and experiment runners execute on the CPU; a GPU is not required. Linux with Python 3.12 and the pinned dependency file is the verified reference environment. The process experiment requires an environment that permits Python multiprocessing and local TCP connections.

| Workload | Execution considerations |
| --- | --- |
| Artifact and manuscript checks | Read existing files and recompute validation summaries; start here before launching experiment grids |
| Table and figure generation | Uses bundled result sources; figure rendering requires Matplotlib and Pillow |
| Vehicle role/domain/baseline grids | Process 36,382 events per attack across the registered cells and 20 seeds; use worker control and checkpoints |
| Message uncertainty analysis | Processes 813,602 predictions and 2,000 clustered-bootstrap resamples in the full configuration |
| Participation trajectories | Uses ten paired 40-RSU trajectories with fixed candidate and final-quorum settings |
| Full process measurements | Launches 16/40 worker processes across five repeats and 500 measured blocks per configuration |

Wall-clock time and peak memory depend on the host, dependency versions, and worker count. Increase `--workers` only when memory allows; use `--workers 1` or `--workers 2` on a smaller machine. The full workflow is substantially larger than table/figure regeneration or the smoke commands. No fixed runtime estimate is assumed across machines.

For timing comparisons, record the CPU, operating system, Python and dependency versions, process load, and measurement configuration. New process runs produce measurements for that host. The distributed block records provide the paper's original launch-level distributions and reported summaries.

## Troubleshooting and repository updates

### An import or dependency check fails

Activate the environment used for installation, and use the same Python executable for both installation and execution:

```bash
python -m pip install -r requirements-verified.txt
python run.py doctor
```

Use `requirements.txt` for supported Python versions other than the verified Python 3.12 environment. Optional official-data backends may have additional dependencies specified by their pinned source checkout.

### A tracked result file contains a Git LFS pointer

Run `git lfs pull` in the repository root. A pointer begins with the Git LFS specification URL instead of the expected CSV header. The GitHub verification workflow retrieves LFS objects during checkout. A complete release archive already contains the CSV data.

### A new command refuses an existing output directory

Choose a new empty destination. For a previously interrupted vehicle run, use its original directory and `--resume`:

```bash
python run.py vehicle --workers 2 --output-dir outputs/vehicle-run --resume
```

The resume option applies to the vehicle commands that expose it. Other commands create independent output directories.

### Figure or process execution is blocked by the local environment

The plotting entry point selects a noninteractive Matplotlib backend. Install the listed plotting dependencies if an import fails. Process runs need local socket and multiprocessing permissions; run them in an environment that permits localhost TCP communication and avoid competing heavy workloads during measurement.

### A manifest mismatch appears after intentionally editing the repository

`MANIFEST.sha256` records the exact bytes of distributed files, including `README.md`. When making an intentional repository update, rebuild the manifest after finishing the edits and commit it together with the modified files:

```bash
python scripts/build_manifest.py
python scripts/verify_release.py
python run.py check
python run.py paper-check
```

For an unchanged download, retrieve the complete original files if a hash differs. Keep the tracked `.gitattributes` file: it preserves CSV and binary asset bytes and uses LF endings for text files. Refreshing the manifest documents an intentional change; the scientific correspondence checks still run independently.

### Which files should be included in a bug report?

Provide the command, complete error traceback, Python version, operating system, dependency versions, and the relevant output manifest. For a numerical discrepancy, identify the method, attack, seed or trace, metric, and manuscript table or figure. Reports can be submitted through the repository's GitHub Issues page.

## Reproduction documentation

- [Experiment commands and output mapping](docs/REPRODUCIBILITY.md)
- [Data acquisition and preprocessing](docs/DATA.md)
- [Baseline definitions and adaptations](docs/BASELINES.md)
- [Process prototype and timing](docs/PROTOTYPE.md)
- [Result definitions](docs/RESULTS.md)
- [Verification record](docs/VERIFICATION.md)

## Citation and license

Please cite the accompanying manuscript when using the method or experimental results. Repository citation metadata is supplied in [`CITATION.cff`](CITATION.cff), which GitHub exposes through **Cite this repository**. The manuscript source and PDF are in [`paper/`](paper/).

SEARPC code is released under the [MIT License](LICENSE). Dataset attribution and third-party terms are recorded in [the data README](data/README.md) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md). Derived VeReMi NextGen data retains its documented dataset attribution and CC BY 4.0 terms; third-party material follows its corresponding notices.
