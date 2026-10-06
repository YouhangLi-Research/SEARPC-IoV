# Data

## External vehicle dataset

The paper uses one public vehicle dataset: **VeReMi NextGen**. Raw archives and
generator source are not copied into this repository. Exact derived inputs
are included for the vehicle authorization and source-control experiments;
their source attribution and CC BY 4.0 terms are recorded in `data/README.md`.

- Official repository: <https://github.com/VeReMi-dataset/VeReMi-NextGen>
- Dataset record: use the Zenodo link provided by the official repository for the desired release.

## Bundled vehicle inputs

The two registered inputs are in `data/derived/`:

- `rq2_trace_bundle_exact.npz`: two sampled event traces, provider/attacker
  indices, frozen probabilities and uncertainties, and domain assignments;
- `SEARPC_holdout_holdout_predictions.csv`: the ordered 291,050-row urban
  Train holdout predictions for each of Data Replay and Time Delay attacks.

The highway Train and Validation portions are used to fit and calibrate the
message backend. The urban Train portion is an external holdout for the role
experiments, not a training portion of that backend. Sampling every eighth
holdout row gives 36,382 role/source events per attack. The separate message
evaluation uses urban Test predictions for 406,801 messages per attack.

```bash
python run.py vehicle-inputs
python run.py role
python run.py domain
python run.py source-baselines
```

These commands do not require raw archives and do not refit a model. Certified
source domains in the stress experiments are controlled input assignments;
they are not claimed to be cryptographic domain certificates provided by
VeReMi NextGen. Attack labels are used for offline scoring and for the
configured delayed adjudication stream, not as directly readable online
authorization decisions.

## Optional official-data reconstruction

Normal reproduction uses the bundled original inputs. For an independent
raw-log alignment/export check, provide the official urban Train directories:

```bash
python scripts/prepare_vehicle_inputs.py \
  --urban-root /absolute/path/urban-scenarios \
  --output outputs/input-export/rq2_trace_bundle_exact.npz
```

The directory must contain
`InTAS_urban_2_dataReplay/Train/json/` and
`InTAS_urban_2_timeDelayAttack/Train/json/`. The exporter validates row order,
labels, and the frozen prediction hash, emits the current NPZ key schema, and
compares its arrays with the distributed reference. Repackaged NPZ bytes need
not have the original ZIP-container hash; array equality and sub-ULP CSV
rounding tolerance are checked explicitly. Normal commands keep using the
original byte-identical bundle.

The original message backend can also be refitted with explicit paths:

```bash
python scripts/retrain_vehicle_backend.py \
  --development-root /absolute/path/highway-scenarios \
  --urban-root /absolute/path/urban-scenarios \
  --nested-archive-root /absolute/path/registered-urban-archives \
  --output-dir outputs/backend-refit --workers 4
```

The development root contains the two `InTAS_highway_2_*` scenario folders,
each with `Train/json/` and `Validation/json/`. The nested-archive root
contains `dataReplay/InTAS_urban_2_dataReplay.zip` and
`timeDelayAttack/InTAS_urban_2_timeDelayAttack.zip`, the registered nested
holdout archives. Their SHA-256 values are respectively
`2e46d7231012cdd2bc45cc003727696c343952e3006ee02e55913cca4d6d3b47`
and `f96649235e8efe72ee2d2cdf4234dbdae819275eb7665d4c6dfd56144b6f6c1c`.
The runner verifies these records rather than accepting a different split.
See the associated conditional trust protocol and loader for archive accounting.

Model fitting uses the registered highway Train/Validation partitions and
exports calibrated predictions for the urban partitions. Keep the original
registered inputs alongside any newly fitted model outputs for comparison.

## Other official-data adapters

Keep downloaded archives outside the Git repository. A recommended local layout is:

```text
external_data/
├── veremi_nextgen_development/
├── veremi_nextgen_external/
├── veremi_nextgen_development_archives/
└── veremi_nextgen_external_archives/
```

The historical adapters accept the following environment variables:

```bash
export SEARPC_VEREMI_DEVELOPMENT_ROOT=/absolute/path/veremi_nextgen_development
export SEARPC_VEREMI_EXTERNAL_ROOT=/absolute/path/veremi_nextgen_external
export SEARPC_VEREMI_PHASE8_ARCHIVE_ROOT=/absolute/path/veremi_nextgen_development_archives
export SEARPC_VEREMI_PHASE9_ARCHIVE_ROOT=/absolute/path/veremi_nextgen_external_archives
```

On Windows PowerShell, use `$env:NAME = "C:\path\..."`.

After extraction, confirm that recognized VeReMi files are present:

```bash
python run.py data-check /absolute/path/to/external_data
```

The CaTCH adapter additionally expects an authorized checkout of the official VeReMi NextGen source at commit `acda994bae9966df6ae2f292a2945d8d91e249ce`. The adapter verifies the pinned commit and the expected source-file hashes before evaluation.

```bash
python scripts/run_official_catch.py \
  --official-repo /absolute/path/VeReMi-NextGen \
  --data-root /absolute/path/urban-scenarios \
  --archive-root /absolute/path/registered-urban-archives \
  --output-dir outputs/catch-review --workers 4
```

The data root contains `InTAS_urban_2_dataReplay/Test/json/` and
`InTAS_urban_2_timeDelayAttack/Test/json/`. The archive root contains the
corresponding `InTAS_urban_2_dataReplay.zip` and
`InTAS_urban_2_timeDelayAttack.zip` files registered in
`artifact/protocols/frozen/SEARPC_CATCH_PROTOCOL.md`. Archive MD5 values,
the official commit, and the relevant source SHA-256 values are checked by the
adapter. The frozen contextual-backend comparison counts are read from the
original catch baseline metrics included with this repository. Install any additional
dependencies specified by the pinned official checkout before executing it.

### Trajectory-based TWSL safety/coverage sweep

The included per-seed counts are sufficient to rebuild the reported
safety/coverage summaries with `python run.py safety-coverage`. To repeat the
TWSL trajectory simulation itself, supply the originally structured raw logs:

```text
twsl_phase13_raw/
├── dataReplay/urban_2_dataReplay/
└── timeDelayAttack/urban_2_timeDelayAttack/
```

These scenario directories must contain receiver logs and vehicle trajectory
logs, not only the normalized `Train/json/` message files. The TWSL loader uses
receive times and trajectory similarity, which cannot be reconstructed from
the calibrated prediction CSV alone.

```bash
python run.py safety-replay --method TWSL --attack dataReplay \
  --mode full20 --raw-root /absolute/path/twsl_phase13_raw \
  --output-dir outputs/twsl-safety-review

python run.py safety-replay --method SEARPC --attack dataReplay \
  --mode full20 --output-dir outputs/searpc-safety-review
```

Repeat these commands for `timeDelayAttack`. `original5` selects seeds
260825–260829; `full20` selects seeds 260825–260844. The readout thresholds are
0.05–0.95 in steps of 0.01. Only the readout is swept: online update thresholds
remain fixed at 0.50. Neither command overwrites distributed reference files.

## Included protocol data

The 40-RSU paired trajectories are not a second traffic dataset. They are deterministic protocol-level traces built from the included frozen risk stream. They test how the same audit sequence and validator population are converted into participation decisions by SEARPC and the external participant-selection rules.

The 16/40-process outputs are likewise not dataset samples. They are measurements from an executable same-host protocol prototype that validates data availability, signature collection, fixed final quorum, latency, and communication accounting.

## Data provenance rules

- Test labels are used for offline evaluation and for generating delayed adjudication records; online state updates consume only records delivered at or before the current canonical height.
- External baselines receive the input information available at their matched decision stage.
- Yadav, BRBC, and SEARPC share the same per-block audit budget and finality configuration in the paired comparison.
- Generated files should be written under `outputs/` or another empty directory, never into `artifact/`.
