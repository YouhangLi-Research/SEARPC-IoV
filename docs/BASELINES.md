# Baseline provenance and comparison scope

SEARPC is evaluated in three stage-matched groups. Each group aligns the input information, decision output, and relevant resource budget for that stage.

| Published method | Evaluation layer | Adaptation used in this artifact | Evidence |
| --- | --- | --- | --- |
| RF | Message evidence | Same message features and test partition | Prediction-based metric/bootstrap rerun |
| HGBDT | Message evidence | Same message features and test partition | Prediction-based metric/bootstrap rerun |
| CaTCH | Message evidence | Pinned official VeReMi NextGen implementation | Executable adapter plus manuscript aggregate |
| BRS | Role/source authorization | Same delivered opinions and identity multiplicity | Full 20-seed source-grid rerun; manuscript projection check |
| TWSL | Role/source authorization | Independent paper-aligned implementation | Full 20-seed source-grid rerun; separate trajectory adapter |
| Yadav | RSU participant selection | Same 40-RSU pool, seven audits/block, `k=13`, `Q=27` | Deterministic block-level paired trace |
| BRBC | RSU participant selection | Same 40-RSU pool, seven audits/block, `k=13`, `Q=27` | Deterministic block-level paired trace |

## CaTCH

The adapter is `artifact/code/frozen_searpc/run_catch_baseline.py`. It pins the official VeReMi NextGen repository to commit `acda994bae9966df6ae2f292a2945d8d91e249ce` and verifies the SHA-256 values of the official source files used by the adapter. Raw VeReMi archives and third-party source are not redistributed.

Use `scripts/run_official_catch.py` for the public entry with explicit paths.
The required checkout, archive layout, and command are described in `DATA.md`.

## BRS and TWSL

`python run.py brs-authorization` evaluates pooled Beta histories on the registered role traces, using 20 paired seeds and 91 readout thresholds. Provider outcomes and recommender honesty share one history and retain the same delayed delivery. All frontier methods report benign trusted actions divided by benign authorization opportunities.

BRS and TWSL are used at the role/source authorization layer. The TWSL package is located at `artifact/baselines/TWSL_VeReMi_Adapted_Baseline/` and includes its own tests, configuration profiles, example inputs, schema, citation record, and mapping documentation.

These methods do not natively implement SEARPC's RSU lifecycle or fixed-finality fast-path control. Their comparison is therefore confined to the stage where they produce a trust or opinion-aggregation decision.

Run `python run.py source-baselines` for the source-domain identity expansion
comparison from the bundled calibrated input. This is the source-stage BRS
posterior-mean and TWSL local-opinion adaptation used by the manuscript; it
does not claim to rerun the entire systems in the source papers. The more
detailed TWSL trajectory/interaction path requires official raw trajectories
and is distinct from this source-stage experiment.

`python run.py safety-coverage` recomputes the safety/coverage reports from
included per-seed counts. `python run.py safety-replay --method TWSL ...`
executes the separate trajectory-based threshold sweep when the raw logs are
supplied. The count-based reporting and the raw trajectory replay are recorded
as different reproduction paths.

## Yadav and BRBC

Yadav and BRBC are compared at the participant-selection layer. Each paired row shares the same frozen risk score, evidence root, seed projection, registry root, audit plan, audit targets, audit outcomes, fast-candidate size, and final quorum. This design isolates the participant-selection rule rather than changing the evidence or budget between methods.

The executable outputs are located at:

- `artifact/results/shared7_baseline/yadav_shared7/`
- `artifact/results/external_baselines/brbc_rq4/`

Run `python run.py shared7` to regenerate and byte-compare them.

## Ablations and protocol controls

Mechanism-level ablations identify the independent contribution of role separation, certified-domain bounding, and same-size candidate reconfiguration. Static `k=13` and the full participant set are protocol controls, not published external baselines. They are reported separately from the seven published methods.

The canonical runner preserves its original method identifiers so deterministic
reference files remain byte-identical:

| Stored identifier | Interpretation |
| --- | --- |
| `validator_only` | SEARPC main participation path; warning threshold 2; content extension disabled |
| `feedback_fixed` | SEARPC w/o Same-k Reconfiguration; delivered audits and lifecycle retained |
| `searpc` | SEARPC with the separately enabled canonical content-risk extension; threshold may be 1 for a delivered high-risk record |
| `content_only` | Optional content-trigger control configuration |
| `static_k13` | Protocol-trajectory control without audit-driven lifecycle updates |

The shared-seven comparisons use the main SEARPC path. In the process prototype,
`fixed_k13` instead denotes size-fixed deterministic rotation, and
`searpc_conditioned` denotes rotation with synthetic-warning conditioning.
These process selectors measure execution cost and do not reproduce the
canonical audit state transitions. Their exact selectors are documented in
`PROTOTYPE.md`.

