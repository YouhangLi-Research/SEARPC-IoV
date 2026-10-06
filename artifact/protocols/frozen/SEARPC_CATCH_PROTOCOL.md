# DURAC-IoV catch baseline CaTCH strong-baseline protocol

Date frozen: 2026-08-25

## 1. Purpose and non-retuning boundary

catch baseline compares the frozen context evaluation contextual message-evidence result with
the official VeReMi NextGen CaTCH-MBD implementation.  It is a strong-baseline
evaluation, not another model-development phase.

- The DURAC probabilities, isotonic calibration and threshold are read from the
  existing context evaluation outputs and are not refit.
- Only the already-viewed official `InTAS_urban_2` Test messages for data replay
  and time delay are evaluated.
- No catch baseline result may be used to change a context evaluation feature, window, model,
  calibrator or threshold on this Test set.
- The frozen CBTDS trust implementation remains outside this experiment.

## 2. Official source and parameters

The source is the official public repository
`https://github.com/VeReMi-dataset/VeReMi-NextGen.git` at commit
`acda994bae9966df6ae2f292a2945d8d91e249ce`.

The official CaTCH functions and official message processing function are run
without source edits.  The runner verifies the SHA-256 digests of all six
official Python files before execution.

For a fair highway-to-urban external test, CaTCH receives the published
**Highway 2AM / low-density** optimized parameters.  The published Urban 2AM
parameters are prohibited because they were optimized for the external target
environment.

| Parameter | Frozen value |
| --- | ---: |
| MPR | 309.270 |
| MPDN | -2.742 |
| MPS | 56.064 |
| MPA | 3.138 |
| MPD | 6.131 |
| MHC | 115.995 |
| MDI | 3.757 |
| MTD | 1.538 |
| PHT | 1.837 |
| MMRU | 1.168 |
| MMRD | 2.902 |
| MNRS | 0.490 |

`MAX_SA_RANGE=150.0` and `MAX_SA_TIME=2.1` retain the official class defaults.
The official CaTCH path currently comments out the sudden-appearance check, so
these two defaults do not affect a CaTCH decision.

## 3. Frozen data and accounting

| Attack | Test messages | Archive MD5 |
| --- | ---: | --- |
| `dataReplay` | 406,801 | `3f3d752b4169475ebc5cb17fd8fa59cd` |
| `timeDelayAttack` | 406,801 | `c5fa8415f36807639e52ddcc5f473878` |

Every receiver JSON file is passed to the official processing function.  The
per-file confusion counts are retained and must aggregate to exactly 406,801
messages per attack and 813,602 messages pooled.

## 4. Fair metrics

CaTCH's official decision is binary: a message is malicious when any active
check factor is below 0.5.  The official implementation does not expose a
single calibrated anomaly probability.  catch baseline therefore reports only
metrics that are valid for both methods at their frozen native operating point:

- malicious recall and false-negative rate;
- false-positive rate and malicious precision;
- malicious F1 and Macro-F1;
- accuracy and complete confusion counts;
- wall-clock processing time as a diagnostic, not a hardware-independent
  complexity claim.

PR-AUC, ROC-AUC, Brier score and ECE are reported for DURAC elsewhere but are
marked not applicable for binary CaTCH.  No pseudo-probability is constructed
from the minimum check factor after viewing Test labels.

## 5. Registered interpretation lines

The strong-baseline result supports the context evaluation message-evidence claim only if:

1. official source hashes, commit and both archive MD5 values match;
2. all 813,602 Test messages are accounted for;
3. DURAC Macro-F1 is at least 0.05 above CaTCH on both attacks;
4. DURAC recall is higher on both attacks; and
5. DURAC FPR is not more than 1 percentage point above CaTCH on either attack.

Failure remains a result.  Passing these lines establishes superiority at the
two frozen native operating points on this cross-environment test; it does not
establish universal superiority to all physical MBD systems or all VeReMi
attacks.

## 6. Next boundary

No message-model change is authorized by catch baseline.  After this result, the next
new experiment is the pre-registered dual-role and closed-loop ablation.  Any
new message-evidence design requires a different untouched scenario or dataset.
