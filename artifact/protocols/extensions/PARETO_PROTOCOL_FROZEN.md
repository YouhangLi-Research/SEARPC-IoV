# SEARPC-vs-TWSL Security-Coverage Pareto Protocol

Status: **FROZEN BEFORE ANY PARETO AGGREGATE WAS GENERATED OR VIEWED**.

This is a robustness/fairness evaluation of the frozen SEARPC method. It is not
an optimization experiment. No scientific parameter may be changed after
viewing Pareto outcomes.

## Purpose

The experiment tests whether SEARPC's lower malicious-provider authorization is
only a consequence of a more conservative decision threshold than the adapted
TWSL baseline.

## Frozen methods and conditions

- Methods: SEARPC role-specific three-state authorization and TWSL adapted to
  the VeReMi evaluation protocol (independent reimplementation).
- Attacks: `dataReplay`, `timeDelayAttack`.
- Role overlap: `0.0`, `0.5`, `1.0`.
- Seeds: the exact consecutive set `260825..260844` for both methods.
- Event stream: the frozen urban Train sampled sequence, 36,382 events per
  attack, 1,165 provider identities, 233 data attackers, stride 8.
- TWSL profile: `table_ii_literal`; communication quality `s=0.2`.
- All recommendation, noise, attack-window, delayed-adjudication, Beta/LCB,
  Domain-Cap, state-lock, recovery, trajectory, and message-evidence settings
  remain frozen.

## Decision threshold being swept

The threshold grid is fixed to `0.05, 0.06, ..., 0.95` (91 points, step 0.01).
The original primary threshold `0.50` is included.

Only the operational authorization readout changes:

- SEARPC authorizes a provider action when its data-role LCB is at least the
  swept threshold and the frozen malicious-state flag is false.
- TWSL authorizes a provider action when its continuous final reputation is at
  least the swept threshold.

The internal evidence/state threshold remains fixed at `0.50` for SEARPC's
failure/recovery observations and for TWSL's recommendation-history binning.
These are mechanism parameters, not swept decision thresholds. This separation
ensures that the sweep changes only participation readout and does not retune
online learning dynamics.

## Threshold-dynamics equivalence gate

At thresholds `0.05`, `0.50`, and `0.95`, a threshold-specific full replay must
be compared with the vectorized readout from the same continuous evidence
stream. All authorization counts must be identical. Only after this gate passes
may all 91 thresholds be evaluated from one continuous replay per method/cell.

The original five-seed primary point at threshold `0.50` must also reproduce
the frozen RQ2 SEARPC and TWSL values. Failure of either gate stops the sweep.

## Common operational plane and statistical unit

The common unit is a provider-action authorization opportunity in the frozen
event stream, matching the existing RQ2 rate definitions. It is not a count of
unique final identities and it is not an identical classifier ROC.

- X-axis: benign provider-action coverage = benign trusted / benign total;
  larger is better.
- Y-axis: malicious provider-action trusted rate = malicious trusted /
  malicious total; smaller is better.

For every attack, overlap, method, and threshold, the 20 seed-level rates are
reported using the seed as the independent unit, with Student-t 95% intervals
(`df=19`). The nondominated frontier is computed from the 20-seed means.

## Dominance rule

Point A dominates B iff `coverage_A >= coverage_B` and
`malicious_trusted_A <= malicious_trusted_B`, with at least one strict
inequality. No point is selected manually.

All six attack-by-overlap conditions are reported.

## Frozen operating summaries

Risk budgets are fixed to malicious trusted rate `<=0%`, `<=0.5%`, `<=1.0%`,
and `<=2.0%`. For each method and condition, report the largest mean benign
coverage among thresholds whose mean malicious trusted rate satisfies the
budget. An infeasible budget is `NA`; no extrapolation is allowed.

Matched-coverage targets are fixed to `80%`, `85%`, `90%`, and `95%`, with a
maximum absolute tolerance of `0.5` percentage point. Select the threshold with
the smallest absolute coverage distance; ties are resolved by lower malicious
trusted rate, then the numerically higher threshold. If none is feasible,
report `NA`.

No post-selection p-value is reported for a visually selected frontier point.

## Completeness and anomaly rules

- Raw schema: `seed, attack, overlap, method, threshold, benign_total,
  benign_trusted, benign_coverage, malicious_total, malicious_trusted,
  malicious_trusted_rate`.
- Expected raw size: `20 x 2 x 3 x 2 x 91 = 21,840` rows.
- All thresholds, seeds, and conditions remain in the output, including crossed
  or unfavorable frontier regions.
- Any scientific bug requires every affected seed/condition to be rerun. No
  isolated unfavorable result may be rerun or deleted.

## Interpretation rule

Frontier dominance, low-risk-budget advantage, or crossed frontiers are all
valid outcomes. If TWSL is strictly better over nearly the entire common
coverage range, the current explanation must be reassessed without retuning
SEARPC.

