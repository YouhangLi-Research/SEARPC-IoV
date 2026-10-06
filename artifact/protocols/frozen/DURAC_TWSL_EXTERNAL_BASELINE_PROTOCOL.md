# DURAC external TWSL baseline protocol

Date frozen: 2026-08-27

Status: frozen before any TWSL result was computed

## 1. Purpose and claim boundary

This experiment adds one external vehicular reputation baseline: TWSL from
Kang et al., IEEE Internet of Things Journal, 2019,
DOI `10.1109/JIOT.2018.2875542`. The code is an independent reimplementation,
not author code. TWSL is compared only on reputation and recommendation-fusion
outcomes. It is not compared on committee exposure, finality, or process
latency.

## 2. Frozen data and event stream

- Official VeReMi NextGen v1 record: `10.5281/zenodo.19665762`.
- Subsets: `InTAS_urban_2_dataReplay` and
  `InTAS_urban_2_timeDelayAttack`, official Urban Train split.
- Outer archive MD5 values: `3f3d752b4169475ebc5cb17fd8fa59cd`
  and `c5fa8415f36807639e52ddcc5f473878`.
- Inner Train archive SHA-256 values:
  `2e46d7231012cdd2bc45cc003727696c343952e3006ee02e55913cca4d6d3b47`
  and `f96649235e8efe72ee2d2cdf4234dbdae819275eb7665d4c6dfd56144b6f6c1c`.
- Receiver files are sorted lexicographically; rows retain their original file
  order; every eighth row from index zero is evaluated. This is the unchanged
  conditional trust stream (36,382 events per attack).
- Each receiver identity is the `veh_*.json` filename stem. The provider is
  `sender_id`. conditional trust labels and probabilities must align row for row before
  execution.

No test label is available to TWSL until the common 50-event delayed verdict.

## 3. Frozen TWSL mapping

### 3.1 Original parameters

The primary profile copies Table II literally: `gamma=0.5`,
`theta=0.6`, `tau=0.4`, `zeta=0.6`, `sigma=0.4`,
`psi=(0.3,0.4,0.3)`, and `rho=(0.5,0.5)`. The paper-text-consistent
`theta=0.4`, `tau=0.6` profile is a sensitivity run, not an alternative chosen
after results.

### 3.2 Communication quality

VeReMi records received CAMs but not attempted transmissions or an explicit
pairwise link-success probability. The TWSL paper's Table II specifies
`s_(i->j)` in `[0,0.4]`. The primary VeReMi adapter therefore uses the fixed,
label-independent midpoint `s=0.2` for every local and recommended opinion.
The frozen sensitivity values are `0.1`, `0.3`, and `0.4`. No DURAC
probability, uncertainty, trust value, LCB, or test label is used as
communication quality.

### 3.3 Trajectory window

- Both vehicles use the same trailing 900-second window ending at the message
  receive time. Raw observations are causally resampled into 45-second bins,
  retaining the last observation in each bin. The 45-second resampling is
  frozen from the source paper's
  reported 43.34-second mean taxi-trace gap; it prevents VeReMi's much denser
  CAM sampling from changing the relative contribution of LCS.
- Only mobility observations at or before that time are used.
- Sender and receiver positions, speed, and heading are read directly from the
  official JSON. Duplicate observations are removed.
- The primary run uses the paper-literal exact LCS position comparison
  (`tolerance=0`). No nonzero tolerance is selected from test performance.
- A missing trajectory is an error; no favorable constant is substituted.
- Up to nine recommenders are sampled deterministically from vehicles with a
  nonempty causal trajectory in that window. If fewer than nine are active,
  all available vehicles are used; an empty pool leaves the local opinion
  unchanged, as in the TWSL core. This TWSL-specific availability restriction
  is required by Eqs. (5)--(10) and is applied before knowing whether a
  candidate is an opinion attacker.

### 3.4 External recommendation overlay

The common conditional trust settings are retained: seeds 260825--260829, nine
recommenders, opinion noise 0.15, inversion probability 0.80, attack windows
`[0.15,0.45)` and `[0.55,0.85)`, and data/opinion attacker overlaps
0%, 50%, and 100%. A scalar recommendation `p` is mapped to the declared TWSL
opinion `(b,d,u)=(sp,s(1-p),1-s)`. Its weight is always recomputed as TWSL
Eq. (10), `delta=0.5 IF + 0.5 SIM`. TWSL receives no role isolation, LCB,
domain cap, three-state rule, validator feedback, or committee information.
For Eq. (4), each recommender's causal positive/negative history is the sequence
of its previously published overlay opinions about that provider; the current
opinion is added only after the current fusion. The denominator is the mean raw
count across providers previously rated by that recommender. This rule is
independent of ground-truth labels and is shared by all profiles.

## 4. Frozen decision and metrics

The trust threshold is fixed at 0.5 before results and is common to all attacks,
overlaps, seeds, parameter profiles, and communication-quality sensitivities.
Report:

1. malicious-provider trusted rate;
2. benign-provider false-restriction rate;
3. malicious recommendation effective-weight share during active windows;
4. event recall, FPR, F1, and Macro-F1;
5. continuous final reputation for malicious and benign events.

TWSL does not output an opinion-attacker state, so opinion-attacker recall is
not reported.

## 5. Integrity and reporting rules

Execution stops if hashes, conditional trust row alignment, receiver recovery, finite
mobility, finite synchronized windows, Eq. (10) weight validation, or event
accounting fails. All 30 primary cells and all sensitivity cells are retained
regardless of direction. The publication label is:

> TWSL adapted to the VeReMi evaluation protocol (independent reimplementation).

An external-comparison claim is made only for the mechanism-matched 0% and 50%
role-overlap conditions. The 100% overlap cells define the boundary and are not
discarded if TWSL is stronger.
