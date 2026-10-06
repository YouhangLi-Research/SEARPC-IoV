# DURAC-IoV conditional trust conditional role and cold-start protocol

Date frozen: 2026-08-25

Status: frozen before inner Train archives are extracted or parsed

## 1. Purpose and evidential status

holdout authorization supports three-state trust and a conditional role-separation effect,
but fails the complete gate. conditional trust does not retune that viewed holdout. It
tests two narrower, mechanism-matched claims on another unparsed split:

1. dual-role trust protects the system when data-provider and opinion-provider
   behavior differ, while remaining safe when the malicious roles coincide;
2. an opinion-role LCB limits the influence of coordinated cold-start
   recommenders under unequal evidence exposure.

The second claim is measured using influence weights, not the authorization
state that holdout authorization showed to be invariant between weighting ablations.
Because these claims and metrics were refined after viewing holdout authorization, conditional trust
is a registered replication, not a pristine first hypothesis test.

## 2. Untouched holdout bytes

The holdout is the official low-density urban `InTAS_urban_2` **Train** split.
Its nested archives were copied from the already verified official outer
archives and hashed without extracting or parsing their JSON contents:

| Attack | Bytes | MD5 | SHA-256 |
| --- | ---: | --- | --- |
| Data replay | 54,502,801 | `3ad535432d81b1e3913ee19e6cd26d67` | `2e46d7231012cdd2bc45cc003727696c343952e3006ee02e55913cca4d6d3b47` |
| Time delay | 57,483,049 | `d67e1db0989aeab1dbb3cc5c8f3e1d88` | `f96649235e8efe72ee2d2cdf4234dbdae819275eb7665d4c6dfd56144b6f6c1c` |

The urban Test and Validation outputs are prohibited from fitting or selecting
any conditional trust outcome. The nested archive hashes must match at runtime.

## 3. Frozen message evidence and trust semantics

- Fit the unchanged five-member contextual HGBDT ensemble on pooled
  `InTAS_highway_2` Train messages.
- Calibrate and choose the FPR-constrained threshold only on pooled highway
  Validation messages, exactly as in Phases 9 and 12.
- Apply to the urban Train holdout without target fitting.
- Sample every eighth aligned holdout message from index zero.
- Retain `Beta(1,1)`, trust threshold 0.5, 5%/95% bounds, three consecutive
  adjudicated failures, ten-success recovery, and 50-event adjudication delay.
- Frozen overlay values remain: seeds 260825--260829, nine recommendations,
  eight SHA-256 domains, opinion sigma 0.15, inversion probability 0.80, attack
  windows `[0.15,0.45)` and `[0.55,0.85)`, overlaps 0.0/0.5/1.0.

No conditional trust result may change these values.

## 4. Experiment A: conditional dual-role replication

Experiment A repeats the paired uniform-recommender design with:

- `single_role_three_state`;
- `dual_role_three_state`.

Primary action-time metrics are malicious-opinion trusted rate,
honest-opinion denied rate, opinion malicious-state recall/FPR, and event
Macro-F1. The overlap claim is explicitly conditional: separation should be
strongest at overlap 0, need only retain a safe positive direction at overlap
0.5, and is tested for absolute non-inferiority at overlap 1.

## 5. Experiment B: cold-start unequal-exposure LCB stress test

Experiment B uses role overlap 0.5. For every paired seed:

- the cold cohort contains every opinion attacker plus an equal-size
  deterministic sample of honest identities;
- cold identities are ineligible before 55% of the trace;
- from 55% onward, each event samples six cold and three warm recommenders;
- before 55%, all nine recommenders are sampled from the warm pool;
- current providers remain excluded from recommendation sampling;
- every variant receives identical identities, messages, opinions, domains,
  and delayed adjudications.

The variants differ only in opinion influence:

- `dual_role_mean_weight`: posterior-mean opinion weights;
- `dual_role_lcb_weight`: 5% LCB opinion weights.

For every fusion, log both raw weights and the domain-capped effective points.
A domain point is adversarial when its weighted-median opinion lies closer to
the inverted truth than to the adjudicated truth. Primary LCB security is the
sum of adversarial domain weights divided by all effective domain weight during
active attack windows after cold-node admission. Also report raw inverted
weight share, event recall/FPR/Macro-F1, and honest/malicious cold-node weight
trajectories. Authorization metrics are diagnostic only because both variants
share the same three-state rule.

## 6. Stop lines

Experiment A supports the conditional role claim only if:

1. hashes, record alignment, sampling, pairing, and message accounting pass;
2. at overlap 0, dual role reduces malicious-opinion trusted rate by at least
   20% relative to single role for both attacks;
3. at overlap 0.5, the reduction is positive for both attacks and the dual
   malicious-opinion trusted rate is at most 5%;
4. at overlap 1, dual malicious-opinion trusted rate is no more than 5
   percentage points above single role;
5. dual opinion malicious-state FPR is at most 5%, its honest-opinion denial is
   no more than 5 percentage points worse, and its event Macro-F1 is no more
   than 0.02 below single role in every cell.

Experiment B supports the LCB claim only if:

6. LCB reduces adversarial effective-domain weight share by at least 20%
   relative to posterior mean for both attacks;
7. LCB reduces raw inverted weight share for both attacks;
8. LCB event Macro-F1 is no more than 0.02 below mean weighting and event FPR
   is no more than 1 percentage point higher for either attack.

All experiment-specific lines must pass before a complete conditional trust GO. Failure
is retained and reported; the urban Train split cannot be rerun with changed
numeric conditions and called confirmatory.

## 7. Boundary to the consensus loop

conditional trust contains no new consensus result. If the conditional role and LCB
mechanisms pass, a separately frozen closed loop protocol will compare fixed PBFT,
simple risk-to-consensus serialization, and the full feedback loop using the
already frozen consensus cost/fault model. This sequencing prevents a failed
trust mechanism from being hidden by consensus tuning.

