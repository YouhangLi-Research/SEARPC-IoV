# SEARPC / VeReMi mapping protocol

This file defines the permitted adapter between the frozen SEARPC evaluation stream and TWSL. It is intentionally separate from the TWSL core.

## 1. Freeze the common event stream

Every method must receive the same:

- event identities and chronological order;
- data-provider and recommender identities;
- delayed verification outcomes;
- role-overlap assignment;
- train/validation/test separation;
- random seeds.

No ground-truth test label may be used before the delayed verdict time at which SEARPC also receives it.

## 2. Map verified interactions

For a requester (i) and provider (j):

- `positive` means the frozen delayed verifier regards the interaction as valid;
- `negative` means the delayed verifier regards it as invalid;
- ambiguous/unresolved events must not be silently converted into positive evidence.

If SEARPC has an explicit uncertain state before verification, either defer the TWSL update until the same delayed verdict or declare a fixed missing-evidence policy before testing.

## 3. Map communication quality

The original TWSL uncertainty is (u_{i\to j}=1-s_{i\to j}), where (s) is successful packet-transmission probability. The preferred mapping order is:

1. measured delivered/attempted packet ratio for the pair and frozen window;
2. a simulator-exposed link-success probability;
3. one global constant selected without test labels and accompanied by sensitivity analysis.

Do not substitute classifier confidence, vehicle reputation or SEARPC LCB for communication quality.

## 4. Map trajectories

Use the same pre-verdict mobility records for all methods. Convert positions to a common projected coordinate system. Speed may be taken from the dataset or calculated from adjacent samples. Direction may be supplied or inferred from segment endpoints.

The paper uses exact LCS point equality. For continuous VeReMi coordinates, pre-register a position tolerance based on measurement resolution, not on which value improves SEARPC's margin. Report both the literal zero-tolerance diagnostic and the selected dataset-resolution mapping when feasible.

## 5. Map recommendation attacks

TWSL's recommended opinions are the local opinion vectors published by other vehicles. To inject a registered scalar recommendation (p\in[0,1]) with declared evidence quality (q\in[0,1]), a transparent adapter is:

\[
b=qp,\qquad d=q(1-p),\qquad u=1-q.
\]

This conversion is a SEARPC-evaluation adapter, not an equation claimed by the TWSL paper. Freeze (q) using the same evidence-availability rule for honest and malicious recommenders. The opinion's TWSL weight remains Eq. (10); do not multiply by SEARPC LCB or apply a domain cap.

The `fuse` CLI exists for these prepared or adversarial opinion vectors.

## 6. Thresholding

TWSL outputs a continuous reputation. If discrete states are required:

- choose thresholds only on the validation partition;
- freeze them before all test and role-overlap evaluations;
- use the same optimization objective and constraints as other continuous-score baselines;
- report continuous reputation/weight outcomes in addition to thresholded metrics.

## 7. Allowed primary comparisons

Recommended reputation-layer metrics:

- malicious trusted-authorization rate;
- malicious effective recommendation weight;
- benign false restriction rate;
- trust/reputation Macro-F1;
- recovery time after an on-off transition.

Do not claim that TWSL directly competes on committee exposure, fixed-Q finality or process-level latency. Those claims require SEARPC internal consensus ablations.

## 8. Required reporting label

Use one of:

- `TWSL (independent paper-aligned reimplementation)` when all original inputs exist;
- `TWSL adapted to the VeReMi protocol` when a declared trajectory or communication mapping is necessary.

Never use `official TWSL code`.

