# Paper alignment and declared completions

## Source

J. Kang, R. Yu, X. Huang, M. Wu, S. Maharjan, S. Xie, and Y. Zhang, “Blockchain for Secure and Efficient Data Sharing in Vehicular Edge Computing and Networks,” IEEE Internet of Things Journal, 6(3), 4660–4670, 2019. DOI: 10.1109/JIOT.2018.2875542.

This repository is an independent implementation. No verified author repository was found during preparation.

## Equation map

| Paper equation | Implementation |
|---|---|
| (1) local belief, distrust and uncertainty | `core.local_opinion` |
| (2) expected reputation | `models.Opinion.expectation` |
| (3) recent/past positive and negative weighting | `core.paper_weighted_event_count` |
| (4) interaction frequency | `core.interaction_frequency` and `pipeline.build_local_opinions` |
| (5) trajectory similarity | `trajectory.trajectory_similarity` |
| (6) weighted dissimilarity | `trajectory.trajectory_similarity` |
| (7) speed difference | `trajectory.speed_dissimilarity` |
| (8) LCS location difference | `trajectory.location_dissimilarity` |
| (9) direction difference | `trajectory.direction_dissimilarity` |
| (10) overall local-opinion weight | `core.opinion_weight` |
| (11) recommended opinion | `core.recommended_opinion` |
| (12) local/recommended consensus | `core.combine_local_and_recommended` |
| (13) final reputation | `models.Opinion.expectation` on final opinion |

## Literal parameter profile

The default configuration copies Table II:

- gamma = 0.5;
- theta = 0.6, tau = 0.4;
- zeta = 0.6, sigma = 0.4;
- recent horizon = seven days;
- psi = (0.3, 0.4, 0.3);
- rho = (0.5, 0.5);
- reputation update period = 15 minutes.

The paper reports communication quality as a range rather than a single value. This implementation therefore requires the value per interaction unless a dataset-level constant is explicitly configured.

## Ambiguities and explicit decisions

### Positive/negative weight contradiction

The prose requires theta < tau so negative events have greater influence, but Table II gives theta=0.6 and tau=0.4. The literal table profile is the default; the constraint-consistent profile is a sensitivity run. Both are shipped and named so that result-driven selection is detectable.

### No-event opinion

Equation (1) divides by alpha+beta. For zero events, this implementation returns the standard vacuous opinion (0,0,1), whose expectation is gamma. The paper does not state this edge case.

### Communication quality aggregation

Equation (1) uses pairwise communication quality. When several interaction rows exist for a pair, the implementation takes their arithmetic mean. If the dataset provides a single frozen pair-level value, repeating it on the rows yields the exact value.

### Interaction-frequency denominator

Equation (4) shows a weighted pair numerator divided by the requestor's average raw interaction count with providers. The implementation follows that expression literally and does not clip interaction frequency or the resulting delta to one.

### Speed denominator

Equation (7) uses the difference of segment average speeds divided by the maximum segment speed. The implementation uses the maximum observed speed across both segments.

### LCS point equality

Equation (8) describes equality of trajectory points. The literal profile therefore uses zero position tolerance. Continuous GPS data usually require a declared tolerance after projection; any non-zero tolerance is a dataset adaptation and is recorded in the manifest.

### Segment direction

When headings are supplied, circular mean heading is used. Otherwise the direction of the vector from the first to the last point is used. The paper defines the angle between trajectory segments but does not specify this extraction step.

### Missing trajectory

The literal profile fails rather than silently substituting a value. Alternative policies (`zero`, `neutral`, `identical`) exist only for explicitly declared diagnostics and must not be selected from test performance.

### Empty recommendation pool

If no other vehicle has an opinion for a provider, the final opinion equals the requestor's local opinion. Equation (12) otherwise applies unchanged.

### Dogmatic consensus

Equation (12) is undefined if both input opinions have zero uncertainty. The original parameter range keeps uncertainty positive. The implementation raises an error in this edge case instead of inventing a fallback.

## What is not implemented

- blockchain storage and smart contracts from the source paper;
- a reproduction of the source paper's San Francisco taxi simulation;
- SEARPC role separation, LCB, domain caps, authorization states or consensus;
- threshold tuning, attack generation, statistical tests or plots.

These exclusions keep the deliverable a trust-computation baseline rather than a new hybrid method.

