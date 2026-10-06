# Pooled Beta authorization readout

This experiment exports the pooled Beta-reputation baseline on the registered
role-authorization traces. Provider outcomes and recommender honesty update
the same identity-level history. The readout uses the posterior mean.

| Parameter | Value |
| --- | --- |
| Input | `data/derived/rq2_trace_bundle_exact.npz` |
| Attacks | Data Replay; Time Delay |
| Role overlap | 0%, 50%, 100% |
| Paired seeds | 260825–260844 |
| Events per attack trace | 36,382 |
| Beta prior | α=1, β=1 |
| Delivery, sampling, noise, and attack schedule | Registered role-cell rules |
| Readout grid | 0.05–0.95 in increments of 0.01 |
| Primary readout | 0.50 |
| Security rate | Malicious trusted actions / malicious actions |
| Benign coverage | Benign trusted actions / benign actions |

Only the readout threshold changes across the grid. It does not alter the
history update or delivery rules. At each risk budget, choose the feasible
threshold with the largest mean benign coverage. A zero-risk point requires
zero malicious trusted actions across all paired seeds.

`python run.py brs-authorization` generates 10,920 count rows and a 546-row
summary. The six primary authorization rates reconstruct Table XIII. The
zero-risk frontier reconstructs the BRS row of Table XIV.
