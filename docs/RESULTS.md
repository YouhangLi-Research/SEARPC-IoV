# Result traceability

The table below maps the main manuscript claims to the distributed evidence.

| Claim | Manuscript-facing value | Repository source | Evidence level |
| --- | --- | --- | --- |
| Message-evidence false-positive rate | SEARPC 3.96%; CaTCH 5.90% | `results/HEADLINE_RESULTS.csv`; Figure 5 data; pinned CaTCH adapter | Official-data adapter and aggregate |
| Malicious trusted authorization | No observed authorization in 6/6 SEARPC cells | `artifact/results/vehicle_role/`; original Figure 6 aggregate | Bundled-input 20-seed rerun plus original aggregate check |
| Same-domain 1-to-7 influence increment | SEARPC 0.019; BRS 0.579; TWSL 0.647 | `artifact/results/vehicle_domain/`; `artifact/results/vehicle_source_baselines/`; `results/PAPER_SOURCE_INFLUENCE_REFERENCE.csv` | Full-grid reruns; original domain intervals and rounded external claims checked |
| Canonical risk-weighted exposure | SEARPC w/o Same-k Reconfiguration 8.285%; SEARPC 5.732% | `artifact/results/participation_control/rq4_protocol_closed/` | Deterministic block-level raw |
| Shared-seven exposure versus Yadav | 18.822% versus 8.025%; −10.797 pp | `artifact/results/shared7_baseline/yadav_shared7/` | Deterministic block-level paired raw |
| Shared-seven exposure versus BRBC | 19.857% versus 8.025%; −11.832 pp | `artifact/results/external_baselines/brbc_rq4/` | Deterministic block-level paired raw |
| 40-process fetch-mode cost | p95 115.62→70.56 ms; 1428.9→1019.6 KB/block | Figure 11 per-launch data | Current five-launch certificate-integration measurements; synthetic warnings |
| Legal-block progress and quorum | 100% legal commits; fixed Q | Shared-seven traces and process outputs | Progress under the configured withholding model; certificate/quorum checks |
| Illegal-acceptance field | 0 | Observable-controller output schema | Model-defined invariant; no conflicting-block attack evaluation |

`results/HEADLINE_RESULTS.csv` provides baseline values, SEARPC values, absolute and relative changes, paired-inference summaries, manuscript table locations, and evidence levels in machine-readable form.

## Interpretation

The vehicle-data experiments assess whether role history and correlated identities obtain inappropriate authorization. The paired 40-RSU trajectories execute the canonical audit and lifecycle chain and assess whether high-risk RSUs continue to occupy fast-candidate positions. The process prototype measures candidate reconfiguration and fixed-quorum certificate handoff under synthetic warnings. These are complementary mechanism, protocol, and execution-cost evaluations; the process prototype is not an end-to-end rerun of the audit chain.

The protocol simulator models compromised validators as withholding usable
signatures for legal blocks. Its online controller consumes observable signer
sets, availability, and timeout outcomes; hidden fault labels are used by the
simulation environment and offline evaluator. For a formed 13-member candidate
with threshold 9, more than four withholding members cause a signature timeout.
This explains equal latent-exceedance and handoff rates in that attack setting.
The illegal-acceptance output is fixed to zero by this model, and is not an
independent measurement of resistance to conflicting blocks or equivocation.

Certified-domain seat limits constrain source multiplicity. At k=13 and
kappa=0.40 the integer cap is 6 seats; it does not imply the local Byzantine
bound of 4 is satisfied. Unusable hints return to the base path using observable
checks. Finality-safety inheritance assumes the integrated base BFT executes
its complete validation, locking, and view-change rules.


The source increments are dimensionless shares on a 0–1 scale. A reduction
of 0.560–0.628 in that share corresponds to 56.0–62.8 percentage points when
the share is expressed as a percentage. The 38.97% latency and 28.65%
communication reductions are relative reductions of physical quantities;
they must not be relabeled as percentage-point differences.

`artifact/results/vehicle_*` contains the complete 20-seed grids.
`artifact/results/brs_authorization/` contains the pooled-Beta authorization
counts and frontier. `python run.py paper-results` exports Tables XI–XXI
from these result sources and verifies the manuscript cells.
