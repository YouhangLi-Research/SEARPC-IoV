# Artifact layout

Use the repository-level `run.py` entry for experiment execution. It configures module paths, creates isolated output directories, and compares generated results with the registered references.

| Component | Location |
| --- | --- |
| Vehicle grids | `scripts/run_vehicle_experiments.py` |
| Exact vehicle inputs | `data/derived/` |
| Role and cold-start results | `artifact/results/vehicle_role/` |
| Source-domain results | `artifact/results/vehicle_domain/` |
| BRS/TWSL source results | `artifact/results/vehicle_source_baselines/` |
| Canonical participation | `artifact/code/participation_control/run_participation.py` |
| Yadav shared-seven comparison | `artifact/code/participation_control/yadav_shared7.py` |
| BRBC shared-seven comparison | `artifact/code/participation_control/brbc_participation.py` |
| Audit-budget attribution | `artifact/code/participation_control/equal_audit_budget.py` |
| Lifecycle sensitivity | `artifact/code/participation_control/fsm_sensitivity.py` |
| Adjudication delivery | `scripts/check_adjudication_delivery.py` |
| Process prototype | `artifact/code/scoped_evidence/run_process_measurements.py` |
| Manuscript result correspondence | `scripts/paper_results.py` |
| Diagram and panel mapping | `figures/FIGURE_INDEX.json` |

Module and result names describe the corresponding experiment. File integrity is recorded in `MANIFEST.sha256`.
