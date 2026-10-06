# Figure provenance

Experimental Figures 5–11 are drawn with Python and Matplotlib from the distributed
result files. Reference PNGs and screenshots are not plotting inputs. The exact
manuscript panel selection is recorded in `figures/FIGURE_INDEX.json`.

## Data sources

The plotting data directory is `figures/experimental/fig5_to_fig11/data/`.

- Figure 5: `SEARPC_clustered_method_intervals.csv` and `SEARPC_clustered_receiver_predictions.csv.gz`.
- Figure 6: `RQ2_uniform_summary.csv`.
- Figure 7: `pareto_risk_budget.csv`; supplementary frontier panels also use `pareto_summary.csv` and `pareto_primary_point_seed20.csv`.
- Figure 8: `RQ3_summary_student_t.csv`.
- Figure 9: `artifact/results/participation_control/rq4_protocol_closed/RQ4_summary.csv`, `artifact/results/shared7_baseline/yadav_shared7/YADAV_SHARED7_summary.csv`, and `artifact/results/external_baselines/brbc_rq4/BRBC_RQ4_summary.csv`. The two Shared-7 copies of the SEARPC comparison are checked for agreement before plotting.
- Figure 10: `RQ4_risk_stream.csv`, `RQ4_block_level.csv`, and `RQ4_summary.csv`, all loaded from `artifact/results/participation_control/rq4_protocol_closed/`.
- Figure 11: `SEARPC_process_per_launch.csv`.

## Reproduction

```bash
python run.py figures
```

The command writes Figure 4 to `figure4/` and Figures 5–11 to `figures5-11/` in a
new run directory under `outputs/`. Specify `--output-dir` to select another empty
directory. Archived release exports are kept in the respective plotting package's
`outputs/` directory; a rerun does not overwrite them.

Figures 1–3 are framework diagrams supplied as final PDF artwork, with
matching SVG and PNG files in `figures/framework/`.
