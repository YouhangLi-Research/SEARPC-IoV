"""Primary-paper projections used by the participation control results-focused manuscript.

The projections do not recompute any scientific result.  They select rows from
the frozen RQ2 Pareto budget and the protocol-closed participation control RQ4 summary so the
main paper foregrounds the pre-specified primary comparisons. Full frontier
and optional-extension outputs remain available in the reproducibility artifact.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from .data_loader import PACKAGE_ROOT, load_csv
from .helpers import ensure_dir, make_contact_sheet, save_panel
from .style import COLORS, OUTPUT_DIR, apply_style


def _zero_risk_panels():
    risk = load_csv("pareto_risk_budget.csv")
    risk = risk[np.isclose(risk["risk_budget"], 0.0)].copy()
    attacks = [
        ("dataReplay", "Data Replay"),
        ("timeDelayAttack", "Time Delay"),
    ]
    out = ensure_dir(OUTPUT_DIR / "fig7_primary")
    paths = []
    for idx, (attack_key, attack_label) in enumerate(attacks):
        sub = risk[risk["attack"] == attack_key]
        overlaps = [0.0, 0.5, 1.0]
        x = np.arange(len(overlaps))
        values = {}
        for method in ("SEARPC", "TWSL"):
            m = sub[sub["method"] == method].set_index("overlap")
            values[method] = [100.0 * float(m.loc[o, "max_benign_coverage"]) for o in overlaps]

        fig, ax = plt.subplots(figsize=(4.15, 2.75))
        width = 0.34
        ax.bar(x - width / 2, values["SEARPC"], width, label="SEARPC",
               color=COLORS["green"], edgecolor="none")
        ax.bar(x + width / 2, values["TWSL"], width, label="TWSL",
               color=COLORS["orange"], edgecolor="none")
        for offset, method in ((-width / 2, "SEARPC"), (width / 2, "TWSL")):
            for xi, value in zip(x, values[method]):
                ax.text(xi + offset, value + 1.2, f"{value:.1f}",
                        ha="center", va="bottom", fontsize=7.5)
        ax.set_xticks(x, ["0%", "50%", "100%"])
        ax.set_xlabel("Attacker-set overlap")
        ax.set_ylabel("Benign authorization coverage (%)")
        ax.set_title(f"{attack_label}: empirical zero-observed-risk")
        ax.set_ylim(0, 100)
        ax.legend(loc="lower right", frameon=False, ncol=2)
        paths.append(save_panel(fig, out, f"fig7_primary_{chr(ord('a') + idx)}"))
    make_contact_sheet(paths, out / "fig7_primary_contact_sheet.png", columns=2)
    return paths


def _rq4_primary_panels():
    overall = load_csv("RQ4_summary.csv").set_index("method")
    brbc = pd.read_csv(
        PACKAGE_ROOT
        / "artifact"
        / "results"
        / "external_baselines"
        / "brbc_rq4"
        / "BRBC_RQ4_summary.csv"
    ).set_index("method")
    yadav = pd.read_csv(
        PACKAGE_ROOT
        / "artifact"
        / "results"
        / "shared7_baseline"
        / "yadav_shared7"
        / "YADAV_SHARED7_summary.csv"
    ).set_index("method")

    # Shared-7 SEARPC is duplicated in the two independently frozen external
    # baseline packages.  Refuse to draw the comparison if they disagree.
    searpc_shared_brbc = brbc.loc["searpc_core_shared_audits"]
    searpc_shared_yadav = yadav.loc["searpc_shared_audits"]
    for column in ("risk_weighted_exposure", "mean_total_wire_messages"):
        if not np.isclose(
            float(searpc_shared_brbc[column]),
            float(searpc_shared_yadav[column]),
            rtol=0,
            atol=1e-12,
        ):
            raise AssertionError(f"Shared-7 SEARPC mismatch for {column}")

    out = ensure_dir(OUTPUT_DIR / "fig9_primary")
    paths = []

    panels = [
        {
            "labels": ["Static k=13", "SEARPC w/o Same-k\nReconfiguration", "SEARPC"],
            "values": [
                100.0 * float(overall.loc["static_k13", "risk_weighted_latent_post_control_exposure"]),
                100.0 * float(overall.loc["feedback_fixed", "risk_weighted_latent_post_control_exposure"]),
                100.0 * float(overall.loc["validator_only", "risk_weighted_latent_post_control_exposure"]),
            ],
            "ylabel": "Canonical RW exposure (%)",
            "decimals": 3,
            "comparison": "−30.8% vs SEARPC w/o Same-k",
        },
        {
            "labels": ["Yadav [5]", "BRBC [16]", "SEARPC"],
            "values": [
                100.0 * float(yadav.loc["yadav_direct_history_shared_audits", "risk_weighted_exposure"]),
                100.0 * float(brbc.loc["brbc_eligibility", "risk_weighted_exposure"]),
                100.0 * float(searpc_shared_brbc["risk_weighted_exposure"]),
            ],
            "ylabel": "Shared-7 RW exposure (%)",
            "decimals": 3,
            "comparison": "−57.4% vs Yadav",
        },
        {
            "labels": ["Yadav [5]", "BRBC [16]", "SEARPC"],
            "values": [
                float(yadav.loc["yadav_direct_history_shared_audits", "mean_total_wire_messages"]),
                float(brbc.loc["brbc_eligibility", "mean_total_wire_messages"]),
                float(searpc_shared_brbc["mean_total_wire_messages"]),
            ],
            "ylabel": "Shared-7 logical wire / block",
            "decimals": 1,
            "comparison": "−29.6% vs Yadav",
        },
    ]
    colors = ["#9B9B9B", "#6F93B9", COLORS["green"]]
    for idx, panel in enumerate(panels):
        values = panel["values"]
        fig, ax = plt.subplots(figsize=(3.85, 2.75))
        fig.subplots_adjust(top=0.90, bottom=0.24, left=0.18, right=0.98)
        x = np.arange(len(panel["labels"]))
        bars = ax.bar(x, values, color=colors, edgecolor="none")
        ax.set_xticks(x)
        ax.set_xticklabels(
            panel["labels"],
            rotation=0,
            ha="center",
            fontsize=9.0,
            fontstyle="normal",
        )
        ax.set_ylabel(panel["ylabel"])
        ymax = max(values) * 1.20
        ax.set_ylim(0, ymax)
        for bar, value in zip(bars, values):
            label = f"{value:.{panel['decimals']}f}"
            ax.text(bar.get_x() + bar.get_width() / 2, value + ymax * 0.025,
                    label, ha="center", va="bottom", fontsize=8.3)
        searpc_bar = bars[-1]
        searpc_x = searpc_bar.get_x() + searpc_bar.get_width() / 2
        searpc_y = values[-1]
        ax.plot(
            [searpc_x, searpc_x],
            [searpc_y + ymax * 0.02, searpc_y + ymax * 0.15],
            color="#1F773F",
            linewidth=1.0,
        )
        ax.text(
            searpc_x,
            searpc_y + ymax * 0.17,
            panel["comparison"],
            ha="center",
            va="bottom",
            fontsize=7.8,
            color="#1F773F",
        )
        paths.append(save_panel(fig, out, f"fig9_primary_{chr(ord('a') + idx)}"))
    make_contact_sheet(paths, out / "fig9_primary_contact_sheet.png", columns=3)
    return paths


def render():
    apply_style()
    return _zero_risk_panels() + _rq4_primary_panels()


if __name__ == "__main__":
    render()
