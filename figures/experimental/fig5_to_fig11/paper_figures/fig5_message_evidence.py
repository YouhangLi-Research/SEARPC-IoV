import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from .style import apply_style, DATA_DIR, OUTPUT_DIR, METHOD_COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet

PANELS = [
    ('dataReplay', 'false_positive_rate', '%', 'fig5_a'),
    ('dataReplay', 'ece_15', 'ECE-15', 'fig5_b'),
    ('dataReplay', 'reliability', 'Observed malicious fraction', 'fig5_c'),
    ('timeDelayAttack', 'false_positive_rate', '%', 'fig5_d'),
    ('timeDelayAttack', 'ece_15', 'ECE-15', 'fig5_e'),
    ('timeDelayAttack', 'reliability', 'Observed malicious fraction', 'fig5_f'),
]

METHODS = [
    ('random_forest', 'RF'),
    ('single_hgbdt', 'HGBDT'),
    ('durac_ensemble', 'SEARPC'),
]


def _reliability_points(labels: np.ndarray, probabilities: np.ndarray, bins: int = 15):
    """clustered bootstrap ECE-compatible equal-width reliability bins.

    This mirrors the frozen clustered bootstrap implementation: p in [0,1] is assigned to
    one of 15 equal-width bins. Empty bins are omitted from the plotted curve.
    """
    labels = np.asarray(labels, dtype=float)
    probabilities = np.asarray(probabilities, dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    bin_id = np.minimum(np.digitize(probabilities, edges[1:-1], right=False), bins - 1)
    xs, ys = [], []
    for b in range(bins):
        mask = bin_id == b
        if not np.any(mask):
            continue
        xs.append(float(probabilities[mask].mean()))
        ys.append(float(labels[mask].mean()))
    return np.asarray(xs), np.asarray(ys)


def render():
    apply_style()
    intervals = load_csv('SEARPC_clustered_method_intervals.csv')
    predictions = pd.read_csv(DATA_DIR / 'SEARPC_clustered_receiver_predictions.csv.gz')
    outdir = OUTPUT_DIR / 'fig5'
    order = [disp for _, disp in METHODS]
    saved = []

    for attack, metric, ylabel, stem in PANELS:
        fig, ax = plt.subplots(figsize=(4.08, 2.88))
        fig.subplots_adjust(top=0.86, bottom=0.18, left=0.16, right=0.98)

        if metric == 'reliability':
            psub = predictions[predictions['attack'] == attack]
            y = psub['attacker'].to_numpy(dtype=int)
            for raw_method, disp in METHODS:
                x, obs = _reliability_points(y, psub[raw_method].to_numpy(dtype=float), bins=15)
                ax.plot(
                    x,
                    obs,
                    marker='o',
                    linewidth=1.35,
                    markersize=3.7,
                    label=disp,
                    color=METHOD_COLORS[disp],
                )
            ax.plot([0, 1], [0, 1], linestyle='--', color='#777777', linewidth=1.0, label='Ideal')
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.set_xlabel('Predicted risk')
            ax.set_ylabel('Observed malicious fraction')
            ax.legend(
                frameon=False,
                loc='upper center',
                bbox_to_anchor=(0.5, 1.14),
                ncol=2,
                columnspacing=0.9,
                handlelength=1.6,
            )
        else:
            sub = intervals[
                (intervals['scope'] == 'attack_external_test')
                & (intervals['attack'] == attack)
                & (intervals['metric'] == metric)
            ].copy()
            x = np.arange(3)
            for i, (raw_method, disp) in enumerate(METHODS):
                row = sub[sub['method'] == raw_method].iloc[0]
                estimate = float(row['estimate'])
                low = float(row['ci95_low'])
                high = float(row['ci95_high'])
                if metric == 'false_positive_rate':
                    estimate *= 100.0
                    low *= 100.0
                    high *= 100.0
                yerr = np.array([[estimate - low], [high - estimate]])
                ax.errorbar(
                    i,
                    estimate,
                    yerr=yerr,
                    fmt='o',
                    color=METHOD_COLORS[disp],
                    capsize=3.2,
                    markersize=5.0,
                    elinewidth=0.9,
                )
            ax.set_xticks(x, order)
            ax.set_ylabel(ylabel)
            # Freeze the V10 viewing windows so the independent panels retain the
            # same visual granularity as the manuscript composite.
            if metric == 'false_positive_rate':
                ax.set_ylim((2.15, 3.85) if attack == 'dataReplay' else (4.35, 6.95))
            else:
                ax.set_ylim((0.0265, 0.0467) if attack == 'dataReplay' else (0.0135, 0.0402))

        saved.append(save_panel(fig, outdir, stem))

    make_contact_sheet(saved, outdir / 'fig5_contact_sheet.png', columns=3)


if __name__ == '__main__':
    render()
