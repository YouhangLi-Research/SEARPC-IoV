import numpy as np
import matplotlib.pyplot as plt
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet

PANELS = [
    ('dataReplay', 'malicious', 'bar', 'Malicious data-provider\nauthorization (%)', 'fig6_a'),
    ('dataReplay', 'benign_coverage', 'bar', 'Benign data-provider\ncoverage (%)', 'fig6_b'),
    ('dataReplay', 'macro_f1', 'line', 'Event Macro-F1 (%)', 'fig6_c'),
    ('timeDelayAttack', 'malicious', 'bar', 'Malicious data-provider\nauthorization (%)', 'fig6_d'),
    ('timeDelayAttack', 'benign_coverage', 'bar', 'Benign data-provider\ncoverage (%)', 'fig6_e'),
    ('timeDelayAttack', 'macro_f1', 'line', 'Event Macro-F1 (%)', 'fig6_f'),
    ('dataReplay', 'opinion_malicious', 'bar', 'Malicious opinion-provider\nauthorization (%)', 'fig6_g'),
    ('timeDelayAttack', 'opinion_malicious', 'bar', 'Malicious opinion-provider\nauthorization (%)', 'fig6_h'),
]

VARIANTS = [
    ('single_role_three_state', 'SEARPC w/o Role Separation'),
    ('dual_role_three_state', 'SEARPC'),
]

OVERLAPS = [0.0, 0.5, 1.0]
LABELS = ['0%', '50%', '100%']
TCRIT_95_DF19 = 2.093024054408263


def _mean_sd(row, metric):
    if metric == 'malicious':
        return float(row['data_malicious_trusted_rate_mean']), float(row['data_malicious_trusted_rate_sd'])
    if metric == 'benign_coverage':
        # Benign trusted-role coverage is 1 - benign denied rate.  The SD is
        # unchanged by the affine transformation C=1-D.
        return 1.0 - float(row['data_honest_denied_rate_mean']), float(row['data_honest_denied_rate_sd'])
    if metric == 'macro_f1':
        return float(row['event_macro_f1_mean']), float(row['event_macro_f1_sd'])
    if metric == 'opinion_malicious':
        return float(row['opinion_malicious_trusted_rate_mean']), float(row['opinion_malicious_trusted_rate_sd'])
    raise ValueError(metric)


def _ci_half_width(sd, n=20):
    return TCRIT_95_DF19 * float(sd) / np.sqrt(n)


def render():
    apply_style()
    # This is the frozen scoped evidence authorization output retained unchanged in participation control.
    df = load_csv('RQ2_uniform_summary.csv')
    outdir = OUTPUT_DIR / 'fig6'
    saved = []

    for attack, metric, kind, ylabel, stem in PANELS:
        fig, ax = plt.subplots(figsize=(4.02, 2.85))
        fig.subplots_adjust(top=0.86, bottom=0.18, left=0.16, right=0.98)
        sub = df[df['attack'] == attack]

        if kind == 'bar':
            x = np.arange(len(OVERLAPS))
            width = 0.28
            for j, (variant, disp) in enumerate(VARIANTS):
                vals, errs = [], []
                for ov in OVERLAPS:
                    row = sub[(sub['variant'] == variant) & (sub['overlap'] == ov)].iloc[0]
                    mean, sd = _mean_sd(row, metric)
                    vals.append(mean * 100.0)
                    errs.append(_ci_half_width(sd) * 100.0)
                ax.bar(
                    x + (j - 0.5) * width,
                    vals,
                    width=width,
                    yerr=errs,
                    capsize=2.0,
                    color=METHOD_COLORS[disp],
                    edgecolor='none',
                    linewidth=0,
                    alpha=0.82,
                    label=disp,
                )
            ax.set_xticks(x, LABELS)
            ax.legend(
                frameon=False,
                loc='upper center',
                bbox_to_anchor=(0.5, 1.12),
                ncol=2,
                columnspacing=1.0,
                handlelength=1.6,
            )
        else:
            x = np.arange(len(OVERLAPS))
            for variant, disp in VARIANTS:
                means, lows, highs = [], [], []
                for ov in OVERLAPS:
                    row = sub[(sub['variant'] == variant) & (sub['overlap'] == ov)].iloc[0]
                    mean, sd = _mean_sd(row, metric)
                    half = _ci_half_width(sd)
                    means.append(mean * 100.0)
                    lows.append((mean - half) * 100.0)
                    highs.append((mean + half) * 100.0)
                means = np.asarray(means)
                lows = np.asarray(lows)
                highs = np.asarray(highs)
                ax.fill_between(x, lows, highs, color=METHOD_COLORS[disp], alpha=0.13, linewidth=0)
                ax.plot(x, means, marker='o', linewidth=1.1, color=METHOD_COLORS[disp], label=disp)
            ax.set_xticks(x, LABELS)
            ax.legend(
                frameon=False,
                loc='upper center',
                bbox_to_anchor=(0.5, 1.12),
                ncol=2,
                columnspacing=1.0,
                handlelength=1.6,
            )

        ax.set_xlabel('Attacker-set overlap')
        ax.set_ylabel(ylabel)
        if metric == 'malicious':
            ax.set_ylim(-0.4, 22.5)
        elif metric == 'opinion_malicious':
            ax.set_ylim(0, 7.2)
        elif metric == 'benign_coverage':
            ax.set_ylim(70, 101)
        else:
            ax.set_ylim(78, 100.5)
        saved.append(save_panel(fig, outdir, stem))

    make_contact_sheet(saved, outdir / 'fig6_contact_sheet.png', columns=3)


if __name__ == '__main__':
    render()
