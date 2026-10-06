import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet

METHODS = [
    ('full_set', 'Full set', METHOD_COLORS['Full set']),
    ('fixed_k13', 'Size-fixed k=13', METHOD_COLORS['Fixed k13']),
    ('searpc_conditioned', 'SEARPC', METHOD_COLORS['SEARPC']),
]
AVAILS = ['cached', 'fetch']
AVAIL_LABELS = ['Cached', 'Fetch']


def _method_legend(ax):
    ax.legend(
        handles=[Patch(facecolor=color, edgecolor='none', label=label) for _, label, color in METHODS],
        frameon=False,
        loc='upper center',
        bbox_to_anchor=(0.5, 1.12),
        ncol=3,
        columnspacing=0.9,
        handlelength=1.3,
    )


def latency_profile(ax, df, process_count):
    """Submission encoding: bar top=p95, white line=p50, dots=launch p95.

    Bars summarize the median across five independent process launches.  The
    individual launch-level p95 points expose between-launch variation without
    elevating the p99 estimate to a main-text performance claim.
    """
    x = np.arange(len(AVAILS))
    width = 0.20
    for i, (key, label, color) in enumerate(METHODS):
        p50s, p95s, launch_p95 = [], [], []
        for avail in AVAILS:
            sub = df[
                (df['process_count'] == process_count)
                & (df['availability'] == avail)
                & (df['method'] == key)
            ]
            p50s.append(float(sub['accounted_p50_ms'].median()))
            p95s.append(float(sub['accounted_p95_ms'].median()))
            launch_p95.append(np.sort(sub['accounted_p95_ms'].to_numpy(dtype=float)))
        p50s = np.asarray(p50s)
        p95s = np.asarray(p95s)
        xpos = x + (i - 1) * width
        ax.bar(xpos, p95s, width, color=color, alpha=0.78, edgecolor='none', label=label, zorder=2)
        # p50: compact white line inside each p95 bar.
        half_line = width * 0.32
        for xx, p50 in zip(xpos, p50s):
            ax.hlines(p50, xx - half_line, xx + half_line, color='white', linewidth=1.35, zorder=4)
        # Five launch-level p95 values; deterministic horizontal offsets avoid
        # overlap while keeping every point visibly attached to its method bar.
        for xx, values in zip(xpos, launch_p95):
            offsets = np.linspace(-width * 0.23, width * 0.23, len(values))
            ax.scatter(
                xx + offsets,
                values,
                s=10,
                facecolors='white',
                edgecolors='#3F3F3F',
                linewidths=0.55,
                zorder=5,
            )
    ax.set_xticks(x, AVAIL_LABELS)
    _method_legend(ax)


def wire_bars(ax, df, process_count):
    x = np.arange(len(AVAILS))
    width = 0.20
    for i, (key, label, color) in enumerate(METHODS):
        vals = []
        for avail in AVAILS:
            sub = df[
                (df['process_count'] == process_count)
                & (df['availability'] == avail)
                & (df['method'] == key)
            ]
            # Summaries use the median across independent launches.
            vals.append(float(sub['mean_total_wire_bytes'].median()))
        ax.bar(x + (i - 1) * width, vals, width, color=color, alpha=0.76, edgecolor='none', label=label)
    ax.set_xticks(x, AVAIL_LABELS)
    _method_legend(ax)


def render():
    apply_style()
    df = load_csv('SEARPC_process_per_launch.csv')
    outdir = OUTPUT_DIR / 'fig11'
    saved = []

    fig, ax = plt.subplots(figsize=(4.06, 2.88))
    fig.subplots_adjust(top=0.86, bottom=0.18, left=0.17, right=0.98)
    latency_profile(ax, df, 16)
    ax.set_ylabel('Launch latency (ms)')
    ax.set_ylim(0, 100)
    saved.append(save_panel(fig, outdir, 'fig11_a'))

    fig, ax = plt.subplots(figsize=(4.06, 2.88))
    fig.subplots_adjust(top=0.86, bottom=0.18, left=0.17, right=0.98)
    latency_profile(ax, df, 40)
    ax.set_ylabel('Launch latency (ms)')
    ax.set_ylim(0, 160)
    saved.append(save_panel(fig, outdir, 'fig11_b'))

    fig, ax = plt.subplots(figsize=(4.06, 2.88))
    fig.subplots_adjust(top=0.86, bottom=0.18, left=0.17, right=0.98)
    wire_bars(ax, df, 16)
    ax.set_ylabel('Wire (KB / block)')
    ax.set_ylim(0, 600000)
    ax.set_yticks(
        [0, 100000, 200000, 300000, 400000, 500000, 600000],
        ['0', '100', '200', '300', '400', '500', '600'],
    )
    saved.append(save_panel(fig, outdir, 'fig11_c'))

    fig, ax = plt.subplots(figsize=(4.06, 2.88))
    fig.subplots_adjust(top=0.86, bottom=0.18, left=0.17, right=0.98)
    wire_bars(ax, df, 40)
    ax.set_ylabel('Wire (KB / block)')
    ax.set_ylim(0, 1500000)
    ax.set_yticks(
        [0, 200000, 400000, 600000, 800000, 1000000, 1200000, 1400000],
        ['0', '200', '400', '600', '800', '1000', '1200', '1400'],
    )
    saved.append(save_panel(fig, outdir, 'fig11_d'))

    make_contact_sheet(saved, outdir / 'fig11_contact_sheet.png', columns=2)


if __name__ == '__main__':
    render()
