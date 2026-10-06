import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS, COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet

PANELS = [
    ('dataReplay', 0.0, 'fig7_a'),
    ('dataReplay', 0.5, 'fig7_b'),
    ('dataReplay', 1.0, 'fig7_c'),
    ('timeDelayAttack', 0.0, 'fig7_d'),
    ('timeDelayAttack', 0.5, 'fig7_e'),
    ('timeDelayAttack', 1.0, 'fig7_f'),
]

# Preserve the V10 visual encoding while fixing the semantic provenance of the
# highlighted points.  Line colors identify methods; dedicated point colors
# reproduce the manuscript's operating-point vocabulary.
FRONTIER_COLORS = {
    'SEARPC': METHOD_COLORS['RF'],
    'TWSL': METHOD_COLORS['TWSL'],
}
POINT_STYLE = {
    ('SEARPC', 'primary'): dict(color=METHOD_COLORS['RF'], marker='*', size=68),
    ('TWSL', 'primary'): dict(color=COLORS['red'], marker='*', size=68),
    ('SEARPC', 'zero'): dict(color='#FF8C00', marker='o', size=42),
    ('TWSL', 'zero'): dict(color=COLORS['purple'], marker='o', size=42),
    ('SEARPC', 'half'): dict(color=METHOD_COLORS['SEARPC'], marker='s', size=38),
    ('TWSL', 'half'): dict(color=COLORS['brown'], marker='s', size=38),
}


def _xy(row, primary=False):
    if primary:
        return float(row['benign_coverage_mean']) * 100.0, float(row['malicious_trusted_rate_mean']) * 100.0
    return float(row['max_benign_coverage']) * 100.0, float(row['malicious_trusted_rate']) * 100.0


def _draw_point(ax, row, method, kind, primary=False):
    st = POINT_STYLE[(method, kind)]
    x, y = _xy(row, primary=primary)
    ax.scatter(x, y, s=st['size'], marker=st['marker'], color=st['color'], zorder=6)


def render():
    apply_style()
    summary = load_csv('pareto_summary.csv')
    risk = load_csv('pareto_risk_budget.csv')
    primary = load_csv('pareto_primary_point_seed20.csv')
    outdir = OUTPUT_DIR / 'fig7'
    saved = []

    for attack, overlap, stem in PANELS:
        fig, ax = plt.subplots(figsize=(4.18, 3.00))
        fig.subplots_adjust(top=0.81, bottom=0.17, left=0.16, right=0.98)

        for method in ['SEARPC', 'TWSL']:
            sub = summary[
                (summary['attack'] == attack)
                & (summary['overlap'] == overlap)
                & (summary['method'] == method)
            ].sort_values('benign_coverage_mean')
            ax.plot(
                sub['benign_coverage_mean'] * 100.0,
                sub['malicious_trusted_rate_mean'] * 100.0,
                color=FRONTIER_COLORS[method],
                linewidth=1.00,
                marker='o',
                markersize=2.2,
                label=method,
            )

            # Star = frozen theta=0.50 primary readout.
            prow = primary[
                (primary['attack'] == attack)
                & (primary['overlap'] == overlap)
                & (primary['method'] == method)
            ].iloc[0]
            _draw_point(ax, prow, method, 'primary', primary=True)

            # Circle = zero-risk optimum; square = 0.5%-risk optimum.
            rsub = risk[
                (risk['attack'] == attack)
                & (risk['overlap'] == overlap)
                & (risk['method'] == method)
            ]
            _draw_point(ax, rsub[rsub['risk_budget'] == 0.0].iloc[0], method, 'zero')
            _draw_point(ax, rsub[rsub['risk_budget'] == 0.005].iloc[0], method, 'half')

        ax.set_xlim(20, 100)
        ax.set_ylim(-0.03, 2.02)
        ax.set_xlabel('Benign provider authorization coverage (%)')
        ax.set_ylabel('Malicious provider authorized (%)')

        # Complete legend for every independent panel.  This keeps the V10
        # color/marker vocabulary but removes the obsolete "target" labels.
        handles = [
            Line2D([0], [0], color=FRONTIER_COLORS['SEARPC'], marker='o', markersize=2.8, linewidth=1.0, label='SEARPC'),
            Line2D([0], [0], color=FRONTIER_COLORS['TWSL'], marker='o', markersize=2.8, linewidth=1.0, label='TWSL'),
            Line2D([0], [0], color=POINT_STYLE[('SEARPC', 'primary')]['color'], marker='*', linestyle='None', markersize=7.0, label=r'SEARPC $\theta=0.50$'),
            Line2D([0], [0], color=POINT_STYLE[('TWSL', 'primary')]['color'], marker='*', linestyle='None', markersize=7.0, label=r'TWSL $\theta=0.50$'),
            Line2D([0], [0], color=POINT_STYLE[('SEARPC', 'zero')]['color'], marker='o', linestyle='None', markersize=5.0, label='SEARPC 0% risk'),
            Line2D([0], [0], color=POINT_STYLE[('TWSL', 'zero')]['color'], marker='o', linestyle='None', markersize=5.0, label='TWSL 0% risk'),
            Line2D([0], [0], color=POINT_STYLE[('SEARPC', 'half')]['color'], marker='s', linestyle='None', markersize=5.0, label='SEARPC 0.5% risk'),
            Line2D([0], [0], color=POINT_STYLE[('TWSL', 'half')]['color'], marker='s', linestyle='None', markersize=5.0, label='TWSL 0.5% risk'),
        ]
        ax.legend(
            handles=handles,
            frameon=False,
            loc='upper center',
            bbox_to_anchor=(0.5, 1.16),
            ncol=4,
            columnspacing=0.35,
            handlelength=0.85,
            handletextpad=0.25,
            borderaxespad=0.05,
            labelspacing=0.15,
            fontsize=5.35,
            markerscale=0.75,
        )
        saved.append(save_panel(fig, outdir, stem))

    make_contact_sheet(saved, outdir / 'fig7_contact_sheet.png', columns=3)


if __name__ == '__main__':
    render()
