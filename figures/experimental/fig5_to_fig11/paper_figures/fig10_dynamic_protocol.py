import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS, COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet, add_epoch_bands


# Panels (a)–(c) are enlarged slightly for the final two-column Word layout.
# Panel (d) has the narrowest tight-crop canvas, so its source typography is
# reduced proportionally; after embedding all panels at the same width, their
# apparent type size is consistent rather than oversized in (d).
ABC_LABEL_SIZE = 10.5
ABC_TICK_SIZE = 9.2
ABC_LEGEND_SIZE = 9.6
ABC_EPOCH_SIZE = 8.1
D_LABEL_SIZE = 9.75
D_TICK_SIZE = 8.55
D_LEGEND_SIZE = 8.9
D_EPOCH_SIZE = 7.5


def _set_panel_typography(ax, label_size: float, tick_size: float) -> None:
    ax.xaxis.label.set_size(label_size)
    ax.yaxis.label.set_size(label_size)
    ax.tick_params(axis='both', which='major', labelsize=tick_size)


def _per_trace_rolling_risk(risk: pd.DataFrame, window: int = 13) -> pd.DataFrame:
    """Frozen Fig.10(a) aggregation.

    Each paired trace is smoothed first with a centered 13-block rolling mean;
    the plotted center and band are then the cross-trace median and IQR at each
    block. This preserves the V10 temporal granularity while avoiding a
    mean-before-rolling aggregation change.
    """
    pieces = []
    for repeat, g in risk.groupby('repeat'):
        s = g.sort_values('block').set_index('block')['risk_score']
        rolled = s.rolling(window, center=True, min_periods=1).mean()
        pieces.append(pd.DataFrame({'repeat': repeat, 'block': rolled.index, 'risk_roll': rolled.values}))
    return pd.concat(pieces, ignore_index=True)


def _cumulative_risk_weighted_exposure(sub: pd.DataFrame) -> pd.Series:
    """Cumulative risk-weighted fast exposure through each block.

    E_RW(h) = sum_{u,l<=h} r_{u,l} b_{u,l} / sum_{u,l<=h} r_{u,l}.
    The final point therefore equals the frozen overall statistic exactly.
    """
    by_block = sub.groupby('block').agg(
        risk=('risk_score', 'sum'),
        weighted_breach=('risk_score', lambda x: 0.0),
    )
    # groupby.agg cannot directly multiply two columns in a named aggregation.
    weighted = (sub['risk_score'] * sub['latent_post_control_exceedance']).groupby(sub['block']).sum()
    by_block['weighted_breach'] = weighted
    numerator = by_block['weighted_breach'].cumsum()
    denominator = by_block['risk'].cumsum()
    return numerator / denominator.replace(0, np.nan) * 100.0


def render():
    apply_style()
    risk = load_csv('RQ4_risk_stream.csv')
    blocks = load_csv('RQ4_block_level.csv')
    overall = load_csv('RQ4_summary.csv').set_index('method')
    outdir = OUTPUT_DIR / 'fig10'
    saved = []

    # Panel a: 13-block per-trace rolling risk, then cross-trace median/IQR.
    fig, ax = plt.subplots(figsize=(4.55, 3.12))
    fig.subplots_adjust(top=0.82, bottom=0.17, left=0.13, right=0.98)
    rolled = _per_trace_rolling_risk(risk, window=13)
    by_block = rolled.groupby('block')['risk_roll']
    med = by_block.median()
    q1 = by_block.quantile(0.25)
    q3 = by_block.quantile(0.75)
    ax.fill_between(med.index, q1.values, q3.values, color=METHOD_COLORS['RF'], alpha=0.18, label='13-block rolling IQR')
    ax.plot(med.index, med.values, color=METHOD_COLORS['RF'], linewidth=1.15, label='13-block rolling median')
    ax.set_xlim(1, 600)
    ax.set_ylim(0.58, 0.93)
    ax.set_xlabel('Block height')
    ax.set_ylabel('Risk score')
    _set_panel_typography(ax, ABC_LABEL_SIZE, ABC_TICK_SIZE)
    add_epoch_bands(ax, label_size=ABC_EPOCH_SIZE)
    ax.legend(frameon=False, loc='upper left', fontsize=ABC_LEGEND_SIZE, handlelength=1.3)
    saved.append(save_panel(fig, outdir, 'fig10_a'))

    # Frozen SEARPC block-level state/event source.
    searpc = blocks[blocks['method'] == 'validator_only'].copy()
    gb = searpc.groupby('block')

    # Panel b: mutually exclusive validator-state composition from the
    # participation control block trace. participation control retains validator-Beta as diagnostic telemetry only;
    # telemetry from the main controller; the online control state is the
    # delivered-audit FSM: Active / Probation / Quarantine.
    active_pool = gb['active_pool'].mean()
    probation = gb['probation'].mean()
    quarantine = gb['quarantined'].mean()
    total = active_pool + probation + quarantine
    if not np.allclose(total.to_numpy(), 40.0, atol=1e-9):
        raise AssertionError('Fig.10(b) Validator-state composition must sum to N=40 at every block.')

    fig, ax = plt.subplots(figsize=(4.55, 3.12))
    fig.subplots_adjust(top=0.82, bottom=0.17, left=0.13, right=0.98)
    x = active_pool.index
    ax.stackplot(
        x,
        active_pool,
        probation,
        quarantine,
        colors=['#3B82F6', '#22A06B', '#E45756'],
        labels=['Active', 'Probation', 'Quarantine'],
        alpha=0.85,
    )
    ax.set_xlim(1, 600)
    ax.set_ylim(0, 42)
    ax.set_xlabel('Block height')
    ax.set_ylabel('Mean validators')
    _set_panel_typography(ax, ABC_LABEL_SIZE, ABC_TICK_SIZE)
    add_epoch_bands(ax, label_size=ABC_EPOCH_SIZE)
    ax.legend(
        frameon=False,
        loc='upper center',
        bbox_to_anchor=(0.5, 1.24),
        ncol=3,
        fontsize=ABC_LEGEND_SIZE,
        columnspacing=0.65,
        handlelength=1.15,
        handletextpad=0.4,
        borderaxespad=0.0,
    )
    saved.append(save_panel(fig, outdir, 'fig10_b'))

    # Panel c: frozen 21-block rolling event rates.
    fig, ax = plt.subplots(figsize=(4.55, 3.12))
    fig.subplots_adjust(top=0.82, bottom=0.17, left=0.13, right=0.98)
    event_cols = [
        ('warning_triggered_resampling', 'Warning resampling', COLORS['purple']),
        ('latent_initial_exceedance', 'Initial fault-budget exceedance', METHOD_COLORS['HGBDT']),
        ('latent_post_control_exceedance', 'Post-control fault-budget exceedance', METHOD_COLORS['SEARPC']),
    ]
    for col, label, color in event_cols:
        s = gb[col].mean().rolling(21, min_periods=1, center=True).mean() * 100.0
        ax.plot(s.index, s, color=color, label=label)
    ax.set_xlim(1, 600)
    ax.set_ylim(-1, 63)
    ax.set_xlabel('Block height')
    ax.set_ylabel('21-block rolling event rate (%)')
    _set_panel_typography(ax, ABC_LABEL_SIZE, ABC_TICK_SIZE)
    add_epoch_bands(ax, label_size=ABC_EPOCH_SIZE)
    ax.legend(frameon=False, loc='upper left', fontsize=ABC_LEGEND_SIZE, handlelength=1.3)
    saved.append(save_panel(fig, outdir, 'fig10_c'))

    # Panel d: true cumulative risk-weighted exposure ratio.
    fig, ax = plt.subplots(figsize=(4.55, 3.12))
    fig.subplots_adjust(top=0.82, bottom=0.17, left=0.18, right=0.98)
    methods = [
        ('static_k13', 'Static k=13', METHOD_COLORS['Static k13'], '-'),
        ('feedback_fixed', 'SEARPC w/o Same-k Reconfiguration', METHOD_COLORS['Feedback fixed'], '-'),
        ('content_only', 'Content-only', METHOD_COLORS['HGBDT'], '--'),
        ('validator_only', 'SEARPC', METHOD_COLORS['Validator only'], '-'),
        ('searpc', 'SEARPC + optional extension', METHOD_COLORS['SEARPC'], '-'),
    ]
    for key, label, color, ls in methods:
        sub = blocks[blocks['method'] == key].copy()
        cum = _cumulative_risk_weighted_exposure(sub)
        final_expected = float(overall.loc[key, 'risk_weighted_latent_post_control_exposure']) * 100.0
        if not np.isclose(float(cum.iloc[-1]), final_expected, rtol=0, atol=1e-10):
            raise AssertionError(f'Fig.10(d) endpoint mismatch for {key}: {cum.iloc[-1]} vs {final_expected}')
        ax.plot(cum.index, cum.values, color=color, linestyle=ls, label=label)
    ax.set_xlim(1, 600)
    ax.set_ylim(-1, 23)
    ax.set_xlabel('Block height')
    ax.set_ylabel('Cumulative RW exposure (%)')
    _set_panel_typography(ax, D_LABEL_SIZE, D_TICK_SIZE)
    add_epoch_bands(ax, label_size=D_EPOCH_SIZE)
    ax.legend(
        frameon=False,
        loc='upper left',
        fontsize=D_LEGEND_SIZE,
        handlelength=1.3,
        labelspacing=0.45,
    )
    saved.append(save_panel(fig, outdir, 'fig10_d'))

    make_contact_sheet(saved, outdir / 'fig10_contact_sheet.png', columns=2)


if __name__ == '__main__':
    render()
