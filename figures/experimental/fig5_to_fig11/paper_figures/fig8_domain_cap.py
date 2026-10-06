import matplotlib.pyplot as plt
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet

PANELS = [
    ('dataReplay', 'concentrated', 'fig8_a'),
    ('timeDelayAttack', 'concentrated', 'fig8_b'),
    ('dataReplay', 'distributed_control', 'fig8_c'),
    ('timeDelayAttack', 'distributed_control', 'fig8_d'),
]
ORDER = [
    ('mean_no_cap', 'Posterior mean', '#4D4D4D', 'o', '-'),
    ('mean_cap', 'Mean + domain cap', METHOD_COLORS['RF'], 's', '-'),
    ('lcb_no_cap', 'SEARPC w/o Domain Cap', METHOD_COLORS['HGBDT'], '^', '--'),
    ('lcb_cap', 'SEARPC', METHOD_COLORS['SEARPC'], 'D', '-'),
]


def render():
    apply_style()
    # This is the frozen scoped evidence domain-cap projection retained unchanged in participation control.
    df = load_csv('RQ3_summary_student_t.csv')
    outdir = OUTPUT_DIR / 'fig8'
    subdf = df[df['metric'] == 'early_adversarial_weight_share']
    saved = []

    for attack, layout, stem in PANELS:
        fig, ax = plt.subplots(figsize=(4.04, 2.88))
        fig.subplots_adjust(top=0.86, bottom=0.18, left=0.16, right=0.98)
        panel = subdf[(subdf['attack'] == attack) & (subdf['layout'] == layout)]
        for variant, label, color, marker, ls in ORDER:
            s = panel[panel['variant'] == variant].sort_values('multiplicity')
            x = s['multiplicity'].to_numpy()
            mean = s['mean'].to_numpy() * 100.0
            low = s['ci95_low'].to_numpy() * 100.0
            high = s['ci95_high'].to_numpy() * 100.0
            ax.fill_between(x, low, high, color=color, alpha=0.10, linewidth=0)
            ax.plot(x, mean, color=color, marker=marker, linestyle=ls, linewidth=1.08, label=label)
        ax.set_xlim(0.7, 7.3)
        ax.set_xticks([1, 3, 5, 7])
        ax.set_ylim(-1, 68)
        ax.set_xlabel('Malicious identities in layout')
        ax.set_ylabel('Early adversarial share (%)')
        ax.legend(
            frameon=False,
            loc='upper center',
            bbox_to_anchor=(0.5, 1.12),
            ncol=2,
            columnspacing=1.0,
            handlelength=1.8,
        )
        saved.append(save_panel(fig, outdir, stem))

    make_contact_sheet(saved, outdir / 'fig8_contact_sheet.png', columns=2)


if __name__ == '__main__':
    render()
