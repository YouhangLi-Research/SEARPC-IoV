import numpy as np
import matplotlib.pyplot as plt
from .style import apply_style, OUTPUT_DIR, METHOD_COLORS
from .data_loader import load_csv
from .helpers import save_panel, make_contact_sheet


def render():
    apply_style()
    overall = load_csv('RQ4_summary.csv').set_index('method')
    yadav = load_csv('YADAV_RQ4_overall.csv').iloc[0]
    outdir = OUTPUT_DIR / 'fig9'
    saved=[]

    # (a)
    fig, ax = plt.subplots(figsize=(4.15, 2.92))
    fig.subplots_adjust(top=0.86, bottom=0.25, left=0.16, right=0.98)
    order_a = [
        ('static_k13','Static k=13', METHOD_COLORS['Static k13']),
        ('yadav','Yadav', METHOD_COLORS['Yadav direct']),
        ('feedback_fixed','SEARPC w/o Same-k Reconfiguration', METHOD_COLORS['Feedback fixed']),
        ('content_only','Content only', METHOD_COLORS['Content only']),
        ('validator_only','SEARPC', METHOD_COLORS['Validator only']),
        ('searpc','SEARPC + optional extension', METHOD_COLORS['SEARPC']),
    ]
    vals=[]; labels=[]; colors=[]
    for key, label, color in order_a:
        if key=='yadav':
            vals.append(yadav['risk_weighted_fast_exposure']*100)
        else:
            vals.append(overall.loc[key,'risk_weighted_latent_post_control_exposure']*100)
        labels.append(label); colors.append(color)
    x=np.arange(len(labels))
    ax.bar(x, vals, color=colors, alpha=0.80, edgecolor='none')
    ax.set_xticks(x, labels, rotation=18, ha='right')
    ax.set_ylabel('Risk-weighted fault-budget exposure (%)')
    ax.set_ylim(0, 24.5)
    saved.append(save_panel(fig, outdir, 'fig9_a'))

    # (b)
    fig, ax = plt.subplots(figsize=(4.15, 2.92))
    fig.subplots_adjust(top=0.86, bottom=0.25, left=0.16, right=0.98)
    order_b = [
        ('static_k13','Static'), ('feedback_fixed','Feedback'), ('content_only','Content'), ('validator_only','Core'), ('searpc','Core+content')
    ]
    x=np.arange(len(order_b)); width=0.30
    fallback=[overall.loc[k,'actual_handoff_rate']*100 for k,_ in order_b]
    warning=[overall.loc[k,'warning_resampling_rate']*100 for k,_ in order_b]
    content=[overall.loc[k,'content_resampling_rate']*100 for k,_ in order_b]
    ax.bar(x-width/2, fallback, width, color=METHOD_COLORS['Feedback fixed'], alpha=0.80, edgecolor='none', label='Actual handoff')
    ax.bar(x+width/2, warning, width, color=METHOD_COLORS['Validator only'], alpha=0.80, edgecolor='none', label='Warning resampling')
    ax.bar(x+width/2, content, width, bottom=warning, color=METHOD_COLORS['SEARPC'], alpha=0.78, edgecolor='none', label='Content increment')
    ax.set_xticks(x, [label for _,label in order_b], rotation=15)
    ax.set_ylabel('Rate (%)')
    ax.set_ylim(0, 23.2)
    ax.legend(frameon=False, loc='upper center', bbox_to_anchor=(0.5,1.18), ncol=3, fontsize=6.7, columnspacing=.7, handlelength=1.2)
    saved.append(save_panel(fig, outdir, 'fig9_b'))

    # (c)
    fig, ax = plt.subplots(figsize=(4.15, 2.92))
    fig.subplots_adjust(top=0.86, bottom=0.25, left=0.16, right=0.98)
    vals=[]; labels=[]; colors=[]
    for key, label, color in order_a:
        if key=='yadav':
            vals.append(yadav['mean_total_wire_messages'])
        else:
            vals.append(overall.loc[key,'mean_total_wire_messages'])
        labels.append(label); colors.append(color)
    x=np.arange(len(labels))
    ax.bar(x, vals, color=colors, alpha=0.80, edgecolor='none')
    ax.set_xticks(x, labels, rotation=18, ha='right')
    ax.set_ylabel('Logical wire messages / block')
    ax.set_ylim(0, 660)
    saved.append(save_panel(fig, outdir, 'fig9_c'))

    # (d)
    fig, ax = plt.subplots(figsize=(4.15, 2.92))
    fig.subplots_adjust(top=0.86, bottom=0.25, left=0.16, right=0.98)
    baselines=[('feedback_fixed','Feedback fixed'),('content_only','Content only'),('validator_only','SEARPC core')]
    metrics=[('risk_weighted_latent_post_control_exposure','Exposure', METHOD_COLORS['Feedback fixed']), ('actual_handoff_rate','Handoff', METHOD_COLORS['SEARPC']), ('mean_total_wire_messages','Wire', METHOD_COLORS['Content only'])]
    x=np.arange(len(baselines)); width=0.20
    for i,(metric,label,color) in enumerate(metrics):
        vals=[]
        for key,_ in baselines:
            vals.append((overall.loc['searpc',metric]-overall.loc[key,metric])/overall.loc[key,metric]*100)
        ax.bar(x + (i-1)*width, vals, width, color=color, alpha=0.82, edgecolor='none', label=label)
    ax.axhline(0, color='#8E8E8E', linewidth=0.8)
    ax.set_xticks(x, [label for _,label in baselines], rotation=15)
    ax.set_ylabel('Core+content relative change (%)')
    ax.set_ylim(-38, 8)
    ax.legend(frameon=False, loc='upper center', bbox_to_anchor=(0.5,1.14), ncol=3, columnspacing=0.9, handlelength=1.4)
    saved.append(save_panel(fig, outdir, 'fig9_d'))

    make_contact_sheet(saved, outdir/'fig9_contact_sheet.png', columns=2)

if __name__ == '__main__':
    render()
