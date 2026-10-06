#!/usr/bin/env python3
"""Generate the current SEARPC Fig.4 panels from frozen summary data.

Outputs are three independent figures. No AI image generation, screenshots,
or crop-based panel creation are used.
"""
from pathlib import Path
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm
from matplotlib.ticker import FuncFormatter

PARTITIONS=['Highway Train','Highway Validation','Urban Test','Urban Holdout']
COMPONENTS=[
 ('Replay—Benign','Data Replay','benign_messages'),
 ('Replay—Attack','Data Replay','attack_messages'),
 ('Delay—Benign','Time Delay','benign_messages'),
 ('Delay—Attack','Time Delay','attack_messages')]
COMPONENT_COLORS={'Replay—Benign':'#4C78A8','Replay—Attack':'#F58518','Delay—Benign':'#54A24B','Delay—Attack':'#B279A2'}
PAIR_COLORS=['#4C78A8','#9ECAE1','#F58518','#FFBE7A','#54A24B','#A1D76A','#E45756','#F2A6A6']


def apply_style():
    plt.rcParams.update({
        'font.family':'sans-serif','font.sans-serif':['Arial','Helvetica','DejaVu Sans'],
        'font.size':10.4,'axes.labelsize':11.6,'xtick.labelsize':9.7,'ytick.labelsize':9.8,
        'legend.fontsize':8.8,'legend.title_fontsize':9.0,
        'figure.facecolor':'white','axes.facecolor':'white','axes.edgecolor':'#999999','axes.linewidth':0.8,
        'grid.color':'#BEBEBE','grid.linestyle':'--','grid.linewidth':0.6,'grid.alpha':0.50,
        'savefig.dpi':600,'figure.dpi':160,'pdf.fonttype':42,'ps.fonttype':42})


def build_tables(df):
    rows=[]
    for p in PARTITIONS:
        row={'partition':p}
        for lab,atk,fld in COMPONENTS:
            r=df[(df['partition']==p)&(df['attack']==atk)].iloc[0]
            row[lab]=int(r[fld])
        row['Total']=sum(row[x[0]] for x in COMPONENTS)
        rows.append(row)
    counts=pd.DataFrame(rows)
    rates=[]
    for ab,p in [('HT','Highway Train'),('HV','Highway Validation'),('UT','Urban Test'),('UH','Urban Holdout')]:
        for short,atk in [('Replay','Data Replay'),('Delay','Time Delay')]:
            r=df[(df['partition']==p)&(df['attack']==atk)].iloc[0]
            rates.append({'partition':p,'partition_abbr':ab,'attack':short,
                          'scenario_id':f'{ab}–{short}','attack_rate_pct':float(r['attack_rate_pct'])})
    return counts,pd.DataFrame(rates)


def save(fig,outdir,stem):
    outdir.mkdir(parents=True,exist_ok=True)
    for ext in ('png','pdf'):
        fig.savefig(outdir/f'{stem}.{ext}',bbox_inches='tight',pad_inches=0.05)
    plt.close(fig)


def main():
    here=Path(__file__).resolve().parent
    ap=argparse.ArgumentParser()
    ap.add_argument('--summary-csv',default=str(here/'data'/'fig4_dataset_distribution_summary.csv'))
    ap.add_argument('--outdir',default='/tmp/searpc_fig4')
    args=ap.parse_args()
    df=pd.read_csv(args.summary_csv); out=Path(args.outdir)
    counts,rates=build_tables(df)
    apply_style()

    # (a) compact four-partition stacked absolute distribution.
    # Optimized for three-across manuscript reproduction: short axis text,
    # two-line partition labels, and a compact 2 x 2 legend without a title.
    fig,ax=plt.subplots(figsize=(6.15,4.55))
    x=np.arange(len(counts)); bottom=np.zeros(len(counts))
    legend_labels={
        'Replay—Benign':'Replay benign', 'Replay—Attack':'Replay attack',
        'Delay—Benign':'Delay benign', 'Delay—Attack':'Delay attack'}
    for lab,_,_ in COMPONENTS:
        vals=counts[lab].to_numpy()
        ax.bar(x,vals,bottom=bottom,width=0.58,label=legend_labels[lab],
               color=COMPONENT_COLORS[lab],edgecolor='white',linewidth=0.75)
        bottom += vals
    ax.set_ylabel(r'Messages ($\times 10^5$)')
    ax.set_xticks(x,['Highway\nTrain','Highway\nValidation','Urban\nTest','Urban\nHoldout'])
    ax.set_ylim(0,8.6e5); ax.set_yticks(np.arange(0,8.1e5,2e5))
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v,_:f'{v/1e5:.0f}'))
    ax.yaxis.grid(True); ax.xaxis.grid(False); ax.set_axisbelow(True)
    ax.legend(ncol=2,loc='lower center',bbox_to_anchor=(0.5,1.015),
              frameon=False,borderaxespad=0,columnspacing=0.9,
              handlelength=1.25,handletextpad=0.42,labelspacing=0.35)
    fig.subplots_adjust(top=0.82,left=0.15,right=0.985,bottom=0.16)
    save(fig,out,'fig4_a_data_distribution')

    # (b) exact-count heatmap, log-normalized only for color mapping.
    heat=counts[[x[0] for x in COMPONENTS]].to_numpy(float)
    fig,ax=plt.subplots(figsize=(5.55,4.65))
    norm=LogNorm(vmin=heat.min(),vmax=heat.max())
    im=ax.imshow(heat,cmap='viridis',norm=norm,aspect='auto')
    ax.set_xlabel('Scenario / Message Class'); ax.set_ylabel('Evaluation Partition')
    ax.set_xticks(np.arange(4),['Replay\nBenign','Replay\nAttack','Delay\nBenign','Delay\nAttack'])
    ax.set_yticks(np.arange(4),PARTITIONS); ax.grid(False)
    for i in range(4):
        for j in range(4):
            nv=norm(heat[i,j])
            ax.text(j,i,f'{int(heat[i,j]):,}',ha='center',va='center',fontsize=9.0,
                    color='black' if nv>0.70 else 'white')
    cbar=fig.colorbar(im,ax=ax,fraction=0.043,pad=0.045); cbar.set_label('Number of Messages')
    cbar.formatter=FuncFormatter(lambda v,_:f'{int(v):,}'); cbar.update_ticks()
    fig.subplots_adjust(left=0.23,right=0.89,bottom=0.17,top=0.98)
    save(fig,out,'fig4_b_distribution_heatmap')

    # (c) four partition groups x Replay/Delay bars.
    # Group spacing and paired shades encode the 4 x 2 hierarchy without a legend.
    centers=np.array([0.0,2.55,5.10,7.65]); offset=0.40; width=0.62
    xpos=np.array([v for c in centers for v in (c-offset,c+offset)])
    fig,ax=plt.subplots(figsize=(7.15,4.60))
    ax.bar(xpos,rates['attack_rate_pct'].to_numpy(),width=width,color=PAIR_COLORS,
           edgecolor='white',linewidth=0.75)
    ax.set_ylabel('Attack-message rate (%)')
    ax.set_ylim(0,22.5); ax.set_yticks(np.arange(0,21,5))
    ax.yaxis.grid(True); ax.xaxis.grid(False); ax.set_axisbelow(True)
    ax.set_xticks(xpos,['Replay','Delay']*4); ax.tick_params(axis='x',pad=3)
    trans=ax.get_xaxis_transform()
    group_labels=['Highway\nTrain','Highway\nValidation','Urban\nTest','Urban\nHoldout']
    for center,label in zip(centers,group_labels):
        ax.text(center,-0.17,label,ha='center',va='top',transform=trans,
                fontsize=9.4,linespacing=0.95,clip_on=False)
    ax.margins(x=0.035)
    fig.subplots_adjust(left=0.125,right=0.985,bottom=0.265,top=0.985)
    save(fig,out,'fig4_c_attack_rate_grouped')

    counts.to_csv(out/'fig4_partition_component_counts.csv',index=False)
    rates.to_csv(out/'fig4_attack_rate_8scenarios.csv',index=False)

if __name__=='__main__':
    main()
