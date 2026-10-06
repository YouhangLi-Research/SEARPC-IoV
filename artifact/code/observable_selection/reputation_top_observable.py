#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import csv, sys
HERE=Path(__file__).resolve(); ROOT=HERE.parents[2]; FROZEN=ROOT/'code/frozen_searpc'; EXT=ROOT/'code/extensions'
sys.path.insert(0,str(FROZEN)); sys.path.insert(0,str(EXT)); sys.path.insert(0,str(HERE.parent))
import run_committee_conditioned as phase16
import run_searpc_v3_robustness as robust
from observable_fast_path import simulate_observable_consensus

def main():
    # Patch both call sites; labels now only generate an observable transcript.
    phase16.execute_certified_committee_consensus=simulate_observable_consensus
    robust.execute_certified_committee_consensus=simulate_observable_consensus
    streams,_=phase16._load_frozen_risk_streams()
    # Use the already frozen observable selection main block rows as the canonical feedback/SEARPC references.
    p=ROOT/'results/observable_selection/rq4_observable/DURAC_observable_selection_committee_block_level.csv'
    with p.open(newline='',encoding='utf-8') as f:
        rows=list(csv.DictReader(f))
    # Robustness helper expects numeric fields for reference metrics.
    for r in rows:
        for k in ['repeat','block','fast_attempt','fast_breach','fallback','direct_full','final_illegal_acceptance','active_pool','audits','total_wire_messages']:
            r[k]=int(float(r[k]))
        r['risk_score']=float(r['risk_score']); r['audit_delay_blocks']=10; r['audit_error_rate']=0.05
    out=ROOT/'results/observable_selection/reputation_top_observable'; out.mkdir(parents=True,exist_ok=True)
    summary=robust._run_reputation_top(rows,streams,out)
    print(summary)
if __name__=='__main__': main()
