#!/usr/bin/env python3
from __future__ import annotations
import argparse, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
FROZEN=ROOT/'code'/'frozen_searpc'
sys.path.insert(0,str(FROZEN)); sys.path.insert(0,str(HERE))
import run_committee_conditioned as phase16
from observable_fast_path import simulate_observable_consensus

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--start',type=int,required=True); ap.add_argument('--end',type=int,required=True); ap.add_argument('--out',type=Path,required=True); a=ap.parse_args()
    orig=phase16._load_frozen_risk_streams
    def loader():
        streams,risk=orig()
        keep=[s for s in streams if a.start <= int(s[0]) <= a.end]
        ids={int(s[0]) for s in keep}
        return keep,[r for r in risk if int(r['repeat']) in ids]
    phase16._load_frozen_risk_streams=loader
    phase16.execute_certified_committee_consensus=simulate_observable_consensus
    phase16._simulate_main(a.out)
if __name__=='__main__': main()
