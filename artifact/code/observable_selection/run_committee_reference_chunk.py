#!/usr/bin/env python3
from __future__ import annotations
import argparse,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[1]; FROZEN=ROOT/'code'/'frozen_searpc'; sys.path.insert(0,str(FROZEN))
import run_committee_conditioned as phase16

def main():
 ap=argparse.ArgumentParser(); ap.add_argument('--repeat',type=int,required=True); ap.add_argument('--out',type=Path,required=True); a=ap.parse_args(); orig=phase16._load_frozen_risk_streams
 def loader():
  streams,risk=orig(); keep=[s for s in streams if int(s[0])==a.repeat]; return keep,[r for r in risk if int(r['repeat'])==a.repeat]
 phase16._load_frozen_risk_streams=loader; phase16._simulate_main(a.out)
if __name__=='__main__': main()
