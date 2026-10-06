#!/usr/bin/env python3
"""participation control audit-budget attribution ablation.

Prespecified regimes, with all scientific thresholds unchanged:
- shared_exogenous: all dynamic methods receive the exact same 7 audits/block;
- equal_budget: all dynamic methods receive exactly 7 audits/block, but target
  selection may follow their own selected/warning/admission state;
- adaptive: the full frozen SEARPC/ablation audit policy.

The budget of seven is fixed before running from ceil(0.5*k), k=13.
"""
from __future__ import annotations
import argparse, csv, hashlib, json
from pathlib import Path
from run_participation import load_risk_stream, run_repeat, summarize, write_csv, EQUAL_AUDIT_BUDGET

REGIMES=('shared_exogenous','equal_budget','adaptive')

def sha(path:Path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--risk-stream',type=Path,required=True); ap.add_argument('--output-dir',type=Path,required=True); a=ap.parse_args()
    streams,_=load_risk_stream(a.risk_stream); rows=[]; summaries=[]
    for regime in REGIMES:
        regime_rows=[]
        for repeat,attack,seed,stream in streams:
            print('audit-budget',regime,repeat,attack,seed,flush=True)
            regime_rows.extend(run_repeat(repeat,attack,seed,stream,audit_regime=regime))
        rows.extend(regime_rows)
        for item in summarize(regime_rows):
            item={'audit_regime':regime,**item,'equal_budget_per_block':EQUAL_AUDIT_BUDGET if regime!='adaptive' else ''}
            summaries.append(item)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    write_csv(a.output_dir/'AUDIT_BUDGET_block_level.csv',rows)
    write_csv(a.output_dir/'AUDIT_BUDGET_summary.csv',summaries)
    manifest={
        'regimes':list(REGIMES),'equal_budget_per_block':EQUAL_AUDIT_BUDGET,
        'budget_definition':'ceil(0.50*k), k=13, frozen before outcomes',
        'risk_stream':str(a.risk_stream),'risk_stream_sha256':sha(a.risk_stream),
        'runner_sha256':sha(Path(__file__)),'rq4_runner_sha256':sha(Path(__file__).with_name('run_participation.py')),
        'rows':len(rows),
    }
    (a.output_dir/'AUDIT_BUDGET_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps(manifest,indent=2,sort_keys=True))
if __name__=='__main__': main()
