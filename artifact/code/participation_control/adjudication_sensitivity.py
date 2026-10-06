#!/usr/bin/env python3
"""Compact scoped evidence vehicle-adjudication sensitivity.

Prespecified matrix:
  error in {0, 0.05, 0.10}
  canonical visibility delay in {0, 10, 30} events
  first five frozen paired seeds
Role test: 50% role overlap, main dual-role three-state method.
Domain test: concentrated, multiplicity=7, 2x2 Mean/LCB x Cap/NoCap.
No method threshold is changed.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os
from concurrent.futures import ProcessPoolExecutor,as_completed
from pathlib import Path
from statistics import mean
import numpy as np
import run_holdout_authorization as role
import run_durac_domain_cap_2x2 as domain
from run_role_authorization import load_bundle

ERRORS=(0.0,0.05,0.10)
DELAYS=(0,10,30)
SEEDS=tuple(range(260825,260830))
OVERLAP=0.5

def sha(p:Path): return hashlib.sha256(p.read_bytes()).hexdigest()
def write_csv(path,rows):
    if not rows: raise ValueError('empty')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def _role_job(args):
    attack,trace,attackers,domains,delay,error,seed=args
    rows=role.run_cell(attack,trace,attackers,domains,OVERLAP,seed,adjudication_delay=delay,adjudication_error=error)
    row=next(r for r in rows if r['variant']=='dual_role_three_state')
    return {'layer':'role','attack':attack,'delay':delay,'error':error,'seed':seed,
            'data_malicious_trusted_rate':row['data_malicious_trusted_rate'],
            'opinion_malicious_trusted_rate':row['opinion_malicious_trusted_rate'],
            'data_trusted_coverage':row['data_trusted_coverage'],
            'opinion_trusted_coverage':row['opinion_trusted_coverage'],
            'event_macro_f1':row['event_macro_f1'],'event_fpr':row['event_fpr']}

def _domain_job(args):
    attack,trace,delay,error,seed=args
    rows=domain.run_cell(attack,trace,'concentrated',7,seed,adjudication_delay=delay,adjudication_error=error)
    out=[]
    for r in rows:
        out.append({'layer':'domain','attack':attack,'delay':delay,'error':error,'seed':seed,'variant':r['variant'],
                    'early_adversarial_weight_share':r['early_adversarial_weight_share'],
                    'window_adversarial_weight_share':r['window_adversarial_weight_share'],
                    'early_fused_error_rate':r['early_fused_error_rate'],'window_fused_error_rate':r['window_fused_error_rate'],
                    'event_macro_f1':r['event_macro_f1'],'event_fpr':r['event_fpr']})
    return out

def summarize_role(rows):
    out=[]
    for attack in role.ATTACKS:
      for delay in DELAYS:
       for error in ERRORS:
        x=[r for r in rows if r['attack']==attack and r['delay']==delay and r['error']==error]
        item={'attack':attack,'delay':delay,'error':error,'seeds':len(x)}
        for k in ('data_malicious_trusted_rate','opinion_malicious_trusted_rate','data_trusted_coverage','opinion_trusted_coverage','event_macro_f1','event_fpr'):
            item[k]=mean(float(r[k]) for r in x)
        out.append(item)
    return out

def summarize_domain(rows):
    out=[]
    for attack in domain.ATTACKS:
      for delay in DELAYS:
       for error in ERRORS:
        for weighting in ('mean','lcb'):
            b=f'{weighting}_no_cap'; c=f'{weighting}_cap'
            paired=[]
            for seed in SEEDS:
                rb=next(r for r in rows if r['attack']==attack and r['delay']==delay and r['error']==error and r['seed']==seed and r['variant']==b)
                rc=next(r for r in rows if r['attack']==attack and r['delay']==delay and r['error']==error and r['seed']==seed and r['variant']==c)
                paired.append((rb,rc))
            base=mean(float(bx['early_adversarial_weight_share']) for bx,_ in paired); cap=mean(float(cx['early_adversarial_weight_share']) for _,cx in paired)
            out.append({'attack':attack,'delay':delay,'error':error,'weighting':weighting,'seeds':len(paired),
                        'early_adverse_no_cap':base,'early_adverse_cap':cap,
                        'early_relative_reduction':(base-cap)/base if base else 0.0,
                        'window_adverse_no_cap':mean(float(bx['window_adversarial_weight_share']) for bx,_ in paired),
                        'window_adverse_cap':mean(float(cx['window_adversarial_weight_share']) for _,cx in paired),
                        'event_macro_f1_delta_cap_minus_no_cap':mean(float(cx['event_macro_f1'])-float(bx['event_macro_f1']) for bx,cx in paired),
                        'event_fpr_delta_cap_minus_no_cap':mean(float(cx['event_fpr'])-float(bx['event_fpr']) for bx,cx in paired)})
    return out

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--domain-predictions',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);ap.add_argument('--workers',type=int,default=min(5,os.cpu_count() or 4));a=ap.parse_args()
    if a.output_dir.exists() and any(a.output_dir.iterdir()): raise FileExistsError(a.output_dir)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    role_traces=load_bundle(a.bundle); domain_traces=domain.load_traces(a.domain_predictions)
    jobs=[]
    for attack,(trace,attackers,domains) in role_traces.items():
        for delay in DELAYS:
            for error in ERRORS:
                for seed in SEEDS: jobs.append(('role',(attack,trace,attackers,domains,delay,error,seed)))
    for attack,trace in domain_traces.items():
        for delay in DELAYS:
            for error in ERRORS:
                for seed in SEEDS: jobs.append(('domain',(attack,trace,delay,error,seed)))
    role_rows=[]; domain_rows=[]
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs={ex.submit(_role_job,args) if kind=='role' else ex.submit(_domain_job,args):kind for kind,args in jobs}
        for i,fu in enumerate(as_completed(futs),1):
            val=fu.result()
            if futs[fu]=='role': role_rows.append(val)
            else: domain_rows.extend(val)
            if i%10==0 or i==len(futs): print(f'adjudication sensitivity {i}/{len(futs)} jobs',flush=True)
    role_rows.sort(key=lambda r:(r['attack'],r['delay'],r['error'],r['seed']));domain_rows.sort(key=lambda r:(r['attack'],r['delay'],r['error'],r['seed'],r['variant']))
    write_csv(a.output_dir/'ADJUDICATION_ROLE_raw.csv',role_rows);write_csv(a.output_dir/'ADJUDICATION_ROLE_summary.csv',summarize_role(role_rows))
    write_csv(a.output_dir/'ADJUDICATION_DOMAIN_raw.csv',domain_rows);write_csv(a.output_dir/'ADJUDICATION_DOMAIN_summary.csv',summarize_domain(domain_rows))
    manifest={'errors':list(ERRORS),'delays':list(DELAYS),'seeds':list(SEEDS),'role_overlap':OVERLAP,'domain_layout':'concentrated','domain_multiplicity':7,'bundle_sha256':sha(a.bundle),'domain_predictions_sha256':sha(a.domain_predictions),'runner_sha256':sha(Path(__file__)),'role_runner_sha256':sha(Path(role.__file__)),'domain_runner_sha256':sha(Path(domain.__file__))}
    (a.output_dir/'ADJUDICATION_SENSITIVITY_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps(manifest,indent=2,sort_keys=True))
if __name__=='__main__':main()
