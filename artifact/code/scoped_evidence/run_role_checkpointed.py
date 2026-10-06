#!/usr/bin/env python3
"""Execution-only checkpoint wrapper for frozen scoped evidence RQ2 cells.

It imports the already-frozen scientific cell functions unchanged.  Checkpointing,
parallel scheduling and canonical row sorting are the only differences from
`run_role_authorization.py`.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,time
from concurrent.futures import ProcessPoolExecutor,as_completed
from pathlib import Path
import run_conditional_trust as p13
from run_holdout_authorization import run_cell as run_uniform
from run_role_authorization import SEEDS20,OVERLAPS,ATTACKS,load_bundle,digest,write_csv

def ckname(kind,attack,seed,overlap=None):
    return f'{kind}__{attack}__seed{seed}' + (f'__ov{int(overlap*100):03d}' if overlap is not None else '') + '.json'
def _job(kind,args):
    t=time.time()
    rows=run_uniform(*args) if kind=='uniform' else p13.run_cold_cell(*args)
    return {'kind':kind,'elapsed_s':time.time()-t,'rows':rows}
def _atomic(path,obj):
    tmp=path.with_suffix(path.suffix+'.tmp');tmp.write_text(json.dumps(obj,sort_keys=True));os.replace(tmp,path)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);ap.add_argument('--workers',type=int,default=min(5,os.cpu_count() or 4));a=ap.parse_args()
    a.output_dir.mkdir(parents=True,exist_ok=True);ck=a.output_dir/'checkpoints';ck.mkdir(exist_ok=True)
    traces=load_bundle(a.bundle); jobs=[]
    for attack,(trace,attackers,domains) in traces.items():
        for ov in OVERLAPS:
            for seed in SEEDS20: jobs.append(('uniform',(attack,trace,attackers,domains,ov,seed),ck/ckname('uniform',attack,seed,ov)))
        for seed in SEEDS20: jobs.append(('cold',(attack,trace,attackers,domains,seed),ck/ckname('cold',attack,seed)))
    pending=[]
    for kind,args,p in jobs:
        if p.exists():
            obj=json.loads(p.read_text()); expected=3 if kind=='uniform' else 2
            if len(obj.get('rows',[]))!=expected: raise RuntimeError(f'bad checkpoint {p}')
        else:pending.append((kind,args,p))
    print(f'RQ2 total={len(jobs)} existing={len(jobs)-len(pending)} pending={len(pending)}',flush=True)
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        fs={ex.submit(_job,kind,args):(kind,args,p) for kind,args,p in pending}
        for i,fu in enumerate(as_completed(fs),1):
            kind,args,p=fs[fu];obj=fu.result();_atomic(p,obj)
            if i%5==0 or i==len(fs):print(f'RQ2 checkpointed {i}/{len(fs)} new cells',flush=True)
    uniform=[];cold=[]
    for kind,args,p in jobs:
        rows=json.loads(p.read_text())['rows']
        if kind=='uniform':uniform.extend(r for r in rows if r['variant'] in ('single_role_three_state','dual_role_three_state'))
        else:cold.extend(rows)
    uniform.sort(key=lambda r:(r['attack'],r['overlap'],r['seed'],r['variant']));cold.sort(key=lambda r:(r['attack'],r['seed'],r['variant']))
    for name,rows in (
        ('RQ2_uniform_raw.csv',uniform),('RQ2_uniform_summary.csv',p13._summaries(uniform,('attack','overlap','variant'))),('RQ2_uniform_comparison.csv',p13._uniform_comparisons(uniform)),
        ('RQ2_cold_raw.csv',cold),('RQ2_cold_summary.csv',p13._summaries(cold,('attack','variant'))),('RQ2_cold_comparison.csv',p13._cold_comparisons(cold))):write_csv(a.output_dir/name,rows)
    manifest={'execution_only_wrapper':True,'cells':len(jobs),'bundle':str(a.bundle),'bundle_sha256':digest(a.bundle),'wrapper_sha256':digest(Path(__file__)),'scientific_phase12_sha256':digest(Path(run_uniform.__code__.co_filename)),'scientific_phase13_sha256':digest(Path(p13.__file__)),'outputs':{p.name:digest(p) for p in sorted(a.output_dir.glob('*.csv'))}}
    (a.output_dir/'RQ2_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');print(json.dumps(manifest,indent=2,sort_keys=True))
if __name__=='__main__':main()
