#!/usr/bin/env python3
"""Checkpointed scoped evidence RQ3 rerun using the executable malicious-opinion gate.

Scientific grid remains frozen: attacks x {concentrated,distributed_control} x
multiplicity {1,3,5,7} x 20 paired seeds x Mean/LCB x Cap/NoCap.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,time
from concurrent.futures import ProcessPoolExecutor,as_completed
from pathlib import Path
import run_durac_domain_cap_2x2 as d

SEEDS=tuple(range(260825,260845))

def sha(p:Path):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def write_csv(path,rows):
    if not rows:raise ValueError('empty')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def key_name(a,l,m,s):return f'{a}__{l}__m{m}__seed{s}.json'
def job(args):
    attack,trace,layout,m,seed=args
    t=time.time(); rows=d.run_cell(attack,trace,layout,m,seed)
    return {'attack':attack,'layout':layout,'multiplicity':m,'seed':seed,'elapsed_s':time.time()-t,'rows':rows}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--predictions',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);ap.add_argument('--workers',type=int,default=min(5,os.cpu_count() or 4));a=ap.parse_args()
    traces=d.load_traces(a.predictions);a.output_dir.mkdir(parents=True,exist_ok=True); ck=a.output_dir/'checkpoints';ck.mkdir(exist_ok=True)
    cells=[(att,traces[att],layout,m,seed) for att in d.ATTACKS for layout in d.LAYOUTS for m in d.MULTIPLICITIES for seed in SEEDS]
    pending=[]
    for att,trace,layout,m,seed in cells:
        p=ck/key_name(att,layout,m,seed)
        if p.exists():
            obj=json.loads(p.read_text());
            if len(obj.get('rows',[]))!=4:raise RuntimeError(f'bad checkpoint {p}')
        else:pending.append((att,trace,layout,m,seed))
    print(f'RQ3 cells={len(cells)} existing={len(cells)-len(pending)} pending={len(pending)}',flush=True)
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        fs={ex.submit(job,x):x for x in pending}
        for i,fu in enumerate(as_completed(fs),1):
            obj=fu.result(); p=ck/key_name(obj['attack'],obj['layout'],obj['multiplicity'],obj['seed']); tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(obj,sort_keys=True));os.replace(tmp,p)
            if i%10==0 or i==len(fs):print(f'RQ3 completed {i}/{len(fs)} new cells',flush=True)
    rows=[]
    for att,trace,layout,m,seed in cells:rows.extend(json.loads((ck/key_name(att,layout,m,seed)).read_text())['rows'])
    rows.sort(key=lambda r:(r['attack'],r['layout'],r['multiplicity'],r['seed'],r['variant']))
    # Reporting-only cardinality guard: the legacy domain module retains its original
    # five-seed SEEDS constant, while this scoped evidence rerun is explicitly 20-seed.  The
    # scientific run_cell is seed-explicit and unaffected; temporarily expose the
    # frozen 20-seed set only while computing paired reporting statistics.
    legacy_seeds = d.SEEDS
    d.SEEDS = SEEDS
    try:
        summary_rows = d.summarize(rows)
        paired_rows = d.paired_effects(rows)
    finally:
        d.SEEDS = legacy_seeds
    write_csv(a.output_dir/'RQ3_raw.csv',rows)
    write_csv(a.output_dir/'RQ3_summary.csv',summary_rows)
    write_csv(a.output_dir/'RQ3_paired_effects.csv',paired_rows)
    manifest={'seeds':list(SEEDS),'cells':len(cells),'rows':len(rows),'predictions':str(a.predictions),'predictions_sha256':sha(a.predictions),'runner_sha256':sha(Path(__file__)),'scientific_runner_sha256':sha(Path(d.__file__)),'scientific_change':'all Mean/LCB x Cap/NoCap variants share the same executable malicious-opinion exclusion gate; no numeric threshold changed','outputs':{p.name:sha(p) for p in sorted(a.output_dir.glob('*.csv'))}}
    (a.output_dir/'RQ3_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n');print(json.dumps(manifest,indent=2,sort_keys=True))
if __name__=='__main__':main()
