#!/usr/bin/env python3
"""SEARPC scoped evidence RQ2 rerun from the exact bundled trace arrays."""
from __future__ import annotations
import argparse, csv, hashlib, json, os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np

from run_holdout_authorization import run_cell as run_uniform
import run_conditional_trust as p13

SEEDS20=tuple(range(260825,260845))
OVERLAPS=(0.0,0.5,1.0)
ATTACKS=('dataReplay','timeDelayAttack')


def digest(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()


def load_bundle(path:Path):
    z=np.load(path,allow_pickle=False)
    out={}
    for a in ATTACKS:
        trace=tuple(zip(
            z[f'{a}__provider_index'].astype(int).tolist(),
            z[f'{a}__attacker'].astype(int).tolist(),
            z[f'{a}__prob'].astype(float).tolist(),
            z[f'{a}__uncertainty'].astype(float).tolist(),
        ))
        attackers=frozenset(int(x) for x in z[f'{a}__data_attackers'])
        domains=tuple(int(x) for x in z[f'{a}__domains'])
        out[a]=(trace,attackers,domains)
    return out


def write_csv(path,rows):
    if not rows: raise ValueError('empty rows')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--bundle',type=Path,required=True); ap.add_argument('--output-dir',type=Path,required=True)
    ap.add_argument('--workers',type=int,default=min(10,os.cpu_count() or 4)); a=ap.parse_args()
    if a.output_dir.exists() and any(a.output_dir.iterdir()): raise FileExistsError(a.output_dir)
    a.output_dir.mkdir(parents=True,exist_ok=True)
    traces=load_bundle(a.bundle)
    uniform=[]; cold=[]; futures={}
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        for attack,(trace,data_attackers,domains) in traces.items():
            for overlap in OVERLAPS:
                for seed in SEEDS20:
                    fu=ex.submit(run_uniform,attack,trace,data_attackers,domains,overlap,seed); futures[fu]='uniform'
            for seed in SEEDS20:
                fu=ex.submit(p13.run_cold_cell,attack,trace,data_attackers,domains,seed); futures[fu]='cold'
        for i,fu in enumerate(as_completed(futures),1):
            rows=fu.result()
            if futures[fu]=='uniform':
                uniform.extend(r for r in rows if r['variant'] in ('single_role_three_state','dual_role_three_state'))
            else: cold.extend(rows)
            if i%10==0 or i==len(futures): print(f'completed {i}/{len(futures)} cells',flush=True)
    uniform.sort(key=lambda r:(r['attack'],r['overlap'],r['seed'],r['variant']))
    cold.sort(key=lambda r:(r['attack'],r['seed'],r['variant']))
    us=p13._summaries(uniform,('attack','overlap','variant')); cs=p13._summaries(cold,('attack','variant'))
    uc=p13._uniform_comparisons(uniform); cc=p13._cold_comparisons(cold)
    for name,rows in (
        ('RQ2_uniform_raw.csv',uniform),('RQ2_uniform_summary.csv',us),('RQ2_uniform_comparison.csv',uc),
        ('RQ2_cold_raw.csv',cold),('RQ2_cold_summary.csv',cs),('RQ2_cold_comparison.csv',cc)):
        write_csv(a.output_dir/name,rows)
    manifest={
        'seeds':list(SEEDS20),'bundle':str(a.bundle),'bundle_sha256':digest(a.bundle),
        'scientific_change':'malicious opinion state has zero fusion authority; no numeric threshold changed',
        'runner_sha256':digest(Path(__file__)),
        'phase12_sha256':digest(Path(run_uniform.__code__.co_filename)),
        'phase13_sha256':digest(Path(p13.__file__)),
        'outputs':{p.name:digest(p) for p in sorted(a.output_dir.glob('*.csv'))},
    }
    (a.output_dir/'RQ2_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True),encoding='utf-8')
    print(json.dumps(manifest,indent=2,sort_keys=True))

if __name__=='__main__': main()
