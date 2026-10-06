#!/usr/bin/env python3
"""Execution-only RQ2 event-metric rerun for the frozen scoped evidence opinion gate.

This runner computes only the two manuscript-facing three-state variants and
only the event metrics that can change when malicious opinion authority is set
to zero.  Role-state/trusted-authorization metrics are intentionally omitted:
the gate is downstream of evidence/state updates, so those metrics are reused
only after a separate state-path equivalence audit.

Scientific state/update/fusion functions are imported from the frozen scoped evidence
runners; no parameter or formula is changed here.
"""
from __future__ import annotations
from collections import deque
import argparse,csv,hashlib,json,random
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
import numpy as np

from authority import apply_malicious_authority_gate
from run_dual_role import (
    RECOMMENDERS, OPINION_ATTACK_PROBABILITY, OPINION_NOISE,
    _ArrayBook, _active, _sample_recommenders, domain_capped_fusion, _event_is_false,
    select_opinion_attackers,
)
from run_holdout_authorization import (
    ADJUDICATION_DELAY, _DynamicStates, _apply_pending, _bounds, _event_metrics,
)
from run_role_authorization import load_bundle
from adjudication import perturb_binary_truth

ATTACKS=('dataReplay','timeDelayAttack')
OVERLAPS=(0.0,0.5,1.0)
SEEDS20=tuple(range(260825,260845))
VARIANTS=('single_role_three_state','dual_role_three_state')

def sha(p:Path): return hashlib.sha256(p.read_bytes()).hexdigest()

def run_event_cell(attack,trace,data_attackers,domains,overlap,seed,adjudication_delay=ADJUDICATION_DELAY,adjudication_error=0.0):
    identities=len(domains)
    opinion_attackers=select_opinion_attackers(frozenset(data_attackers),identities,overlap,seed)
    rng=random.Random(seed*1_000_003+int(overlap*1000))
    single_book=_ArrayBook(identities,1); dual_book=_ArrayBook(identities,2)
    single_states=_DynamicStates(1,identities); dual_states=_DynamicStates(2,identities)
    pending=deque(); actual_false=set(); predicted_false={v:set() for v in VARIANTS}
    for event_index,(provider,attacker,malicious_probability,message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _,item=pending.popleft(); _apply_pending(single_book,single_states,dual_book,dual_states,item)
        truth=1.0-attacker
        if attacker: actual_false.add(event_index)
        recommenders=_sample_recommenders(rng,provider,identities)
        opinions=np.empty(RECOMMENDERS,dtype=float)
        for pos,recommender in enumerate(recommenders):
            base=truth
            if recommender in opinion_attackers and _active(event_index,len(trace)) and rng.random()<OPINION_ATTACK_PROBABILITY:
                base=1.0-truth
            opinions[pos]=min(1.0,max(0.0,rng.gauss(base,OPINION_NOISE)))
        rec_domains=np.asarray([domains[i] for i in recommenders])
        sl,su=_bounds(single_book,0,provider); dl,du=_bounds(dual_book,0,provider)
        base_rel=min(1.0,max(0.0,1.0-message_uncertainty))
        sr=base_rel*(1.0-float(su-sl)); dr=base_rel*(1.0-float(du-dl))
        spm=float(single_book.mean(0,provider)); dpm=float(dual_book.mean(0,provider))
        sw=apply_malicious_authority_gate(single_book.lcb(0,recommenders),single_states.malicious[0,recommenders])
        dw=apply_malicious_authority_gate(dual_book.lcb(1,recommenders),dual_states.malicious[1,recommenders])
        cp=1.0-malicious_probability
        for variant,reliability,provider_mean,weights in (
            ('single_role_three_state',sr,spm,sw),('dual_role_three_state',dr,dpm,dw)):
            fusion=domain_capped_fusion(opinions,rec_domains,np.asarray(weights)*reliability)
            if _event_is_false(cp,reliability,provider_mean,fusion): predicted_false[variant].add(event_index)
        delivered_truth=perturb_binary_truth(truth,seed=seed,event_index=event_index,error_rate=adjudication_error,tag=f'role:{attack}:{overlap}')
        pending.append((event_index+adjudication_delay,(provider,delivered_truth,base_rel,recommenders,opinions)))
    rows=[]
    for variant in VARIANTS:
        rows.append({'attack':attack,'overlap':overlap,'seed':seed,'variant':variant,**_event_metrics(actual_false,predicted_false[variant],len(trace)),'messages':len(trace)})
    return rows

def write_csv(path,rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--bundle',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);ap.add_argument('--seeds',choices=('5','20'),default='20');ap.add_argument('--workers',type=int,default=1);ap.add_argument('--attack',choices=('all','dataReplay','timeDelayAttack'),default='all');ap.add_argument('--overlap',choices=('all','0','0.5','1'),default='all');a=ap.parse_args()
    if a.workers < 1 or a.workers > 2:
        raise ValueError('workers must be 1 or 2; higher concurrency was rejected by the frozen execution audit')
    seeds=SEEDS20[:5] if a.seeds=='5' else SEEDS20
    b=load_bundle(a.bundle); rows=[]
    jobs=[]
    for attack in ATTACKS:
        if a.attack != 'all' and attack != a.attack:
            continue
        trace,atk,dom=b[attack]
        for ov in OVERLAPS:
            if a.overlap != 'all' and abs(ov-float(a.overlap)) > 1e-12:
                continue
            for seed in seeds:
                jobs.append((attack,trace,atk,dom,ov,seed))
    if a.workers == 1:
        for j in jobs:
            print('RQ2-event',j[0],j[4],j[5],flush=True); rows.extend(run_event_cell(*j))
    else:
        with ProcessPoolExecutor(max_workers=a.workers) as ex:
            fs={ex.submit(run_event_cell,*j):j for j in jobs}
            for i,fu in enumerate(as_completed(fs),1):
                rows.extend(fu.result())
                if i % 5 == 0 or i == len(fs): print(f'RQ2-event completed {i}/{len(fs)} cells',flush=True)
    rows.sort(key=lambda r:(r['attack'],r['overlap'],r['seed'],r['variant']))
    write_csv(a.output_dir/'RQ2_event_only_raw.csv',rows)
    # simple seed means for first-look direction; final inferential tables remain downstream.
    summary=[]
    for attack in ATTACKS:
      for ov in OVERLAPS:
       for v in VARIANTS:
        xs=[r for r in rows if r['attack']==attack and r['overlap']==ov and r['variant']==v]
        summary.append({'attack':attack,'overlap':ov,'variant':v,'n_seeds':len(xs),**{m:float(np.mean([r[m] for r in xs])) for m in ('event_recall','event_fpr','event_f1','event_macro_f1')}})
    write_csv(a.output_dir/'RQ2_event_only_summary.csv',summary)
    manifest={'scientific_change':'none; execution-only projection of frozen V3.3 cell','seeds':list(seeds),'bundle_sha256':sha(a.bundle),'runner_sha256':sha(Path(__file__)),'outputs':{p.name:sha(p) for p in sorted(a.output_dir.glob('*.csv'))}}
    (a.output_dir/'RQ2_event_only_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
if __name__=='__main__': main()
