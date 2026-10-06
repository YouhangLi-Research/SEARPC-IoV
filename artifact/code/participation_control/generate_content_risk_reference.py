#!/usr/bin/env python3
"""Generate the scoped evidence content-risk streams from the bundled exact RQ2 traces.

This is the closed loop risk construction with the scoped evidence executable opinion
malicious-state gate.  It needs no raw VeReMi archive because the exact provider,
label, calibrated probability, uncertainty, domain and attacker arrays are
already bundled.
"""
from __future__ import annotations
from collections import deque
import argparse, csv, hashlib, json, math, random
from pathlib import Path
import numpy as np
from scipy.special import betaincinv

from authority import apply_malicious_authority_gate
from run_dual_role import (
    ADJUDICATION_DELAY, LCB_QUANTILE, OPINION_ATTACK_PROBABILITY, OPINION_NOISE,
    RECOMMENDERS, SEEDS, _ArrayBook, _active, _event_is_false, _sample_recommenders,
    domain_capped_fusion, select_opinion_attackers,
)
from run_holdout_authorization import _DynamicStates, _bounds

ATTACKS=('dataReplay','timeDelayAttack')
ROLE_OVERLAP=.5
BLOCKS=600
ROLLING_WINDOW=100
HIGH_QUANTILE=.90
MEDIAN_QUANTILE=.50


def digest(p:Path): return hashlib.sha256(p.read_bytes()).hexdigest()

def load_bundle(path:Path):
    z=np.load(path,allow_pickle=False); out={}
    for a in ATTACKS:
        trace=tuple(zip(z[f'{a}__provider_index'].astype(int).tolist(), z[f'{a}__attacker'].astype(int).tolist(),
                        z[f'{a}__prob'].astype(float).tolist(), z[f'{a}__uncertainty'].astype(float).tolist()))
        out[a]=(trace,frozenset(int(x) for x in z[f'{a}__data_attackers']),tuple(int(x) for x in z[f'{a}__domains']))
    return out

def online_levels(scores):
    levels=[]
    for i,score in enumerate(scores):
        if i<ROLLING_WINDOW: levels.append('medium'); continue
        hist=np.asarray(scores[i-ROLLING_WINDOW:i],dtype=float)
        med=float(np.quantile(hist,MEDIAN_QUANTILE,method='linear')); high=float(np.quantile(hist,HIGH_QUANTILE,method='linear'))
        levels.append('high' if score>=high else 'low' if score<med else 'medium')
    return levels

def evenly_spaced_indices(length,count):
    idx=np.rint(np.linspace(0,length-1,count)).astype(int)
    if len(set(map(int,idx)))!=count: raise ValueError('duplicate block mapping')
    return tuple(map(int,idx))

def apply_pending(book,states,item):
    provider,truth,reliability,recommenders,opinions=item
    pi=np.asarray([provider],dtype=int); tv=np.asarray([truth],dtype=float); rw=np.asarray([reliability],dtype=float)
    book.update(0,pi,tv,rw); states.observe(0,pi,tv)
    honesty=1.0-np.abs(opinions-truth); book.update(1,recommenders,honesty); states.observe(1,recommenders,honesty)

def risk_stream(attack,seed,trace,data_attackers,domains):
    opinion_attackers=select_opinion_attackers(data_attackers,len(domains),ROLE_OVERLAP,seed)
    rng=random.Random(seed*1_000_003+140014)
    book=_ArrayBook(len(domains),2); states=_DynamicStates(2,len(domains)); pending=deque(); scores=[]
    for event_index,(provider,attacker,malicious_probability,message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _,item=pending.popleft(); apply_pending(book,states,item)
        truth=1.0-attacker
        recommenders=_sample_recommenders(rng,provider,len(domains))
        opinions=np.empty(RECOMMENDERS,dtype=float)
        for pos,recommender in enumerate(recommenders):
            base=truth
            if recommender in opinion_attackers and _active(event_index,len(trace)) and rng.random()<OPINION_ATTACK_PROBABILITY:
                base=1.0-truth
            opinions[pos]=min(1.0,max(0.0,rng.gauss(base,OPINION_NOISE)))
        rec_domains=np.asarray([domains[i] for i in recommenders])
        pl,pu=_bounds(book,0,provider); provider_mean=float(book.mean(0,provider))
        reliability=min(1.0,max(0.0,1.0-message_uncertainty))*(1.0-float(pu-pl))
        raw=np.asarray(book.lcb(1,recommenders))*reliability
        weights=apply_malicious_authority_gate(raw,states.malicious[1,recommenders])
        value,disagreement,effective_weight,represented_domains=domain_capped_fusion(opinions,rec_domains,weights)
        alpha=1.0+reliability*(1.0-malicious_probability)+provider_mean
        beta_v=1.0+reliability*malicious_probability+(1.0-provider_mean)
        if represented_domains:
            ow=min(1.0,effective_weight/represented_domains)*(1.0-disagreement)
            alpha+=ow*value; beta_v+=ow*(1.0-value)
        credibility_lcb=float(betaincinv(alpha,beta_v,LCB_QUANTILE))
        scores.append(1.0-credibility_lcb)
        base_rel=min(1.0,max(0.0,1.0-message_uncertainty))
        pending.append((event_index+ADJUDICATION_DELAY,(provider,truth,base_rel,recommenders,opinions)))
    levels=online_levels(scores); selected=evenly_spaced_indices(len(scores),BLOCKS)
    return [{'block':b,'source_index':idx,'risk_score':scores[idx],'risk_level':levels[idx]} for b,idx in enumerate(selected,1)]

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--bundle',type=Path,required=True); ap.add_argument('--output',type=Path,required=True); a=ap.parse_args()
    traces=load_bundle(a.bundle); rows=[]; repeat=0
    for attack in ATTACKS:
        trace,attackers,domains=traces[attack]
        for seed in SEEDS:
            repeat+=1; stream=risk_stream(attack,seed,trace,attackers,domains)
            rows.extend({'repeat':repeat,'attack':attack,'seed':seed,**x} for x in stream)
            print('risk',repeat,attack,seed,{k:sum(x['risk_level']==k for x in stream) for k in ('low','medium','high')},flush=True)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    manifest={'bundle':str(a.bundle),'bundle_sha256':digest(a.bundle),'runner_sha256':digest(Path(__file__)),'rows':len(rows),'output_sha256':digest(a.output)}
    a.output.with_suffix('.manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True),encoding='utf-8')
    print(json.dumps(manifest,indent=2))
if __name__=='__main__': main()
