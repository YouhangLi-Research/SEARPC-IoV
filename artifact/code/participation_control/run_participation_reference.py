#!/usr/bin/env python3
"""SEARPC scoped evidence RQ4 observable-only participation experiment.

Changes from observable selection:
- committee seed is bound to the canonical evidence-state root;
- main validator admission uses a finite-state delivered-audit controller with
  no Beta/posterior control input;
- latent post-control fault-budget exceedance and observable handoff remain
  separate variables.
"""
from __future__ import annotations

import argparse, csv, hashlib, json, math
from collections import defaultdict
from pathlib import Path
from statistics import mean
import random

from canonical_evidence import CanonicalEvidenceRecord, RollingEvidenceRoot, canonical_cut, derive_bound_seed
from validator_fsm import ValidatorAdmissionFSM, AdmissionState
from observable_fast_path import (
    plan_fast_path, decide_from_observation, simulate_transcript_from_fault_labels,
    offline_fault_evaluation,
)
from durac import CertifiedSelection, ValidatorCandidate
from durac.consensus import pbft_protocol_message_count
from run_durac_validator_recovery import _domains, _latencies, _initial_means
from run_durac_rotating_attack import BASE_SEED, COVERAGE, DELAY, ERROR_RATE, _compromised, _paired_uniform
from run_dual_path import _audit_domain
from run_closed_loop import AUDIT_WIRE_MESSAGES

N=40; K=13; QK=9; Q=27
EQUAL_AUDIT_BUDGET=math.ceil(0.50*K)  # prespecified: 50% of the 13-seat fast committee = 7 audits/block
METHODS=('static_k13','feedback_fixed','content_only','validator_only','searpc')
DYNAMIC=('feedback_fixed','content_only','validator_only','searpc')


def digest(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''): h.update(b)
    return h.hexdigest()


def write_csv(path:Path,rows:list[dict]):
    if not rows: raise ValueError('empty rows')
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def load_risk_stream(path:Path):
    grouped=defaultdict(list); rows=[]
    with path.open(newline='',encoding='utf-8') as f:
        for raw in csv.DictReader(f):
            row={
                'repeat':int(raw['repeat']),'attack':raw['attack'],'seed':int(raw['seed']),
                'block':int(raw['block']),'source_index':int(raw['source_index']),
                'risk_score':float(raw['risk_score']),'risk_level':raw['risk_level'],
            }
            rows.append(row); grouped[(row['repeat'],row['attack'],row['seed'])].append({k:row[k] for k in ('block','source_index','risk_score','risk_level')})
    streams=[(*key,grouped[key]) for key in sorted(grouped)]
    if len(streams)!=10 or any(len(s)!=600 for *_,s in streams): raise ValueError('unexpected risk-stream shape')
    return streams,rows


def candidate_list(ids,domains,latencies):
    return [ValidatorCandidate(int(i),.5,domains[i],float(latencies[i])) for i in sorted(ids)]


def warning_cutoff(method,high):
    if method in ('feedback_fixed','content_only'): return None
    if method=='validator_only': return 2
    if method=='searpc': return 1 if high else 2
    raise ValueError(method)


def enhanced_audit(method,high,primary_max,resampled):
    if method=='feedback_fixed': return False
    if method=='content_only': return high
    if method=='validator_only': return primary_max>0 or resampled
    if method=='searpc': return high or primary_max>0 or resampled
    raise ValueError(method)


def cohorts():
    means=_initial_means(); ranked=sorted(means,key=lambda i:(-means[i],i))
    return tuple(frozenset(ranked[s:s+12]) for s in (0,12,24))


def main_seed(repeat,block,root,purpose):
    legacy=BASE_SEED+1_600_000_000+repeat*10_000_000+block*10_000
    return derive_bound_seed(base_seed=legacy,height=block,view=0,evidence_root=root,purpose=purpose)


def _rank_ids(repeat:int,block:int,ids,stream_id:int):
    return sorted(ids, key=lambda vid: (_paired_uniform(repeat=repeat,block=block,validator_id=int(vid),stream=stream_id), int(vid)))

def _audit_targets_for_regime(*, regime:str, repeat:int, block:int, method:str, selected_ids, warned, quarantined, probation, active, enhanced:bool):
    '''Return (targets, coverage) under a frozen observation-budget regime.

    adaptive: original observable selection/scoped evidence policy.
    shared_exogenous: every dynamic method receives the same seven exogenous audits.
    equal_budget: every dynamic method receives exactly seven audits, but its own
      selected/warning/quarantine priorities determine which seven.
    '''
    if regime == 'adaptive':
        targets=set(selected_ids)|set(warned)|set(quarantined)|set(probation)
        if not targets:
            targets=set(range(N))
        return tuple(sorted(targets)), (1.0 if enhanced else COVERAGE)
    if regime == 'shared_exogenous':
        return tuple(_rank_ids(repeat,block,range(N),41)[:EQUAL_AUDIT_BUDGET]), 1.0
    if regime == 'equal_budget':
        priority=[]
        seen=set()
        for bucket in (selected_ids, warned, quarantined, probation, active, range(N)):
            for vid in _rank_ids(repeat,block,bucket,42):
                vid=int(vid)
                if vid not in seen:
                    seen.add(vid); priority.append(vid)
                if len(priority)>=EQUAL_AUDIT_BUDGET:
                    return tuple(priority),1.0
        return tuple(priority),1.0
    raise ValueError(regime)

def run_repeat(repeat,attack,seed,stream,audit_regime='adaptive'):
    domains,latencies=_domains(),_latencies(); cohort_tuple=cohorts()
    static_registered=candidate_list(range(N),domains,latencies)
    trackers={m:ValidatorAdmissionFSM(range(N),failure_trigger=3,probation_successes=5,activation_successes=5,minimum_audit_domains=2) for m in DYNAMIC}
    warnings={m:{i:0 for i in range(N)} for m in DYNAMIC}
    queues={m:defaultdict(list) for m in DYNAMIC}
    roots={m:RollingEvidenceRoot() for m in DYNAMIC}
    rows=[]
    for item in stream:
        block=int(item['block']); risk=float(item['risk_score']); high=item['risk_level']=='high'; compromised=_compromised(block,*cohort_tuple)
        # Deliver the canonical batch before making height-h protocol decisions.
        for m in DYNAMIC:
            # Apply replicated audit evidence in canonical serialization order,
            # not physical/network arrival order.  This is the executable form
            # of the height-h canonical evidence cut.
            batch = canonical_cut(queues[m].pop(block, []), decision_height=block)
            for record in batch:
                upd = trackers[m].update(
                    record.subject_id, record.outcome, audit_domain=record.source_domain
                )
                warnings[m][record.subject_id] = upd.failure_streak
            roots[m].append_batch(batch)

        event=f'v33-rq4-{repeat}-{block}'
        # Static k13 has no adaptive evidence state; bind to the canonical empty root.
        static_root=RollingEvidenceRoot().root
        sseed=main_seed(repeat,block,static_root,'primary')
        sp=plan_fast_path(static_registered,static_registered,size=K,selection=CertifiedSelection.DIVERSE_UNIFORM,seed=sseed,event_id=event+'|static',leader_reputation_weighted=False,backup_collector_enabled=True)
        seval=offline_fault_evaluation(sp,byzantine_ids=compromised)
        strans=simulate_transcript_from_fault_labels(sp,byzantine_ids=compromised)
        sdec=decide_from_observation(sp,strans,use_full_certificate=True,fallback_enabled=True,backup_collector_enabled=True)
        rows.append({
            'repeat':repeat,'attack':attack,'seed':seed,'block':block,'method':'static_k13','audit_regime':audit_regime,'risk_score':risk,'content_level':'high' if high else 'low',
            'evidence_root':static_root,'evidence_records':0,'active_pool':N,'quarantined':0,'probation':0,'primary_warning_max':0,'resampled':0,
            'latent_initial_exceedance':seval.fault_budget_exceedance,'latent_post_control_exceedance':seval.fault_budget_exceedance,
            'warning_triggered_resampling':0,'content_triggered_resampling':0,'direct_standard':0,'actual_handoff':sdec.actual_handoff,
            'hint_assembly_timeout':sdec.hint_assembly_timeout,'invalid_hint':sdec.invalid_hint,'block_unavailable':sdec.block_unavailable,
            'fallback_total':sdec.fallback_triggered,'audits':0,'protocol_messages':sdec.protocol_message_count,'total_wire_messages':sdec.protocol_message_count,
            'final_Q':Q,'final_legal_commit':sdec.final_legal_eventual_commit,'final_illegal_acceptance':sdec.final_illegal_block_accepted,
            'primary_member_ids':'|'.join(map(str,sp.member_ids)),'selected_member_ids':'|'.join(map(str,sp.member_ids)),
        })

        for m in DYNAMIC:
            tr=trackers[m]; active=set(tr.active_ids); pool=candidate_list(active,domains,latencies); registered=candidate_list(range(N),domains,latencies)
            direct=int(len(pool)<K); resampled=0; pmax=0; initial=None; final=None; selected_ids=(); primary_ids=(); actual_handoff=timeout=invalid=unavailable=0
            proto=pbft_protocol_message_count(N) if direct else 0; final_legal=1; final_illegal=0
            root=roots[m].root; seed_primary=main_seed(repeat,block,root,'primary')
            if not direct:
                primary=plan_fast_path(pool,registered,size=K,selection=CertifiedSelection.DIVERSE_UNIFORM,seed=seed_primary,event_id=event,leader_reputation_weighted=False,backup_collector_enabled=True)
                primary_ids=primary.member_ids; initial=offline_fault_evaluation(primary,byzantine_ids=compromised)
                pmax=max((warnings[m].get(v,0) for v in primary.member_ids),default=0); cutoff=warning_cutoff(m,high); plan=primary
                if cutoff is not None and pmax>=cutoff:
                    clean=[c for c in pool if warnings[m].get(c.validator_id,0)<cutoff]
                    if len(clean)<K: direct=1; proto=pbft_protocol_message_count(N)
                    else:
                        seed_res=main_seed(repeat,block,root,'resample')
                        plan=plan_fast_path(clean,registered,size=K,selection=CertifiedSelection.DIVERSE_UNIFORM,seed=seed_res,event_id=event+'|resample',leader_reputation_weighted=False,backup_collector_enabled=True); resampled=1
                if not direct:
                    selected_ids=plan.member_ids; final=offline_fault_evaluation(plan,byzantine_ids=compromised)
                    transcript=simulate_transcript_from_fault_labels(plan,byzantine_ids=compromised)
                    dec=decide_from_observation(plan,transcript,use_full_certificate=True,fallback_enabled=True,backup_collector_enabled=True)
                    actual_handoff=dec.actual_handoff; timeout=dec.hint_assembly_timeout; invalid=dec.invalid_hint; unavailable=dec.block_unavailable; proto=dec.protocol_message_count; final_legal=dec.final_legal_eventual_commit; final_illegal=dec.final_illegal_block_accepted
            warned={v for v in active if warnings[m].get(v,0)>0}
            enh=enhanced_audit(m,high,pmax,resampled)
            targets,coverage=_audit_targets_for_regime(
                regime=audit_regime, repeat=repeat, block=block, method=m, selected_ids=selected_ids,
                warned=warned, quarantined=tr.quarantined_ids, probation=tr.probation_ids, active=active, enhanced=enh,
            )
            audits=0
            for vid in targets:
                if coverage<1.0 and _paired_uniform(repeat=repeat,block=block,validator_id=vid,stream=1)>=coverage: continue
                success=float(vid not in compromised)
                if _paired_uniform(repeat=repeat,block=block,validator_id=vid,stream=2)<ERROR_RATE: success=1.0-success
                due=block+DELAY; audits+=1
                if due<=len(stream):
                    domain = _audit_domain(repeat, block, vid)
                    queues[m][due].append(CanonicalEvidenceRecord(
                        evidence_id=f'{repeat}:{block}:{due}:{vid}:{domain}:{int(success>=.5)}',
                        subject_id=int(vid), evidence_kind='validator_audit', outcome=float(success),
                        source_domain=str(domain), effective_height=due-1,
                    ))
            warning_resample=int(resampled and not (m=='searpc' and high and pmax==1)); content_resample=int(resampled and m=='searpc' and high and pmax==1)
            rows.append({
                'repeat':repeat,'attack':attack,'seed':seed,'block':block,'method':m,'audit_regime':audit_regime,'risk_score':risk,'content_level':'high' if high else 'low',
                'evidence_root':root,'evidence_records':roots[m].records,'active_pool':len(active),'quarantined':len(tr.quarantined_ids),'probation':len(tr.probation_ids),'primary_warning_max':pmax,'resampled':resampled,
                'latent_initial_exceedance':int(initial.fault_budget_exceedance) if initial else 0,'latent_post_control_exceedance':int(final.fault_budget_exceedance) if final else 0,
                'warning_triggered_resampling':warning_resample,'content_triggered_resampling':content_resample,'direct_standard':direct,'actual_handoff':actual_handoff,
                'hint_assembly_timeout':timeout,'invalid_hint':invalid,'block_unavailable':unavailable,'fallback_total':int(direct or actual_handoff),
                'audits':audits,'protocol_messages':proto,'total_wire_messages':proto+AUDIT_WIRE_MESSAGES*audits,'final_Q':Q,'final_legal_commit':final_legal,'final_illegal_acceptance':final_illegal,
                'primary_member_ids':'|'.join(map(str,primary_ids)),'selected_member_ids':'|'.join(map(str,selected_ids)),
            })
    return rows


def summarize(rows):
    groups=defaultdict(list)
    for r in rows: groups[r['method']].append(r)
    out=[]
    for m,xs in groups.items():
        n=len(xs); risk_total=sum(r['risk_score'] for r in xs)
        latent=[r for r in xs if r['latent_post_control_exceedance']]; hand=[r for r in xs if r['actual_handoff']]; both=sum(r['latent_post_control_exceedance'] and r['actual_handoff'] for r in xs)
        out.append({
            'method':m,'blocks':n,'risk_weighted_latent_post_control_exposure':sum(r['risk_score']*r['latent_post_control_exceedance'] for r in xs)/risk_total,
            'latent_initial_exceedance_rate':mean(r['latent_initial_exceedance'] for r in xs),'latent_post_control_exceedance_rate':mean(r['latent_post_control_exceedance'] for r in xs),
            'actual_handoff_rate':mean(r['actual_handoff'] for r in xs),'warning_resampling_rate':mean(r['warning_triggered_resampling'] for r in xs),'content_resampling_rate':mean(r['content_triggered_resampling'] for r in xs),
            'direct_standard_rate':mean(r['direct_standard'] for r in xs),'p_handoff_given_latent_post_control':both/len(latent) if latent else 0.0,'p_latent_post_control_given_handoff':both/len(hand) if hand else 0.0,
            'mean_active_pool':mean(r['active_pool'] for r in xs),'mean_audits':mean(r['audits'] for r in xs),'mean_total_wire_messages':mean(r['total_wire_messages'] for r in xs),
            'final_Q_min':min(r['final_Q'] for r in xs),'final_Q_max':max(r['final_Q'] for r in xs),'final_legal_commit_rate':mean(r['final_legal_commit'] for r in xs),'final_illegal_acceptance':sum(r['final_illegal_acceptance'] for r in xs),
        })
    out.sort(key=lambda r:METHODS.index(r['method']))
    idx={r['method']:r for r in out}; fb=idx['feedback_fixed']; rec=idx['searpc']; val=idx['validator_only']
    for r in out:
        r['relative_exposure_reduction_vs_feedback']=1-r['risk_weighted_latent_post_control_exposure']/fb['risk_weighted_latent_post_control_exposure'] if fb['risk_weighted_latent_post_control_exposure'] else 0.0
        r['relative_exposure_reduction_vs_validator']=1-r['risk_weighted_latent_post_control_exposure']/val['risk_weighted_latent_post_control_exposure'] if val['risk_weighted_latent_post_control_exposure'] else 0.0
    return out


def paired_bootstrap(rows,reference='feedback_fixed',treated='searpc',draws=20000,seed=20260919):
    # trace/repeat is the paired inferential unit
    by=defaultdict(dict)
    for r in rows: by[(r['repeat'],r['method'])].setdefault('rows',[]).append(r)
    units=sorted({r['repeat'] for r in rows}); diffs=[]
    for u in units:
        a=by[(u,reference)]['rows']; b=by[(u,treated)]['rows']
        ar=sum(x['risk_score']*x['latent_post_control_exceedance'] for x in a)/sum(x['risk_score'] for x in a)
        br=sum(x['risk_score']*x['latent_post_control_exceedance'] for x in b)/sum(x['risk_score'] for x in b)
        ah=mean(x['actual_handoff'] for x in a); bh=mean(x['actual_handoff'] for x in b)
        diffs.append((br-ar,bh-ah))
    rng=random.Random(seed); ex=[]; hd=[]
    for _ in range(draws):
        samp=[diffs[rng.randrange(len(diffs))] for _ in diffs]; ex.append(sum(x[0] for x in samp)/len(samp)); hd.append(sum(x[1] for x in samp)/len(samp))
    ex.sort(); hd.sort(); lo=int(.025*draws); hi=min(draws-1,int(.975*draws))
    return [{
        'baseline':reference,'treated':treated,'n_traces':len(units),'bootstrap_draws':draws,
        'exposure_difference':sum(x[0] for x in diffs)/len(diffs),'exposure_ci95_low':ex[lo],'exposure_ci95_high':ex[hi],
        'handoff_difference':sum(x[1] for x in diffs)/len(diffs),'handoff_ci95_low':hd[lo],'handoff_ci95_high':hd[hi],
    }]


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--risk-stream',type=Path,required=True); ap.add_argument('--output-dir',type=Path,required=True); a=ap.parse_args()
    streams,riskrows=load_risk_stream(a.risk_stream); allrows=[]
    for repeat,attack,seed,stream in streams:
        print('rq4',repeat,attack,seed,flush=True); allrows.extend(run_repeat(repeat,attack,seed,stream))
    a.output_dir.mkdir(parents=True,exist_ok=True); write_csv(a.output_dir/'RQ4_block_level.csv',allrows); write_csv(a.output_dir/'RQ4_summary.csv',summarize(allrows)); write_csv(a.output_dir/'RQ4_paired_bootstrap.csv',paired_bootstrap(allrows))
    write_csv(a.output_dir/'RQ4_risk_stream.csv',riskrows)
    manifest={'risk_stream':str(a.risk_stream),'risk_stream_sha256':digest(a.risk_stream),'runner_sha256':digest(Path(__file__)),'rows':len(allrows),'outputs':{p.name:digest(p) for p in sorted(a.output_dir.glob('*.csv'))}}
    (a.output_dir/'RQ4_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True),encoding='utf-8'); print(json.dumps(manifest,indent=2))
if __name__=='__main__': main()
