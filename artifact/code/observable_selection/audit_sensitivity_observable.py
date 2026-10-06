#!/usr/bin/env python3
"""observable selection observable-only audit delay/error sensitivity.

This regenerates the Table-XVI experiment after removal of the base simulation oracle
path. Hidden fault labels generate simulated validator/audit behavior and are
used for latent evaluation only; control decisions consume delivered audit
outcomes and observable signature transcripts.
"""
from __future__ import annotations

from collections import defaultdict
import csv
from pathlib import Path
from random import Random
from statistics import mean
import sys

HERE=Path(__file__).resolve(); CODE=HERE.parents[1]; FROZEN=CODE/'frozen_searpc'
sys.path.insert(0,str(FROZEN)); sys.path.insert(0,str(HERE.parent))
from durac import AdmissionState, CertifiedSelection, ValidatorCandidate
from run_dual_axis import _load_frozen_risk_streams, AUDIT_WIRE_MESSAGES
from run_durac_rotating_attack import BASE_SEED, _compromised, _paired_uniform
from run_dual_path import _audit_domain
from run_durac_validator_recovery import _domains, _latencies, _initial_means
from observable_fast_path import plan_fast_path, offline_fault_evaluation, simulate_transcript_from_fault_labels, decide_from_observation
from on_off_experiment import LightAdmissionTracker, candidate_list

N=40; K=13; Q=27; BASE_COVERAGE=.50
DELAYS=(0,10,30); ERRORS=(0.,.05,.10); METHODS=('feedback_fixed','searpc')


def cohorts():
    means=_initial_means(); ranked=sorted(means,key=lambda i:(-means[i],i))
    return tuple(frozenset(ranked[s:s+12]) for s in (0,12,24))

def write_csv(path, rows):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

def run_condition(delay,error,streams):
    all_rows=[]; cohort_tuple=cohorts(); domains=_domains(); lats=_latencies()
    for repeat,attack,seed,stream in streams:
        trackers={m:LightAdmissionTracker('consecutive3') for m in METHODS}
        warnings={m:{i:0 for i in range(N)} for m in METHODS}
        # Store (vid, observed success, audit domain, truth-malicious-at-origin)
        queues={m:defaultdict(list) for m in METHODS}
        failure_truth={m:{i:[] for i in range(N)} for m in METHODS}
        false_q={m:0 for m in METHODS}; departures={m:0 for m in METHODS}
        for item in stream:
            block=int(item['block']); risk=float(item['risk_score']); high=item['risk_level']=='high'
            compromised=_compromised(block,*cohort_tuple)
            for m in METHODS:
                tr=trackers[m]
                for vid,success,domain,truth_mal in queues[m].pop(block,[]):
                    before=tr.state(vid)
                    if success < .5:
                        failure_truth[m][vid].append(bool(truth_mal)); failure_truth[m][vid]=failure_truth[m][vid][-3:]
                    else:
                        failure_truth[m][vid]=[]
                    upd=tr.update(vid,success,audit_domain=domain); warnings[m][vid]=upd.failure_streak
                    after=tr.state(vid)
                    if before is AdmissionState.ACTIVE and after is AdmissionState.QUARANTINE:
                        departures[m]+=1
                        if not any(failure_truth[m][vid]): false_q[m]+=1
                        failure_truth[m][vid]=[]

            for m in METHODS:
                tr=trackers[m]; active=set(tr.active_ids)
                pool=candidate_list(active,domains,lats); registered=candidate_list(range(N),domains,lats)
                direct=int(len(pool)<K); resampled=0; primary_max=0; initial_eval=None; final_eval=None
                members=(); actual_handoff=0; hint_timeout=0; invalid_hint=0; unavailable=0
                proto=0; final_legal=1; final_illegal=0
                event=f'v32sens-{delay}-{error}-{repeat}-{block}-{m}'
                selection_seed=BASE_SEED+1_600_000_000+repeat*10_000_000+block*10_000
                if not direct:
                    primary=plan_fast_path(pool,registered,size=K,selection=CertifiedSelection.DIVERSE_UNIFORM,seed=selection_seed,event_id=event,leader_reputation_weighted=False,backup_collector_enabled=True)
                    initial_eval=offline_fault_evaluation(primary,byzantine_ids=compromised)
                    primary_max=max((warnings[m].get(v,0) for v in primary.member_ids),default=0)
                    cutoff=None if m=='feedback_fixed' else (1 if high else 2)
                    plan=primary
                    if cutoff is not None and primary_max>=cutoff:
                        clean=[c for c in pool if warnings[m].get(c.validator_id,0)<cutoff]
                        if len(clean)<K:
                            direct=1
                        else:
                            plan=plan_fast_path(clean,registered,size=K,selection=CertifiedSelection.DIVERSE_UNIFORM,seed=selection_seed+160,event_id=event+'|resample',leader_reputation_weighted=False,backup_collector_enabled=True)
                            resampled=1
                    if not direct:
                        members=plan.member_ids; final_eval=offline_fault_evaluation(plan,byzantine_ids=compromised)
                        transcript=simulate_transcript_from_fault_labels(plan,byzantine_ids=compromised)
                        dec=decide_from_observation(plan,transcript,use_full_certificate=True,fallback_enabled=True,backup_collector_enabled=True)
                        actual_handoff=dec.actual_handoff; hint_timeout=dec.hint_assembly_timeout; invalid_hint=dec.invalid_hint; unavailable=dec.block_unavailable
                        proto=dec.protocol_message_count; final_legal=dec.final_legal_eventual_commit; final_illegal=dec.final_illegal_block_accepted
                if direct:
                    # Base finalizer sees 28 honest signatures at worst (12 Byzantine), Q=27.
                    from durac.consensus import pbft_protocol_message_count
                    proto=pbft_protocol_message_count(N); final_legal=1; final_illegal=0

                warned={v for v in active if warnings[m][v]>0}
                targets=set(members)|warned|set(tr.quarantined_ids)|set(tr.probation_ids)
                if not targets and direct: targets=set(range(N))
                enhanced=(m=='searpc' and (high or primary_max>0 or resampled))
                coverage=1.0 if enhanced else BASE_COVERAGE
                audits=0
                for vid in sorted(targets):
                    if coverage<1 and _paired_uniform(repeat=repeat, block=block, validator_id=vid, stream=1)>=coverage: continue
                    truth=vid not in compromised; obs=truth
                    if _paired_uniform(repeat=repeat, block=block, validator_id=vid, stream=2)<error: obs=not obs
                    due=block+(1 if delay==0 else delay); audits+=1
                    if due<=len(stream): queues[m][due].append((vid,float(obs),_audit_domain(repeat,block,vid),vid in compromised))
                all_rows.append({
                    'delay':delay,'error':error,'repeat':repeat,'attack':attack,'seed':seed,'block':block,'method':m,'risk_score':risk,
                    'active_pool':len(active),'quarantined':len(tr.quarantined_ids),'probation':len(tr.probation_ids),'warned_active':len(warned),
                    'latent_initial_exceedance':int(initial_eval.fault_budget_exceedance) if initial_eval else 0,
                    'latent_final_exceedance':int(final_eval.fault_budget_exceedance) if final_eval else 0,
                    'warning_triggered_resampling':resampled,'direct_standard':direct,'actual_handoff':actual_handoff,
                    'hint_assembly_timeout':hint_timeout,'invalid_hint':invalid_hint,'block_unavailable':unavailable,
                    'fallback_total':int(direct or actual_handoff),'audits':audits,'protocol_messages':proto,'total_wire_messages':proto+AUDIT_WIRE_MESSAGES*audits,
                    'false_quarantine_cumulative':false_q[m],'quarantine_departures_cumulative':departures[m],
                    'final_Q':Q,'final_legal_commit':final_legal,'final_illegal_acceptance':final_illegal,
                })
    return all_rows

def summarize(rows):
    groups=defaultdict(list)
    for r in rows: groups[(r['delay'],r['error'],r['method'])].append(r)
    out=[]
    for (d,e,m),xs in sorted(groups.items()):
        risk_total=sum(r['risk_score'] for r in xs)
        repeats=defaultdict(list)
        for r in xs: repeats[r['repeat']].append(r)
        fq=sum(max(rr['false_quarantine_cumulative'] for rr in ys) for ys in repeats.values())
        dep=sum(max(rr['quarantine_departures_cumulative'] for rr in ys) for ys in repeats.values())
        out.append({
            'delay':d,'error':e,'method':m,'blocks':len(xs),
            'risk_weighted_latent_final_exposure':sum(r['risk_score']*r['latent_final_exceedance'] for r in xs)/risk_total,
            'latent_initial_exceedance_rate':mean(r['latent_initial_exceedance'] for r in xs),
            'latent_final_exceedance_rate':mean(r['latent_final_exceedance'] for r in xs),
            'warning_triggered_resampling_rate':mean(r['warning_triggered_resampling'] for r in xs),
            'actual_handoff_rate':mean(r['actual_handoff'] for r in xs),
            'direct_standard_rate':mean(r['direct_standard'] for r in xs),
            'fallback_total_rate':mean(r['fallback_total'] for r in xs),
            'mean_active_pool':mean(r['active_pool'] for r in xs),
            'false_quarantine_n':fq,'quarantine_departures_n':dep,'false_quarantine_share':fq/dep if dep else 0.,
            'mean_wire_messages':mean(r['total_wire_messages'] for r in xs),
            'final_Q_min':min(r['final_Q'] for r in xs),'final_Q_max':max(r['final_Q'] for r in xs),
            'final_illegal_acceptance':sum(r['final_illegal_acceptance'] for r in xs),
        })
    # Add paired searpc improvement and wire ratio against feedback in same grid cell.
    idx={(r['delay'],r['error'],r['method']):r for r in out}
    for r in out:
        if r['method']=='searpc':
            b=idx[(r['delay'],r['error'],'feedback_fixed')]
            r['relative_exposure_reduction_vs_feedback']=1-r['risk_weighted_latent_final_exposure']/b['risk_weighted_latent_final_exposure']
            r['wire_ratio_vs_feedback']=r['mean_wire_messages']/b['mean_wire_messages']
        else:
            r['relative_exposure_reduction_vs_feedback']=0.; r['wire_ratio_vs_feedback']=1.
    return out

def main():
    streams,_=_load_frozen_risk_streams(); root=HERE.parents[2]; outdir=root/'results'/'observable_selection'/'audit_sensitivity'; outdir.mkdir(parents=True,exist_ok=True)
    raw=[]
    for d in DELAYS:
        for e in ERRORS:
            print('condition',d,e,flush=True); raw.extend(run_condition(d,e,streams))
    summary=summarize(raw); write_csv(outdir/'audit_sensitivity_observable_raw.csv',raw); write_csv(outdir/'audit_sensitivity_observable_summary.csv',summary)
    print('wrote',len(raw),'raw rows',len(summary),'summary rows')
if __name__=='__main__': main()
