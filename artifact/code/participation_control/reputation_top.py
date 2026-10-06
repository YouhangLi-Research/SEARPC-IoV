#!/usr/bin/env python3
"""Same-pool, same-audit-schedule reputation-top baseline for participation control."""
from __future__ import annotations
import argparse, csv, hashlib, json
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from scipy.stats import beta

from durac import CertifiedSelection, ValidatorCandidate
from authorized_selection import plan_authorized_fast_path
from canonical_evidence import recorded_seed_commitment
from observable_fast_path import offline_fault_evaluation, simulate_transcript_from_fault_labels, decide_from_observation
from run_durac_validator_recovery import _domains, _latencies, _initial_means
from run_durac_rotating_attack import _compromised
from run_dual_path import _audit_domain
from run_closed_loop import AUDIT_WIRE_MESSAGES
from run_participation import cohorts, main_selection_capability, write_csv, Q, K
from validator_fsm import ValidatorAdmissionFSM


def read_csv(p):
    with Path(p).open(newline="",encoding="utf-8") as f:return list(csv.DictReader(f))
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--rq4-blocks",type=Path,required=True);ap.add_argument("--output-dir",type=Path,required=True);a=ap.parse_args()
    rows=read_csv(a.rq4_blocks); feedback={(int(r["repeat"]),int(r["block"])):r for r in rows if r["method"]=="feedback_fixed"}; risks={(int(r["repeat"]),int(r["block"])):float(r["risk_score"]) for r in rows if r["method"]=="feedback_fixed"}
    domains,latencies=_domains(),_latencies();registered=[ValidatorCandidate(i,.5,domains[i],latencies[i]) for i in range(40)];cs=cohorts();raw=[]; mismatch=0
    for repeat in range(1,11):
        fsm=ValidatorAdmissionFSM(range(40),failure_trigger=3,probation_successes=5,activation_successes=5,minimum_audit_domains=2);alpha={i:1.0 for i in range(40)};beta_v={i:1.0 for i in range(40)};queue=defaultdict(list)
        for block in range(1,601):
            for vid,outcome,domain in queue.pop(block,[]):
                fsm.update(vid,outcome,audit_domain=domain);alpha[vid]+=outcome;beta_v[vid]+=1-outcome
            r=feedback[(repeat,block)];active=set(map(int,fsm.active_ids));mismatch+=int(len(active)!=int(r["active_pool"]))
            pool=[ValidatorCandidate(i,float(beta.ppf(.05,alpha[i],beta_v[i])),domains[i],latencies[i]) for i in sorted(active)]
            seed_commitment=recorded_seed_commitment(height=block,root=r["seed_projection_root"])
            capability=main_selection_capability(repeat,block,seed_commitment,"reputation-top")
            plan=plan_authorized_fast_path(pool,registered,size=K,selection=CertifiedSelection.REPUTATION_TOP,capability=capability,leader_reputation_weighted=False,backup_collector_enabled=True)
            comp=_compromised(block,*cs);off=offline_fault_evaluation(plan,byzantine_ids=comp);tr=simulate_transcript_from_fault_labels(plan,byzantine_ids=comp);dec=decide_from_observation(plan,tr,use_full_certificate=True,fallback_enabled=True,backup_collector_enabled=True)
            outs=[x for x in r.get("audit_behavior_outcomes","").split("|") if x]
            for entry in outs:
                vid,behavior,outcome=entry.split(":");vid=int(vid);queue[block+10].append((vid,float(outcome),_audit_domain(repeat,block,vid)))
            audits=int(r["audits"])
            raw.append({"repeat":repeat,"block":block,"method":"reputation_top_same_pool","risk_score":risks[(repeat,block)],"active_pool":len(active),"selected_member_ids":"|".join(map(str,plan.member_ids)),"latent_post_control_exceedance":off.fault_budget_exceedance,"actual_handoff":dec.actual_handoff,"audits":audits,"wire_messages":dec.protocol_message_count+AUDIT_WIRE_MESSAGES*audits,"final_Q":Q,"illegal_acceptance":dec.final_illegal_block_accepted})
    summaries=[]
    for method in ("feedback_fixed","reputation_top_same_pool","searpc"):
        if method=="reputation_top_same_pool":xs=raw
        else:xs=[r for r in rows if r["method"]==method]
        risk=lambda r:float(r["risk_score"]); latent=lambda r:int(r.get("latent_post_control_exceedance",0)); hand=lambda r:int(r.get("actual_handoff",0));wire=lambda r:float(r.get("wire_messages",r.get("total_wire_messages",0)))
        den=sum(risk(r) for r in xs)
        out={"method":method,"blocks":len(xs),"risk_weighted_exposure":sum(risk(r)*latent(r) for r in xs)/den,"unweighted_exceedance_rate":mean(latent(r) for r in xs),"actual_handoff_rate":mean(hand(r) for r in xs),"mean_active_pool":mean(float(r["active_pool"]) for r in xs),"mean_audits":mean(float(r["audits"]) for r in xs),"mean_wire_messages":mean(wire(r) for r in xs),"final_Q_min":min(int(r["final_Q"]) for r in xs),"final_Q_max":max(int(r["final_Q"]) for r in xs),"illegal_acceptance":sum(int(r.get("illegal_acceptance",r.get("final_illegal_acceptance",0))) for r in xs),"same_active_pool_source":"feedback_fixed","same_audit_schedule_source":"feedback_fixed","look_ahead":0,"tie_break":"validator_id"}
        if method=="reputation_top_same_pool":
            reps=[];longs=[];unique=[]
            for repeat in range(1,11):
                z=[tuple(map(int,r["selected_member_ids"].split("|"))) for r in raw if r["repeat"]==repeat];reps+= [z[i]==z[i-1] for i in range(1,len(z))];unique.append(len(set(v for committee in z for v in committee)));best=cur=1
                for i in range(1,len(z)):cur=cur+1 if z[i]==z[i-1] else 1;best=max(best,cur)
                longs.append(best)
            out.update(adjacent_committee_repetition=mean(reps),median_longest_unchanged_run=median(longs),mean_unique_selected_validators=mean(unique))
        else:out.update(adjacent_committee_repetition="",median_longest_unchanged_run="",mean_unique_selected_validators="")
        summaries.append(out)
    a.output_dir.mkdir(parents=True,exist_ok=True);write_csv(a.output_dir/"REPUTATION_TOP_block_level.csv",raw);write_csv(a.output_dir/"REPUTATION_TOP_summary.csv",summaries)
    manifest={"input_sha256":digest(a.rq4_blocks),"runner_sha256":digest(Path(__file__)),"pool_count_mismatches":mismatch,"rows":len(raw)};(a.output_dir/"REPUTATION_TOP_manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
