#!/usr/bin/env python3
"""participation control observable transcript robustness over projected-seed committees."""
from __future__ import annotations
import argparse, csv, hashlib, json, random
from collections import defaultdict
from pathlib import Path
from statistics import mean

from observable_fast_path import FastPathPlan, ObservableTranscript, decide_from_observation, simulate_transcript_from_fault_labels
from run_durac_validator_recovery import _initial_means
from run_durac_rotating_attack import _compromised

MODELS=('legal_sign','withhold','selective_sign','equivocation_invalid','honest_network_timeout')


def read_csv(p):
    with p.open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def write_csv(p,rows):
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()

def cohorts():
    means=_initial_means(); ranked=sorted(means,key=lambda i:(-means[i],i)); return tuple(frozenset(ranked[s:s+12]) for s in (0,12,24))

def det_u(*parts):
    h=hashlib.sha256('|'.join(map(str,parts)).encode()).digest();return int.from_bytes(h[:8],'big')/2**64

def plan_from_row(r):
    ids=tuple(int(x) for x in r['selected_member_ids'].split('|') if x!='')
    if not ids:return None
    return FastPathPlan(selection='diverse_uniform',committee_size=len(ids),member_ids=ids,leader_id=ids[0],registered_ids=frozenset(range(40)),final_quorum=27,fast_quorum=9)

def transcript(model,plan,compromised,repeat,block):
    members=set(plan.member_ids); byz=set(compromised); honest=set(range(40))-byz
    if model=='legal_sign':
        return ObservableTranscript(frozenset(members),frozenset(range(40)))
    if model=='withhold':
        return simulate_transcript_from_fault_labels(plan,byzantine_ids=byz)
    if model=='selective_sign':
        byz_fast={v for v in members&byz if det_u('sel-fast',repeat,block,v)<.5}
        byz_base={v for v in byz if det_u('sel-base',repeat,block,v)<.5}
        return ObservableTranscript(frozenset((members&honest)|byz_fast),frozenset(honest|byz_base))
    if model=='equivocation_invalid':
        invalid=bool(members&byz)
        return ObservableTranscript(frozenset(members),frozenset(range(40)),hint_structurally_valid=not invalid)
    if model=='honest_network_timeout':
        unavailable={v for v in honest if det_u('net',repeat,block,v)<.15}
        online=set(range(40))-unavailable
        return ObservableTranscript(frozenset(members&online),frozenset(online))
    raise ValueError(model)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--rq4-blocks',type=Path,required=True);ap.add_argument('--output-dir',type=Path,required=True);a=ap.parse_args()
    rows=read_csv(a.rq4_blocks); cs=cohorts(); raw=[]
    for r in rows:
        plan=plan_from_row(r)
        if plan is None: continue
        repeat=int(r['repeat']);block=int(r['block']);comp=_compromised(block,*cs); latent=int(r['latent_post_control_exceedance'])
        for model in MODELS:
            tr=transcript(model,plan,comp,repeat,block);dec=decide_from_observation(plan,tr,use_full_certificate=True,fallback_enabled=True,backup_collector_enabled=True)
            raw.append({'model':model,'method':r['method'],'repeat':repeat,'block':block,'latent_post_control_exceedance':latent,'actual_handoff':dec.actual_handoff,'hint_assembly_timeout':dec.hint_assembly_timeout,'invalid_hint':dec.invalid_hint,'block_unavailable':dec.block_unavailable,'final_legal_commit':dec.final_legal_eventual_commit,'final_illegal_acceptance':dec.final_illegal_block_accepted})
    groups=defaultdict(list)
    for r in raw:groups[(r['model'],r['method'])].append(r)
    summary=[]
    for (model,method),xs in sorted(groups.items()):
        tp=sum(x['latent_post_control_exceedance'] and x['actual_handoff'] for x in xs); fn=sum(x['latent_post_control_exceedance'] and not x['actual_handoff'] for x in xs); fp=sum((not x['latent_post_control_exceedance']) and x['actual_handoff'] for x in xs); tn=len(xs)-tp-fn-fp
        latent=tp+fn;hand=tp+fp
        summary.append({'model':model,'method':method,'attempted_blocks':len(xs),'latent_post_control_rate':mean(x['latent_post_control_exceedance'] for x in xs),'actual_handoff_rate':mean(x['actual_handoff'] for x in xs),'hint_timeout_rate':mean(x['hint_assembly_timeout'] for x in xs),'invalid_hint_rate':mean(x['invalid_hint'] for x in xs),'block_unavailable_rate':mean(x['block_unavailable'] for x in xs),'p_handoff_given_latent':tp/latent if latent else 'N/A','p_latent_given_handoff':tp/hand if hand else 'N/A','tp':tp,'fn':fn,'fp':fp,'tn':tn,'final_illegal_acceptance':sum(x['final_illegal_acceptance'] for x in xs)})
    write_csv(a.output_dir/'TRANSCRIPT_ROBUSTNESS_raw.csv',raw);write_csv(a.output_dir/'TRANSCRIPT_ROBUSTNESS_summary.csv',summary)
    manifest={'input':str(a.rq4_blocks),'input_sha256':digest(a.rq4_blocks),'runner_sha256':digest(Path(__file__)),'models':MODELS,'outputs':{p.name:digest(p) for p in sorted(a.output_dir.glob('*.csv'))}}
    (a.output_dir/'TRANSCRIPT_ROBUSTNESS_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True));print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
