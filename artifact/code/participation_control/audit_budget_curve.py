#!/usr/bin/env python3
"""Equal-budget trigger attribution over five audit budgets."""
from __future__ import annotations
import argparse, hashlib, json, random
from pathlib import Path
from statistics import mean

from run_participation import load_risk_stream, run_repeat, write_csv

BUDGETS=(3,5,7,9,13)
MODES=("real","shuffled","random")


def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def controlled_stream(stream,mode,repeat):
    rows=[dict(x) for x in stream]
    levels=[x["risk_level"] for x in rows]
    if mode=="real": return rows
    highs=sum(x=="high" for x in levels)
    idx=list(range(len(rows)))
    rng=random.Random(340000+repeat+(0 if mode=="shuffled" else 10000))
    if mode=="shuffled":
        perm=levels[:]; rng.shuffle(perm)
        for row,lev in zip(rows,perm): row["risk_level"]=lev
    elif mode=="random":
        selected=set(rng.sample(idx,highs))
        for i,row in enumerate(rows): row["risk_level"]="high" if i in selected else ("medium" if i<100 else "low")
    else: raise ValueError(mode)
    assert sum(x["risk_level"]=="high" for x in rows)==highs
    return rows


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--risk-stream",type=Path,required=True);ap.add_argument("--output-dir",type=Path,required=True);a=ap.parse_args()
    streams,_=load_risk_stream(a.risk_stream); summary=[]
    for budget in BUDGETS:
        for mode in MODES:
            allrows=[]
            for repeat,attack,seed,stream in streams:
                print("budget-curve",budget,mode,repeat,flush=True)
                allrows.extend(run_repeat(repeat,attack,seed,controlled_stream(stream,mode,repeat),audit_regime="equal_budget",audit_budget=budget,selected_methods=("validator_only","searpc")))
            for method in ("validator_only","searpc"):
                xs=[r for r in allrows if r["method"]==method]
                repeats=sorted({r["repeat"] for r in xs})
                den=sum(r["risk_score"] for r in xs)
                summary.append({
                    "audit_budget":budget,"trigger_mode":mode,"method":method,"blocks":len(xs),
                    "risk_weighted_exposure":sum(r["risk_score"]*r["latent_post_control_exceedance"] for r in xs)/den,
                    "unweighted_exceedance_rate":mean(r["latent_post_control_exceedance"] for r in xs),
                    "actual_handoff_rate":mean(r["actual_handoff"] for r in xs),
                    "total_resampling_rate":mean(r["resampled"] for r in xs),
                    "mean_quarantined_count":mean(r["quarantined"] for r in xs),
                    "mean_active_pool":mean(r["active_pool"] for r in xs),
                    "scheduled_audits":sum(r["audits"] for r in xs),
                    "delivered_valid_records":sum(
                        max(r["evidence_records"] for r in xs if r["repeat"]==repeat)
                        for repeat in repeats
                    ),
                    "invalid_records":0,"mean_wire_messages":mean(r["total_wire_messages"] for r in xs),
                    "final_Q_min":min(r["final_Q"] for r in xs),"final_Q_max":max(r["final_Q"] for r in xs),
                    "illegal_acceptance":sum(r["final_illegal_acceptance"] for r in xs),
                })
    a.output_dir.mkdir(parents=True,exist_ok=True)
    write_csv(a.output_dir/"AUDIT_BUDGET_CURVE_summary.csv",summary)
    manifest={"budgets":BUDGETS,"trigger_modes":MODES,"input_sha256":digest(a.risk_stream),"runner_sha256":digest(Path(__file__)),"rq4_runner_sha256":digest(Path(__file__).with_name("run_participation.py")),"rows":len(summary)}
    (a.output_dir/"AUDIT_BUDGET_CURVE_manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
if __name__=="__main__": main()
