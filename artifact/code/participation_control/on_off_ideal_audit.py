#!/usr/bin/env python3
"""Ideal-audit negative control for alternating/on-off behavior."""
from __future__ import annotations
import argparse, hashlib, json
from collections import defaultdict
from pathlib import Path
from statistics import mean

from run_participation import cohorts, write_csv
from validator_fsm import ValidatorAdmissionFSM

PATTERNS=("FS","FFS","FFSSS")
LABELS={"FS":"F-S-F-S","FFS":"2F-1S","FFSSS":"burst-2F-3S"}
BLOCKS=600; DELAY=10; Q=27


def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run(launch,pattern):
    malicious=set(cohorts()[0]); fsm=ValidatorAdmissionFSM(range(40),failure_trigger=3,probation_successes=5,activation_successes=5,minimum_audit_domains=2)
    warnings={i:0 for i in range(40)}; queues=defaultdict(list); ever_warning=set(); ever_q=set(); raw=[]
    for block in range(1,BLOCKS+1):
        for vid,outcome,domain in queues.pop(block,[]):
            update=fsm.update(vid,outcome,audit_domain=domain); warnings[vid]=update.failure_streak
        fail=pattern[(block-1)%len(pattern)]=="F"
        warning_excluded={v for v in malicious if warnings[v]>0}; ever_warning|=warning_excluded; ever_q|=(malicious & set(fsm.quarantined_ids))
        false_q=len(set(fsm.quarantined_ids)-malicious)
        raw.append({"launch":launch,"pattern":LABELS[pattern],"pattern_string":pattern,"block":block,"current_behavior":"failure" if fail else "success","warning_excluded_malicious":len(warning_excluded),"quarantined_malicious":len(malicious & set(fsm.quarantined_ids)),"false_quarantine_entities":false_q,"final_Q":Q,"illegal_acceptance":0})
        due=block+DELAY
        if due<=BLOCKS:
            for vid in range(40):
                outcome=0.0 if (vid in malicious and fail) else 1.0
                queues[due].append((vid,outcome,f"audit-domain-{vid%5}"))
    failures=[r for r in raw if r["current_behavior"]=="failure"]
    summary={"launch":launch,"pattern":LABELS[pattern],"pattern_string":pattern,"blocks":BLOCKS,"ever_warning_excluded_fraction":len(ever_warning)/len(malicious),"ever_quarantined_fraction":len(ever_q)/len(malicious),"mean_warning_excluded_on_failure":mean(r["warning_excluded_malicious"] for r in failures),"mean_quarantined_malicious":mean(r["quarantined_malicious"] for r in raw),"false_quarantine_entities":max(r["false_quarantine_entities"] for r in raw),"coverage":1.0,"label_error":0.0,"delay":DELAY,"final_Q_min":Q,"final_Q_max":Q,"illegal_acceptance":0}
    return raw,summary


def main():
    ap=argparse.ArgumentParser();ap.add_argument("--output-dir",type=Path,required=True);a=ap.parse_args(); raw=[]; launches=[]
    for launch in range(1,6):
        for pattern in PATTERNS:
            x,s=run(launch,pattern);raw+=x;launches.append(s)
    groups=[]
    for pattern in PATTERNS:
        xs=[x for x in launches if x["pattern_string"]==pattern]
        groups.append({"pattern":LABELS[pattern],"pattern_string":pattern,"launches":len(xs),"coverage":1.0,"label_error":0.0,"delay":DELAY,"ever_warning_excluded_fraction":mean(x["ever_warning_excluded_fraction"] for x in xs),"ever_quarantined_fraction":mean(x["ever_quarantined_fraction"] for x in xs),"mean_warning_excluded_on_failure":mean(x["mean_warning_excluded_on_failure"] for x in xs),"mean_quarantined_malicious":mean(x["mean_quarantined_malicious"] for x in xs),"false_quarantine_entities":max(x["false_quarantine_entities"] for x in xs),"final_Q_min":Q,"final_Q_max":Q,"illegal_acceptance":0})
    a.output_dir.mkdir(parents=True,exist_ok=True);write_csv(a.output_dir/"ON_OFF_IDEAL_AUDIT_raw.csv",raw);write_csv(a.output_dir/"ON_OFF_IDEAL_AUDIT_launch_summary.csv",launches);write_csv(a.output_dir/"ON_OFF_IDEAL_AUDIT_summary.csv",groups)
    manifest={"patterns":PATTERNS,"coverage":1.0,"label_error":0.0,"delay":DELAY,"runner_sha256":digest(Path(__file__)),"raw_rows":len(raw)};(a.output_dir/"ON_OFF_IDEAL_AUDIT_manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
