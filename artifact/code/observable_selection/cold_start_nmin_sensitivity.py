#!/usr/bin/env python3
"""observable selection role-local cold-start evidence-floor sensitivity.

This does not change the default method. It audits the consequence of adding an
explicit effective-evidence floor on top of the frozen 5% LCB >= 0.5 rule for
the data-provider role. The role-local provider state is independent of opinion
attacker assignment, so each frozen attack trace is evaluated once.
"""
from __future__ import annotations

import csv, sys
from collections import deque
from pathlib import Path
import numpy as np
from scipy.stats import beta as beta_distribution

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
FROZEN=ROOT/'code'/'frozen_searpc'
sys.path.insert(0,str(FROZEN))
import run_holdout_authorization as p12

BUNDLE=ROOT/'data'/'derived'/'rq2_trace_bundle_exact.npz'
OUT=ROOT/'results'/'observable_selection'/'cold_start_nmin'
N_MINS=(4,8,12,20)
DELAY=int(p12.ADJUDICATION_DELAY)


def load_attack(attack:str):
    with np.load(BUNDLE) as z:
        provider=z[f'{attack}__provider_index'].astype(int)
        attacker=z[f'{attack}__attacker'].astype(int)
        uncertainty=z[f'{attack}__uncertainty'].astype(float)
        identities=len(z[f'{attack}__domains'])
    return provider,attacker,uncertainty,identities


def run_attack(attack:str):
    provider, attacker, uncertainty, identities=load_attack(attack)
    alpha=np.ones(identities,dtype=float); beta=np.ones(identities,dtype=float)
    malicious_state=np.zeros(identities,dtype=bool)
    fail=np.zeros(identities,dtype=np.int32); succ=np.zeros(identities,dtype=np.int32)
    pending=deque()
    stats={n:{'mal':0,'mal_trusted':0,'ben':0,'ben_trusted':0,'ben_denied':0,
              'first_trust':{},'trusted_actions':0} for n in N_MINS}
    for t,(pid,is_att,u) in enumerate(zip(provider,attacker,uncertainty)):
        pid=int(pid); is_att=int(is_att)
        while pending and pending[0][0] <= t:
            _,p,truth,w=pending.popleft()
            alpha[p]+=w*truth; beta[p]+=w*(1-truth)
            if truth < p12.TRUST_THRESHOLD:
                fail[p]+=1; succ[p]=0
                if fail[p]>=p12.FAILURE_STREAK: malicious_state[p]=True
            else:
                fail[p]=0; succ[p]+=1
                if malicious_state[p] and succ[p]>=p12.RECOVERY_STREAK:
                    malicious_state[p]=False; succ[p]=0
        lcb=float(beta_distribution.ppf(p12.LCB_QUANTILE,alpha[pid],beta[pid]))
        evidence=float(alpha[pid]+beta[pid]-2.0)
        for n in N_MINS:
            trusted=bool(lcb>=p12.TRUST_THRESHOLD and evidence>=n and not malicious_state[pid])
            s=stats[n]
            if is_att:
                s['mal']+=1; s['mal_trusted']+=int(trusted)
            else:
                s['ben']+=1; s['ben_trusted']+=int(trusted); s['ben_denied']+=int(not trusted)
            s['trusted_actions']+=int(trusted)
            if trusted and pid not in s['first_trust']:
                s['first_trust'][pid]=t
        truth=1.0-is_att
        reliability=min(1.0,max(0.0,1.0-float(u)))
        pending.append((t+DELAY,pid,truth,reliability))
    rows=[]
    # newcomer delay is measured in sampled events from first provider appearance
    first_seen={}
    for t,p in enumerate(provider): first_seen.setdefault(int(p),t)
    for n,s in stats.items():
        delays=[s['first_trust'][i]-first_seen[i] for i in s['first_trust'] if i in first_seen]
        rows.append({
            'attack':attack,'n_min_effective_evidence':n,
            'malicious_actions':s['mal'],
            'malicious_trusted_rate':s['mal_trusted']/s['mal'] if s['mal'] else 0.0,
            'benign_actions':s['ben'],
            'benign_trusted_coverage':s['ben_trusted']/s['ben'] if s['ben'] else 0.0,
            'benign_denial_rate':s['ben_denied']/s['ben'] if s['ben'] else 0.0,
            'newcomers_ever_trusted':len(s['first_trust']),
            'mean_first_trust_delay_events':sum(delays)/len(delays) if delays else float('nan'),
            'median_first_trust_delay_events':float(np.median(delays)) if delays else float('nan'),
            'active_pool_effect':'not_applicable_vehicle_role_gate',
            'committee_exposure_effect':'unchanged_in_core_content_trigger_is_secondary_extension',
        })
    return rows


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    rows=[]
    for attack in ('dataReplay','timeDelayAttack'): rows.extend(run_attack(attack))
    with (OUT/'cold_start_nmin_sensitivity.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader();w.writerows(rows)
    # analytical minimum full-weight successes for the frozen Beta(1,1), 5% LCB, tau=.5 rule
    min_full=None
    for n in range(0,100):
        if float(beta_distribution.ppf(p12.LCB_QUANTILE,1+n,1)) >= p12.TRUST_THRESHOLD:
            min_full=n; break
    (OUT/'cold_start_audit.txt').write_text(
        f'frozen_prior=Beta(1,1)\nlcb_quantile={p12.LCB_QUANTILE}\ntrust_threshold={p12.TRUST_THRESHOLD}\nminimum_full_weight_successes={min_full}\n',
        encoding='utf-8')
    print('minimum full-weight successes',min_full)
    for r in rows: print(r)
if __name__=='__main__': main()
