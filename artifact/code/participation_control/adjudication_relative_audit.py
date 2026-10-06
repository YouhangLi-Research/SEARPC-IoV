#!/usr/bin/env python3
"""scoped evidence adjudication sensitivity extension for the preregistered interpretation audit.

This reporting/robustness extension does not change any SEARPC threshold or policy.
It fills two comparisons requested before manuscript closure:
  1) single-role vs dual-role under the same adjudication error/delay grid;
  2) concentrated Domain-Cap 1->7 endpoint slope under the same grid.

The already-computed n=7 sensitivity rows are consumed as immutable inputs; only
single/dual role cells and the missing n=1 domain endpoint are recomputed.
"""
from __future__ import annotations
import argparse, csv, json, math, os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from statistics import mean
import pandas as pd

import run_holdout_authorization as role
import run_durac_domain_cap_2x2 as domain
from run_role_authorization import load_bundle

ERRORS=(0.0,0.05,0.10)
DELAYS=(0,10,30)
SEEDS=tuple(range(260825,260830))
OVERLAP=0.5


def _write_csv(path: Path, rows: list[dict]):
    if not rows: raise ValueError('empty rows')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)


def _role_job(args):
    attack, trace, attackers, domains, delay, error, seed = args
    rows=role.run_cell(attack, trace, attackers, domains, OVERLAP, seed,
                       adjudication_delay=delay, adjudication_error=error)
    out=[]
    for variant in ('single_role_three_state','dual_role_three_state'):
        r=next(x for x in rows if x['variant']==variant)
        out.append({
            'attack':attack,'delay':delay,'error':error,'seed':seed,'variant':variant,
            'data_malicious_trusted_rate':r['data_malicious_trusted_rate'],
            'opinion_malicious_trusted_rate':r['opinion_malicious_trusted_rate'],
            'data_benign_coverage':1.0-r['data_honest_denied_rate'],
            'opinion_benign_coverage':1.0-r['opinion_honest_denied_rate'],
            'event_macro_f1':r['event_macro_f1'],'event_fpr':r['event_fpr'],
        })
    return out


def _domain_n1_job(args):
    attack, trace, delay, error, seed = args
    rows=domain.run_cell(attack, trace, 'concentrated', 1, seed,
                         adjudication_delay=delay, adjudication_error=error)
    out=[]
    for r in rows:
        out.append({
            'attack':attack,'delay':delay,'error':error,'seed':seed,'multiplicity':1,
            'variant':r['variant'],
            'early_adversarial_weight_share':r['early_adversarial_weight_share'],
            'window_adversarial_weight_share':r['window_adversarial_weight_share'],
            'early_fused_error_rate':r['early_fused_error_rate'],
            'window_fused_error_rate':r['window_fused_error_rate'],
            'event_macro_f1':r['event_macro_f1'],'event_fpr':r['event_fpr'],
        })
    return out


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--domain-predictions', type=Path, required=True)
    ap.add_argument('--base-sensitivity-dir', type=Path, required=True)
    ap.add_argument('--output-dir', type=Path, required=True)
    ap.add_argument('--workers', type=int, default=min(5, os.cpu_count() or 4))
    a=ap.parse_args()
    a.output_dir.mkdir(parents=True, exist_ok=True)
    role_traces=load_bundle(a.bundle)
    domain_traces=domain.load_traces(a.domain_predictions)

    jobs=[]
    for attack,(trace,attackers,domains) in role_traces.items():
        for delay in DELAYS:
            for error in ERRORS:
                for seed in SEEDS:
                    jobs.append(('role',(attack,trace,attackers,domains,delay,error,seed)))
    for attack,trace in domain_traces.items():
        for delay in DELAYS:
            for error in ERRORS:
                for seed in SEEDS:
                    jobs.append(('domain',(attack,trace,delay,error,seed)))

    role_rows=[]; n1_rows=[]
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs={ex.submit(_role_job,args) if kind=='role' else ex.submit(_domain_n1_job,args):kind for kind,args in jobs}
        for i,fu in enumerate(as_completed(futs),1):
            val=fu.result()
            (role_rows if futs[fu]=='role' else n1_rows).extend(val)
            if i%10==0 or i==len(futs):
                print(f'adjudication relative audit {i}/{len(futs)} jobs', flush=True)

    role_rows.sort(key=lambda r:(r['attack'],r['delay'],r['error'],r['seed'],r['variant']))
    n1_rows.sort(key=lambda r:(r['attack'],r['delay'],r['error'],r['seed'],r['variant']))
    _write_csv(a.output_dir/'ADJUDICATION_ROLE_SINGLE_DUAL_raw.csv',role_rows)
    _write_csv(a.output_dir/'ADJUDICATION_DOMAIN_N1_raw.csv',n1_rows)

    # Cross-check dual rows against the main sensitivity run.
    main_role=pd.read_csv(a.base_sensitivity_dir/'ADJUDICATION_ROLE_raw.csv')
    rr=pd.DataFrame(role_rows)
    dual=rr[rr.variant=='dual_role_three_state'].copy()
    chk=dual.merge(main_role,on=['attack','delay','error','seed'],suffixes=('_audit','_main'))
    # Cross-check only quantities that have identical semantics in both files.
    # `*_benign_coverage = 1 - honest_denied_rate` is NOT the same quantity as
    # `*_trusted_coverage`, so those coverage columns must not be compared.
    check_metrics=['data_malicious_trusted_rate','opinion_malicious_trusted_rate','event_macro_f1','event_fpr']
    chk=dual.merge(main_role,on=['attack','delay','error','seed'],suffixes=('_audit','_main'))
    max_abs=0.0
    for m in check_metrics:
        max_abs=max(max_abs,float((chk[f'{m}_audit']-chk[f'{m}_main']).abs().max()))

    # Role relative-direction summaries.
    role_summary=[]
    for attack in role.ATTACKS:
        for delay in DELAYS:
            for error in ERRORS:
                x=rr[(rr.attack==attack)&(rr.delay==delay)&(rr.error==error)]
                s=x[x.variant=='single_role_three_state']; d=x[x.variant=='dual_role_three_state']
                m=s.merge(d,on=['attack','delay','error','seed'],suffixes=('_single','_dual'))
                rec={'attack':attack,'delay':delay,'error':error,'seeds':len(m)}
                for metric in ('data_malicious_trusted_rate','opinion_malicious_trusted_rate','data_benign_coverage','opinion_benign_coverage','event_macro_f1','event_fpr'):
                    rec[f'{metric}_single']=float(m[f'{metric}_single'].mean())
                    rec[f'{metric}_dual']=float(m[f'{metric}_dual'].mean())
                    rec[f'{metric}_delta_dual_minus_single']=float((m[f'{metric}_dual']-m[f'{metric}_single']).mean())
                rec['data_role_direction_pass']=bool(rec['data_malicious_trusted_rate_delta_dual_minus_single'] < -1e-12)
                rec['opinion_role_direction_pass']=bool(rec['opinion_malicious_trusted_rate_delta_dual_minus_single'] < -1e-12)
                role_summary.append(rec)
    _write_csv(a.output_dir/'ADJUDICATION_ROLE_SINGLE_DUAL_summary.csv',role_summary)

    # Domain 1->7 endpoint slopes by condition, using immutable n=7 main-sensitivity rows.
    n1=pd.DataFrame(n1_rows)
    n7=pd.read_csv(a.base_sensitivity_dir/'ADJUDICATION_DOMAIN_raw.csv').copy()
    n7['multiplicity']=7
    domain_summary=[]
    for attack in domain.ATTACKS:
        for delay in DELAYS:
            for error in ERRORS:
                for weighting in ('mean','lcb'):
                    v0=f'{weighting}_no_cap'; v1=f'{weighting}_cap'
                    slopes=[]
                    for seed in SEEDS:
                        a1=n1[(n1.attack==attack)&(n1.delay==delay)&(n1.error==error)&(n1.seed==seed)]
                        a7=n7[(n7.attack==attack)&(n7.delay==delay)&(n7.error==error)&(n7.seed==seed)]
                        r1n=a1[a1.variant==v0].iloc[0]; r1c=a1[a1.variant==v1].iloc[0]
                        r7n=a7[a7.variant==v0].iloc[0]; r7c=a7[a7.variant==v1].iloc[0]
                        # The pre-feedback early window is empty when delay=0;
                        # its slope is therefore undefined.  Window slopes are
                        # defined for every delay and are the primary sensitivity
                        # readout.  For delay>0 we additionally report the early slope.
                        wn=float(r7n.window_adversarial_weight_share-r1n.window_adversarial_weight_share)/6.0
                        wc=float(r7c.window_adversarial_weight_share-r1c.window_adversarial_weight_share)/6.0
                        if delay>0:
                            en=float(r7n.early_adversarial_weight_share-r1n.early_adversarial_weight_share)/6.0
                            ec=float(r7c.early_adversarial_weight_share-r1c.early_adversarial_weight_share)/6.0
                        else:
                            en=ec=math.nan
                        slopes.append((wn,wc,en,ec))
                    wno=mean(x for x,_,_,_ in slopes); wcap=mean(y for _,y,_,_ in slopes)
                    if delay>0:
                        eno=mean(x for _,_,x,_ in slopes); ecap=mean(y for _,_,_,y in slopes)
                    else:
                        eno=ecap=math.nan
                    domain_summary.append({
                        'attack':attack,'delay':delay,'error':error,'weighting':weighting,'seeds':len(slopes),
                        'window_no_cap_1to7_slope':wno,'window_cap_1to7_slope':wcap,
                        'window_relative_slope_reduction':(wno-wcap)/wno if abs(wno)>1e-15 else math.nan,
                        'window_seed_count_cap_slope_lower':sum(wc<wn-1e-15 for wn,wc,_,_ in slopes),
                        'early_no_cap_1to7_slope':eno,'early_cap_1to7_slope':ecap,
                        'early_relative_slope_reduction':((eno-ecap)/eno if delay>0 and abs(eno)>1e-15 else math.nan),
                        'early_seed_count_cap_slope_lower':(sum(ec<en-1e-15 for _,_,en,ec in slopes) if delay>0 else None),
                        'registered_direction_pass':bool(wcap<wno-1e-12 and (delay==0 or ecap<eno-1e-12)),
                    })
    _write_csv(a.output_dir/'ADJUDICATION_DOMAIN_1TO7_SLOPE_summary.csv',domain_summary)

    # Coverage stability is reported, not threshold-fitted.
    rdf=pd.DataFrame(role_summary)
    coverage=[]
    for attack in role.ATTACKS:
        base=rdf[(rdf.attack==attack)&(rdf.delay==0)&(rdf.error==0.0)].iloc[0]
        for metric in ('data_benign_coverage_dual','opinion_benign_coverage_dual'):
            vals=rdf[rdf.attack==attack][metric]
            coverage.append({
                'attack':attack,'metric':metric,'clean_value':float(base[metric]),
                'minimum_over_grid':float(vals.min()),'maximum_over_grid':float(vals.max()),
                'largest_drop_from_clean':float(base[metric]-vals.min()),
            })
    _write_csv(a.output_dir/'ADJUDICATION_BENIGN_COVERAGE_STABILITY.csv',coverage)

    all_role=all(x['data_role_direction_pass'] and x['opinion_role_direction_pass'] for x in role_summary)
    all_domain=all(x['registered_direction_pass'] for x in domain_summary)
    verdict={
        'dual_rows_match_main_sensitivity_max_abs_diff':max_abs,
        'role_separation_relative_direction_preserved_all_cells':bool(all_role),
        'domain_cap_1to7_slope_attenuation_preserved_all_cells':bool(all_domain),
        'structural_adjudication_robustness_pass':bool(all_role and all_domain and max_abs<1e-12),
        'note':'Benign coverage is reported as a range/drop without introducing a post-hoc pass threshold.'
    }
    (a.output_dir/'ADJUDICATION_RELATIVE_AUDIT.json').write_text(json.dumps(verdict,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    lines=['# SEARPC V3.3 adjudication error × canonical-delay result audit','',
           'No algorithm threshold was changed. This audit adds only the missing single-vs-dual and n=1 endpoint comparisons needed to interpret the prespecified sensitivity grid.','',
           f'- Dual-role replay matches the primary sensitivity rows (max absolute difference): `{max_abs:.3e}`.',
           f'- Role-separation relative direction preserved in every attack/error/delay cell: **{"PASS" if all_role else "FAIL"}**.',
           f'- Concentrated Domain-Cap 1→7 slope attenuation preserved in every attack/error/delay/weighting cell: **{"PASS" if all_domain else "FAIL"}**.',
           '- Benign coverage is reported descriptively; no outcome-dependent collapse threshold was introduced.','',
           '## Role comparison','',pd.DataFrame(role_summary).to_markdown(index=False),'',
           '## Domain 1→7 slope comparison','',pd.DataFrame(domain_summary).to_markdown(index=False),'',
           '## Benign coverage stability','',pd.DataFrame(coverage).to_markdown(index=False),'']
    (a.output_dir/'ADJUDICATION_RELATIVE_AUDIT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(verdict,indent=2,sort_keys=True))

if __name__=='__main__': main()
