#!/usr/bin/env python3
"""Export manuscript tables from result sources and verify publication assets."""
from __future__ import annotations

import argparse
import csv
from hashlib import sha256
import json
from pathlib import Path
import re
from zipfile import ZipFile
import xml.etree.ElementTree as ET

import numpy as np
import pandas as pd
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'artifact/results'
FIGDATA = ROOT / 'figures/experimental/fig5_to_fig11/data'
SOURCES = {}


def read(path):
    path = Path(path)
    SOURCES[path.relative_to(ROOT).as_posix()] = sha256(path.read_bytes()).hexdigest()
    return pd.read_csv(path)


def one(frame, **filters):
    for key, value in filters.items():
        frame = frame[frame[key] == value]
    if len(frame) != 1:
        raise AssertionError(f'Expected one source row for {filters}, found {len(frame)}')
    return frame.iloc[0]


def percent(value, places=3):
    return f'{100*value:.{places}f}%'


def signed(value, places=3):
    return f'{value:+.{places}f}'.replace('-', '−')


def process_launches():
    directory = RESULTS / 'final_reproduction/system-full'
    manifest = json.loads((directory/'SEARPC_process_manifest.json').read_text())
    for item in manifest['outputs'].values():
        if sha256((ROOT/item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise AssertionError(f'Measurement checksum differs: {item["path"]}')
    snapshot = ROOT / manifest['measurement_source']
    if sha256(snapshot.read_bytes()).hexdigest() != manifest['runner_sha256']:
        raise AssertionError('Measurement source checksum differs')
    current = ROOT / 'artifact/code/scoped_evidence/run_process_measurements.py'
    if sha256(current.read_bytes()).hexdigest() != manifest['current_runner_sha256']:
        raise AssertionError('Current process runner checksum differs')
    raw = read(directory/'SEARPC_process_block_level.csv')
    saved = read(directory/'SEARPC_process_per_launch.csv')
    keys = ['process_count', 'payload_bytes', 'method', 'availability', 'repeat']
    if len(raw) != 30000 or raw.duplicated(keys+['block']).any():
        raise AssertionError('Process block accounting differs')
    cells = []
    for key, cell in raw.groupby(keys):
        n = key[0]
        q = 11 if n == 16 else 27
        if (len(cell) != 500 or set(cell.block) != set(range(1, 501))
                or not (cell.committed == 1).all() or not (cell.final_quorum == q).all()
                or not (cell.final_signature_count >= q).all()):
            raise AssertionError(f'Invalid measured cell: {key}')
        row = dict(zip(keys, key))
        row.update(accounted_p95_ms=float(np.quantile(cell.accounted_latency_ms, .95)),
                   mean_total_wire_bytes=float(cell.total_wire_bytes.mean()))
        frozen = one(saved, **dict(zip(keys, key)))
        for column in ('accounted_p95_ms', 'mean_total_wire_bytes'):
            if not np.isclose(row[column], frozen[column], rtol=1e-12, atol=1e-12):
                raise AssertionError(f'Raw-to-launch summary differs: {key}, {column}')
        cells.append(row)
    plotted = read(FIGDATA/'SEARPC_process_per_launch.csv')
    pd.testing.assert_frame_equal(saved, plotted, check_exact=False, rtol=1e-12, atol=1e-12)
    return pd.DataFrame(cells)


def tables():
    result = {}
    intervals = read(RESULTS/'rq1/SEARPC_clustered_method_intervals.csv')
    detection = read(RESULTS/'rq1/SEARPC_catch_metrics.csv')
    rows = []
    for label, method in [('RF', 'random_forest'), ('HGBDT', 'single_hgbdt'),
                          ('CaTCH [8]', 'official_catch'), ('SEARPC', 'durac_ensemble')]:
        if method == 'official_catch':
            r = one(detection, scope='pooled_external_test', method=method)
            rows.append([label, f'{r.macro_f1:.4f}', percent(r.malicious_recall, 2),
                         percent(r.false_positive_rate, 2), 'N/A', 'N/A', 'N/A'])
        else:
            values = [one(intervals, scope='pooled_external_test', method=method, metric=m).estimate
                      for m in ('macro_f1', 'malicious_recall', 'false_positive_rate',
                                'pr_auc', 'brier_score', 'ece_15')]
            rows.append([label, f'{values[0]:.4f}', percent(values[1], 2), percent(values[2], 2),
                         *[f'{value:.4f}' for value in values[3:]]])
    result['XI'] = rows
    rows = []
    for label, attack, scope in [('Data Replay', 'dataReplay', 'attack_external_test'),
                                 ('Time Delay', 'timeDelayAttack', 'attack_external_test'),
                                 ('Pooled', 'all', 'pooled_external_test')]:
        for name, method in [('CaTCH', 'official_catch'), ('SEARPC', 'durac_contextual_calibrated')]:
            r = one(detection, attack=attack, scope=scope, method=method)
            rows.append([label, name, f'{int(r.messages):,}', f'{r.macro_f1:.4f}',
                         percent(r.malicious_recall, 2), percent(r.false_positive_rate, 2)])
    result['XII'] = rows
    uniform = read(RESULTS/'vehicle_role/RQ2_uniform_raw.csv')
    brs = read(RESULTS/'brs_authorization/BRS_authorization_raw.csv')
    conditions = [(a, o) for a in ('dataReplay', 'timeDelayAttack') for o in (0., .5, 1.)]
    rows = []
    for label, variant in [('SEARPC w/o Role Separation', 'single_role_three_state'),
                            ('BRS [9]', 'BRS'), ('SEARPC', 'dual_role_three_state')]:
        values = []
        for attack, overlap in conditions:
            if variant == 'BRS':
                cell = brs[(brs.attack == attack)&(brs.overlap == overlap)&(brs.threshold == .5)]
                values.append(cell.malicious_trusted_rate.mean())
            else:
                cell = uniform[(uniform.attack == attack)&(uniform.overlap == overlap)&(uniform.variant == variant)]
                values.append(cell.data_malicious_trusted_rate.mean())
            if len(cell) != 20:
                raise AssertionError('Role seed accounting differs')
        rows.append([label, *[percent(v) for v in values], percent(max(values)), f'{sum(v == 0 for v in values)}/6'])
    result['XIII'] = rows
    risk = read(FIGDATA/'pareto_risk_budget.csv')
    rows = []
    for label, method in [('BRS [9]', 'BRS'), ('TWSL [3]', 'TWSL'), ('SEARPC', 'SEARPC')]:
        cells = []
        for attack, overlap in conditions:
            if method == 'BRS':
                cell = brs[(brs.attack == attack)&(brs.overlap == overlap)].groupby('threshold').agg(
                    malicious_trusted=('malicious_trusted', 'sum'), coverage=('benign_coverage', 'mean'))
                feasible = cell[cell.malicious_trusted == 0]
                if feasible.empty:
                    cells.append('N/F')
                    continue
                threshold = feasible.coverage.idxmax()
                coverage = feasible.loc[threshold, 'coverage']
            else:
                r = one(risk, attack=attack, overlap=overlap, method=method, risk_budget=0.)
                threshold, coverage = r.selected_threshold, r.max_benign_coverage
            cells.append(f'{percent(coverage, 2)} (θ={threshold:.2f})')
        rows.append([label, *cells])
    result['XIV'] = rows
    cold = read(RESULTS/'vehicle_role/RQ2_cold_summary.csv')
    baseline = [one(cold, attack=a, variant='dual_role_mean_weight') for a in ('dataReplay', 'timeDelayAttack')]
    treatment = [one(cold, attack=a, variant='dual_role_lcb_weight') for a in ('dataReplay', 'timeDelayAttack')]
    key = 'adversarial_effective_weight_share_mean'
    result['XV'] = [
        ['Weighted mean', *[percent(r[key]) for r in baseline], *['Reference']*4],
        ['SEARPC', *[f'{percent(t[key])} (−{100*(1-t[key]/b[key]):.1f}%)' for b, t in zip(baseline, treatment)],
         *[signed(100*(t[column]-b[column])) for b, t in zip(baseline, treatment)
           for column in ('event_macro_f1_mean', 'event_fpr_mean')]]]
    domain = read(RESULTS/'vehicle_domain/RQ3_summary.csv')
    def d(attack, variant, multiplicity=7):
        return one(domain, attack=attack, layout='concentrated', variant=variant, multiplicity=multiplicity)
    rows16, rows17 = [], []
    for label, prefix in [('Posterior mean', 'mean'), ('SEARPC', 'lcb')]:
        row16, errors, windows, f1, fpr = [label], [], [], [], []
        for attack in ('dataReplay', 'timeDelayAttack'):
            no, cap = d(attack, prefix+'_no_cap'), d(attack, prefix+'_cap')
            metric = 'early_adversarial_weight_share_mean'
            sn = (no[metric]-d(attack, prefix+'_no_cap', 1)[metric])/6
            sc = (cap[metric]-d(attack, prefix+'_cap', 1)[metric])/6
            row16.extend([f'{percent(no[metric], 2)}→{percent(cap[metric], 2)}',
                          f'{sn:.6f}→{sc:.6f} ({signed(sc-sn, 6)}; {signed(100*(sc/sn-1), 2)}%)'])
            errors.append(f'{100*no.early_fused_error_rate_mean:.2f}→{percent(cap.early_fused_error_rate_mean, 2)}')
            windows.append(f'{100*no.window_fused_error_rate_mean:.4f}→{percent(cap.window_fused_error_rate_mean, 4)}')
            f1.append(signed(100*(cap.event_macro_f1_mean-no.event_macro_f1_mean)))
            fpr.append(signed(100*(cap.event_fpr_mean-no.event_fpr_mean)))
        rows16.append(row16)
        rows17.append([label, ' / '.join(errors), ' / '.join(windows), ' / '.join(f1)+' pp', ' / '.join(fpr)+' pp'])
    result['XVI'], result['XVII'] = rows16, rows17
    external = read(RESULTS/'vehicle_source_baselines/IDENTITY_MULTIPLICITY_EXTERNAL_summary.csv')
    rows = []
    for label, variant in [('BRS [9]', 'brs_identity_pooling'), ('TWSL [3]', 'twsl_local_identity_pooling'),
                            ('SEARPC', 'lcb_cap')]:
        row = [label]
        for attack in ('dataReplay', 'timeDelayAttack'):
            frame = domain if label == 'SEARPC' else external
            values = [one(frame, attack=attack, layout='concentrated', variant=variant, multiplicity=n)
                      .early_adversarial_weight_share_mean for n in (1, 7)]
            row.extend(['—' if label == 'SEARPC' else percent(values[1], 2), f'{values[1]-values[0]:.3f}'])
        rows.append(row+['Yes' if label == 'SEARPC' else 'No'])
    result['XVIII'] = rows
    yadav = read(RESULTS/'shared7_baseline/yadav_shared7/YADAV_SHARED7_summary.csv')
    brbc = read(RESULTS/'external_baselines/brbc_rq4/BRBC_RQ4_summary.csv')
    rows = []
    for label, frame, method in [('Yadav [5]', yadav, 'yadav_direct_history_shared_audits'),
                                ('BRBC [16]', brbc, 'brbc_eligibility'), ('SEARPC', yadav, 'searpc_shared_audits')]:
        r = one(frame, method=method)
        rows.append([label, percent(r.risk_weighted_exposure), percent(r.actual_handoff_rate),
                     percent(r.expensive_full_path_rate), f'{r.mean_active_pool:.2f}',
                     percent(r.mean_selected_compromised_fraction), f'{r.mean_total_wire_messages:.1f}'])
    result['XIX'] = rows
    canonical = read(RESULTS/'participation_control/rq4_protocol_closed/RQ4_summary.csv')
    bootstrap = read(RESULTS/'participation_control/manuscript_tables/RQ4_PAIRED_TRACE_BOOTSTRAP.csv')
    ci = one(bootstrap, audit_regime='adaptive', baseline='feedback_fixed', target='validator_only', metric='exposure')
    rows = []
    for label, method, delta in [('Static k=13', 'static_k13', '—'),
                                ('SEARPC w/o Same-k Reconfiguration', 'feedback_fixed', 'Reference'),
                                ('SEARPC', 'validator_only', f'{signed(100*ci.paired_mean_difference)} pp '
                                 f'[{signed(100*ci.ci95_low)}, {signed(100*ci.ci95_high)}]')]:
        r = one(canonical, method=method)
        rows.append([label, percent(r.risk_weighted_latent_post_control_exposure),
                     percent(r.latent_post_control_exceedance_rate), percent(r.actual_handoff_rate),
                     f'{percent(r.warning_resampling_rate, 2)} + {percent(r.content_resampling_rate, 2)}',
                     f'{r.mean_total_wire_messages:.2f}', delta])
    result['XX'] = rows
    launch = process_launches()
    rows = []
    for label, method in [('Full set', 'full_set'), ('Fixed k=13', 'fixed_k13'), ('SEARPC', 'searpc_conditioned')]:
        cells = [launch[(launch.process_count == 40)&(launch.method == method)&(launch.availability == a)]
                 for a in ('cached', 'fetch')]
        if any(len(c) != 5 for c in cells):
            raise AssertionError('Five-launch median accounting differs')
        rows.append([label, *[f'{c.accounted_p95_ms.median():.2f}' for c in cells],
                     *[f'{c.mean_total_wire_bytes.median()/1000:.1f}' for c in cells], '2500/2500', '27'])
    result['XXI'] = rows
    return result


def manuscript_tables():
    ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    with ZipFile(ROOT/'paper/SEARPC_manuscript_en.docx') as archive:
        document = ET.fromstring(archive.read('word/document.xml'))
    return [[[''.join(t.text or '' for t in cell.findall('.//w:t', ns))
               for cell in row.findall('w:tc', ns)] for row in table.findall('w:tr', ns)]
            for table in document.findall('.//w:tbl', ns)]


def normalize(value):
    return re.sub(r'\s+', ' ', value.replace('\u00a0', ' ')).strip()


def figures(output):
    index = json.loads((ROOT/'figures/FIGURE_INDEX.json').read_text())
    count = 0
    with ZipFile(ROOT/'paper/SEARPC_manuscript_en.docx') as manuscript:
        for item in index['experimental']:
            path = ROOT/item['image']
            content = path.read_bytes()
            if not content or sha256(content).hexdigest() != item['sha256']:
                raise AssertionError(f'Figure asset checksum differs: {path.name}')
            if manuscript.read(item['word_media']) != content:
                raise AssertionError(f'Figure differs from manuscript: {path.name}')
            with Image.open(path) as image:
                image.verify()
            if not (ROOT/item['vector']).read_bytes().startswith(b'%PDF-'):
                raise AssertionError(f'Figure PDF is invalid: {item["vector"]}')
            if output is not None:
                if item['figure'] == 4:
                    generated = output/'figure4'/path.name
                else:
                    relative = path.relative_to(ROOT/'figures/experimental/fig5_to_fig11/outputs')
                    generated = output/'figures5-11'/relative
                with Image.open(path) as reference, Image.open(generated) as observed:
                    if not np.array_equal(np.asarray(reference.convert('RGBA')), np.asarray(observed.convert('RGBA'))):
                        raise AssertionError(f'Generated figure pixels differ: {generated.name}')
                if not generated.with_suffix('.pdf').read_bytes().startswith(b'%PDF-'):
                    raise AssertionError(f'Generated figure PDF is invalid: {generated.name}')
            count += 1
    for item in index['framework']:
        for key, hash_key in [('image', 'png_sha256'), ('vector', 'svg_sha256'), ('pdf', 'pdf_sha256')]:
            path = ROOT/item[key]
            if sha256(path.read_bytes()).hexdigest() != item[hash_key]:
                raise AssertionError(f'Framework checksum differs: {path.name}')
    return {'experimental_panels': count, 'framework_figures': 3,
            'manuscript_assets': 'PASS', 'generated_panels': 'PASS' if output else 'not requested'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--figure-output', type=Path)
    args = parser.parse_args()
    observed = tables()
    published = manuscript_tables()
    checked = {}
    for number, rows in observed.items():
        candidates = [t for t in published if len(t) == len(rows)+1
                      and t[1] and t[1][0] == rows[0][0] and len(t[1]) == len(rows[0])]
        exact = [t for t in candidates if [[normalize(c) for c in r] for r in t[1:]]
                 == [[normalize(c) for c in r] for r in rows]]
        if len(exact) != 1:
            raise AssertionError(f'Table {number} differs: source={rows}; manuscript={candidates}')
        checked[number] = {'rows': len(rows), 'cells': sum(map(len, rows)), 'status': 'PASS'}
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)
            with (args.output_dir/f'Table_{number}.csv').open('w', newline='', encoding='utf-8') as handle:
                writer = csv.writer(handle)
                writer.writerow(exact[0][0])
                writer.writerows(rows)
    report = {'tables': checked, 'figures': figures(args.figure_output),
              'measured_blocks': 30000, 'communication_bytes_per_KB': 1000,
              'source_files_sha256': SOURCES, 'status': 'PASS'}
    if args.output_dir:
        (args.output_dir/'PAPER_CORRESPONDENCE.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f'Manuscript correspondence: PASS ({len(checked)} tables; {sum(v["cells"] for v in checked.values())} cells; '
          f'{report["figures"]["experimental_panels"]} experimental panels)')


if __name__ == '__main__':
    main()
