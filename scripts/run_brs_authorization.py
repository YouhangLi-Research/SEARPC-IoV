#!/usr/bin/env python3
"""Replay the pooled Beta-reputation readout on registered role traces.

Provider outcomes and recommender honesty share one history, as in the
single-role book. Readout thresholds do not change the delivered updates.
"""
from __future__ import annotations

import argparse
from collections import deque
from concurrent.futures import ProcessPoolExecutor
import csv
import hashlib
import json
from pathlib import Path
import random
import sys

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'artifact/code/participation_control'))
sys.path.insert(1, str(ROOT / 'artifact/code/scoped_evidence'))
sys.path.insert(2, str(ROOT / 'artifact/code/frozen_searpc'))
import run_dual_role as role
from run_role_authorization import load_bundle

THRESHOLDS = np.arange(5, 96, dtype=float) / 100


def replay(arguments):
    attack, overlap, seed = arguments
    trace, attackers, domains = load_bundle(ROOT / 'data/derived/rq2_trace_bundle_exact.npz')[attack]
    identities = len(domains)
    opinion_attackers = role.select_opinion_attackers(frozenset(attackers), identities, overlap, seed)
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    book = role._ArrayBook(identities, 1)
    pending = deque()
    trusted = np.zeros((2, len(THRESHOLDS)), dtype=np.int64)
    totals = np.zeros(2, dtype=np.int64)
    for event_index, (provider, attacker, probability, uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            old_provider, truth, reliability, recommenders, opinions = item
            book.update(0, np.asarray([old_provider]), np.asarray([truth]), np.asarray([reliability]))
            book.update(0, recommenders, 1.0 - np.abs(opinions-truth))
        label = int(attacker)
        totals[label] += 1
        trusted[label] += float(book.mean(0, provider)) >= THRESHOLDS
        truth = 1.0-label
        recommenders = role._sample_recommenders(rng, provider, identities)
        opinions = np.empty(role.RECOMMENDERS, dtype=float)
        for position, recommender in enumerate(recommenders):
            base = truth
            if (recommender in opinion_attackers and role._active(event_index, len(trace))
                    and rng.random() < role.OPINION_ATTACK_PROBABILITY):
                base = 1.0-truth
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, role.OPINION_NOISE)))
        pending.append((event_index+role.ADJUDICATION_DELAY,
                        (provider, truth, min(1.0, max(0.0, 1.0-uncertainty)), recommenders, opinions)))
    return [{'attack': attack, 'overlap': overlap, 'seed': seed, 'method': 'BRS',
             'threshold': float(threshold), 'benign_total': int(totals[0]),
             'benign_trusted': int(trusted[0, i]), 'malicious_total': int(totals[1]),
             'malicious_trusted': int(trusted[1, i]),
             'benign_coverage': float(trusted[0, i]/totals[0]),
             'malicious_trusted_rate': float(trusted[1, i]/totals[1])}
            for i, threshold in enumerate(THRESHOLDS)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    jobs = [(attack, overlap, seed) for attack in ('dataReplay', 'timeDelayAttack')
            for overlap in (0.0, 0.5, 1.0) for seed in range(260825, 260845)]
    records = []
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for index, result in enumerate(pool.map(replay, jobs), 1):
            records.extend(result)
            if index % 10 == 0:
                print(f'BRS authorization: {index}/{len(jobs)} paired cells', flush=True)
    raw = pd.DataFrame(records)
    raw.to_csv(args.output_dir/'BRS_authorization_raw.csv', index=False)
    summary = raw.groupby(['attack', 'overlap', 'threshold'], as_index=False).agg(
        seeds=('seed', 'nunique'), benign_coverage=('benign_coverage', 'mean'),
        malicious_trusted_rate=('malicious_trusted_rate', 'mean'),
        malicious_trusted=('malicious_trusted', 'sum'))
    summary.to_csv(args.output_dir/'BRS_authorization_summary.csv', index=False)
    report = {'cells': len(jobs), 'rows': len(records), 'seeds': 20, 'thresholds': 91,
              'update_rule': 'Pooled provider outcomes and recommender honesty; delayed delivery',
              'sources_sha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (Path(__file__), Path(role.__file__),
                                           ROOT/'data/derived/rq2_trace_bundle_exact.npz')}}
    (args.output_dir/'VERIFICATION.json').write_text(json.dumps(report, indent=2)+'\n')
    print(summary[summary.threshold == 0.5].to_string(index=False))


if __name__ == '__main__':
    main()
