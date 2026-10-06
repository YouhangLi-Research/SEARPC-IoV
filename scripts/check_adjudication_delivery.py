#!/usr/bin/env python3
"""Check delayed adjudication consumption in the released vehicle runners.

These short, controlled streams check execution semantics. They are separate
from the dataset-level authorization and aggregation performance measurements.
"""
from __future__ import annotations

import argparse
from collections import deque
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in reversed((ROOT / 'artifact/code/participation_control', ROOT / 'artifact/code/scoped_evidence',
                      ROOT / 'artifact/code/observable_selection', ROOT / 'artifact/code/frozen_searpc')):
    sys.path.insert(0, str(path))

import numpy as np
import run_holdout_authorization as role
import run_durac_domain_cap_2x2 as domain
from adjudication import perturb_binary_truth

ERRORS = (0.0, 0.05, 0.10)
DELAYS = (0, 10, 30)
EVENTS = 96
SEED = 260825


class ObservedTrace:
    def __init__(self, rows, clock):
        self.rows, self.clock = rows, clock

    def __len__(self):
        return len(self.rows)

    def __iter__(self):
        for index, row in enumerate(self.rows):
            self.clock['event'] = index
            yield row
        self.clock['closed'] = True


def check_cell(layer, attack, error, delay):
    module = role if layer == 'role' else domain
    clock = {'event': -1, 'closed': False}
    counters = {'online_deliveries': 0, 'early_deliveries': 0,
                'post_stream_flush': 0, 'perturbed_records': 0,
                'determinism_checks': 0}
    original_queue = module.deque
    original_perturb = module.perturb_binary_truth

    class CheckedQueue(deque):
        def popleft(self):
            item = super().popleft()
            due = item[0]
            if clock['closed']:
                counters['post_stream_flush'] += 1
            else:
                counters['online_deliveries'] += 1
                if due > clock['event']:
                    counters['early_deliveries'] += 1
                    raise AssertionError('adjudication consumed before delivery')
            return item

    def checked_perturb(truth, **kwargs):
        value = original_perturb(truth, **kwargs)
        assert value == original_perturb(truth, **kwargs)
        assert value in (0.0, 1.0)
        if error == 0:
            assert value == truth
        counters['determinism_checks'] += 1
        counters['perturbed_records'] += int(value != truth)
        return value

    module.deque = CheckedQueue
    module.perturb_binary_truth = checked_perturb
    try:
        attackers = frozenset(i for i in range(EVENTS) if i % 4 == 0)
        if layer == 'role':
            rows = [(i, int(i in attackers), 0.85 if i in attackers else 0.15, 0.02)
                    for i in range(EVENTS)]
            result = role.run_cell(attack, ObservedTrace(rows, clock), attackers,
                                   [i % 6 for i in range(EVENTS)],
                                   0.5, SEED, adjudication_delay=delay,
                                   adjudication_error=error)
            assert len(result) == 3
            cap_violations = 0
        else:
            rows = [(int(i in attackers), 0.85 if i in attackers else 0.15, 0.02)
                    for i in range(EVENTS)]
            result = domain.run_cell(attack, ObservedTrace(rows, clock),
                                     'concentrated', 7, SEED,
                                     adjudication_delay=delay,
                                     adjudication_error=error)
            assert len(result) == 4
            cap_violations = sum(int(r['cap_bound_violations']) for r in result
                                 if r['domain_cap'])
            assert cap_violations == 0
        assert counters['online_deliveries'] > 0
        assert counters['determinism_checks'] == EVENTS
        return {'layer': layer, 'attack': attack, 'error_rate': error,
                'delay_events': delay, 'events': EVENTS, 'seed': SEED,
                **counters, 'cap_bound_violations': cap_violations, 'passed': True}
    finally:
        module.deque = original_queue
        module.perturb_binary_truth = original_perturb


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(args.output_dir)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = [check_cell(layer, attack, error, delay)
            for layer in ('role', 'domain')
            for attack in ('dataReplay', 'timeDelayAttack')
            for error in ERRORS for delay in DELAYS]
    with (args.output_dir / 'delivery_checks.csv').open('w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    sources = [Path(__file__), Path(role.__file__), Path(domain.__file__)]
    report = {
        'scope': 'Controlled-stream adjudication delivery and perturbation checks',
        'error_rates': list(ERRORS), 'delays_events': list(DELAYS),
        'events_per_case': EVENTS, 'cases': len(rows),
        'passed_cases': sum(r['passed'] for r in rows),
        'early_online_deliveries': sum(r['early_deliveries'] for r in rows),
        'domain_cap_bound_violations': sum(r['cap_bound_violations'] for r in rows),
        'sources_sha256': {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in sources},
    }
    (args.output_dir / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
