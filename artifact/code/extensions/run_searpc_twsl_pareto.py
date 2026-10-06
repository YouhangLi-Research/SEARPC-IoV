#!/usr/bin/env python3
"""Checkpointed frozen-readout Pareto runner for SEARPC and adapted TWSL.

The authorization threshold is the only swept value. Online state-transition
and recommendation-history thresholds remain fixed at their original 0.50.
"""
from __future__ import annotations

import argparse
from collections import deque
import csv
import hashlib
import json
import os
from pathlib import Path
import random
import sys
import time

import numpy as np


SEEDS5 = tuple(range(260825, 260830))
SEEDS20 = tuple(range(260825, 260845))
ATTACKS = ("dataReplay", "timeDelayAttack")
OVERLAPS = (0.0, 0.5, 1.0)
THRESHOLDS = tuple(round(value / 100.0, 2) for value in range(5, 96))
PRIMARY_THRESHOLD = 0.50
INTERNAL_THRESHOLD = 0.50
PREDICTION_SHA256 = "58a93ef9159a7a090654c8b3adc4ffb5eeaabd7f895049e32c4911ec5c82b915"
TRACE_BUNDLE_SHA256 = "09d7fe87141f7467057e1176a09efff0a93167df5aa97b8d5715486c8cb79cc0"


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def atomic_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError("refusing to write empty Pareto rows")
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temporary, path)


def _row(
    method: str,
    seed: int,
    attack: str,
    overlap: float,
    threshold: float,
    benign_total: int,
    benign_trusted: int,
    malicious_total: int,
    malicious_trusted: int,
) -> dict:
    return {
        "seed": seed,
        "attack": attack,
        "overlap": overlap,
        "method": method,
        "threshold": threshold,
        "benign_total": benign_total,
        "benign_trusted": benign_trusted,
        "benign_coverage": benign_trusted / benign_total,
        "malicious_total": malicious_total,
        "malicious_trusted": malicious_trusted,
        "malicious_trusted_rate": malicious_trusted / malicious_total,
    }


def run_searpc_cell(
    legacy_root: Path,
    trace_bundle: Path,
    attack: str,
    overlap: float,
    seed: int,
    thresholds: tuple[float, ...],
) -> list[dict]:
    sys.path.insert(0, str(legacy_root.resolve()))
    import run_dual_role as p11
    import run_holdout_authorization as p12
    import run_conditional_trust as p13

    if p12.TRUST_THRESHOLD != INTERNAL_THRESHOLD:
        raise ValueError("frozen SEARPC internal threshold changed")
    with np.load(trace_bundle) as bundle:
        provider = bundle[f"{attack}__provider_index"].astype(int)
        attacker = bundle[f"{attack}__attacker"].astype(int)
        probability = bundle[f"{attack}__prob"].astype(float)
        uncertainty = bundle[f"{attack}__uncertainty"].astype(float)
        domains = tuple(int(value) for value in bundle[f"{attack}__domains"])
        data_attackers = frozenset(int(value) for value in bundle[f"{attack}__data_attackers"])
    trace = tuple(zip(provider, attacker, probability, uncertainty))
    identities = len(domains)
    opinion_attackers = p11.select_opinion_attackers(data_attackers, identities, overlap, seed)
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    book = p11._ArrayBook(identities, 2)
    states = p12._DynamicStates(2, identities)
    pending: deque = deque()
    threshold_array = np.asarray(thresholds, dtype=float)
    malicious_trusted = np.zeros(len(thresholds), dtype=np.int64)
    benign_trusted = np.zeros(len(thresholds), dtype=np.int64)
    malicious_total = 0
    benign_total = 0

    for event_index, (provider_id, is_attacker, _malicious_probability, message_uncertainty) in enumerate(trace):
        while pending and pending[0][0] <= event_index:
            _, item = pending.popleft()
            p13._apply_dual_pending(book, states, item)

        provider_id = int(provider_id)
        is_attacker = int(is_attacker)
        lower, _ = p12._bounds(book, 0, provider_id)
        eligible = not bool(states.malicious[0, provider_id])
        trusted = np.logical_and(float(lower) >= threshold_array, eligible)
        if is_attacker:
            malicious_total += 1
            malicious_trusted += trusted.astype(np.int64)
        else:
            benign_total += 1
            benign_trusted += trusted.astype(np.int64)

        truth = 1.0 - is_attacker
        recommenders = p11._sample_recommenders(rng, provider_id, identities)
        opinions = np.empty(p11.RECOMMENDERS, dtype=float)
        for position, recommender in enumerate(recommenders):
            base = truth
            if (
                recommender in opinion_attackers
                and p11._active(event_index, len(trace))
                and rng.random() < p11.OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
            opinions[position] = min(1.0, max(0.0, rng.gauss(base, p11.OPINION_NOISE)))
        base_reliability = min(1.0, max(0.0, 1.0 - float(message_uncertainty)))
        pending.append(
            (
                event_index + p11.ADJUDICATION_DELAY,
                (provider_id, truth, base_reliability, recommenders, opinions),
            )
        )

    return [
        _row(
            "SEARPC", seed, attack, overlap, threshold,
            benign_total, int(benign_trusted[index]),
            malicious_total, int(malicious_trusted[index]),
        )
        for index, threshold in enumerate(thresholds)
    ]


def load_twsl_attack(
    legacy_root: Path,
    predictions: Path,
    raw_root: Path,
    attack: str,
):
    sys.path.insert(0, str(legacy_root.resolve()))
    import run_durac_twsl_external_baseline as twsl

    twsl.PREDICTIONS = predictions
    folder = "urban_2_dataReplay" if attack == "dataReplay" else "urban_2_timeDelayAttack"
    twsl.ATTACKS[attack]["raw"] = raw_root / attack / folder
    return twsl, twsl._load_attack(attack)


def run_twsl_cell(
    twsl,
    loaded,
    legacy_root: Path,
    attack: str,
    overlap: float,
    seed: int,
    thresholds: tuple[float, ...],
) -> list[dict]:
    events, identities, data_attackers, trajectory, _audit = loaded
    config = twsl.load_config(twsl.PROFILES["table_ii_literal"])
    identity_index = {identity: index for index, identity in enumerate(identities)}
    opinion_attackers = twsl._select_opinion_attackers(data_attackers, len(identities), overlap, seed)
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    local_history: dict[tuple[str, str], list[int]] = {}
    recommendation_history: dict[tuple[int, int], list[int]] = {}
    recommendation_provider_counts: dict[int, dict[int, int]] = {}
    pending: deque[tuple[int, str, str, int]] = deque()
    threshold_array = np.asarray(thresholds, dtype=float)
    malicious_trusted = np.zeros(len(thresholds), dtype=np.int64)
    benign_trusted = np.zeros(len(thresholds), dtype=np.int64)
    malicious_total = 0
    benign_total = 0

    for event_index, event in enumerate(events):
        while pending and pending[0][0] <= event_index:
            _, receiver, provider_identity, truth = pending.popleft()
            counts = local_history.setdefault((receiver, provider_identity), [0, 0])
            counts[0 if truth else 1] += 1

        provider = identity_index[event.provider_id]
        truth = 1 - event.attacker
        recommenders = twsl._sample_active_recommenders(
            rng, provider, event.receiver_id, identities, trajectory, event.receive_time
        )
        opinions: list[float] = []
        similarities: list[float] = []
        for recommender in recommenders:
            base = float(truth)
            if (
                recommender in opinion_attackers
                and twsl._active(event_index, len(events))
                and rng.random() < twsl.OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
            opinions.append(min(1.0, max(0.0, rng.gauss(base, twsl.OPINION_NOISE))))
            similarities.append(
                trajectory.similarity(
                    identities[recommender], event.provider_id, event.receive_time, config
                )
            )

        weights = [
            twsl._profile_weight(
                recommendation_history,
                recommendation_provider_counts,
                recommender,
                provider,
                similarity,
                config,
            )
            for recommender, similarity in zip(recommenders, similarities)
        ]
        local_positive, local_negative = local_history.get(
            (event.receiver_id, event.provider_id), [0, 0]
        )
        local = twsl.local_opinion(local_positive, local_negative, twsl.PRIMARY_QUALITY, config.gamma)
        opinion_rows = [
            (
                twsl.Opinion(
                    twsl.PRIMARY_QUALITY * opinion,
                    twsl.PRIMARY_QUALITY * (1.0 - opinion),
                    1.0 - twsl.PRIMARY_QUALITY,
                    config.gamma,
                ),
                weight,
            )
            for opinion, weight in zip(opinions, weights)
        ]
        recommended = twsl.weighted_opinion_from_rows(opinion_rows, config.gamma)
        reputation = twsl.combine_local_and_recommended(local, recommended).expectation
        trusted = reputation >= threshold_array
        if event.attacker:
            malicious_total += 1
            malicious_trusted += trusted.astype(np.int64)
        else:
            benign_total += 1
            benign_trusted += trusted.astype(np.int64)

        for recommender, opinion in zip(recommenders, opinions):
            counts = recommendation_history.setdefault((recommender, provider), [0, 0])
            counts[0 if opinion >= INTERNAL_THRESHOLD else 1] += 1
            provider_counts = recommendation_provider_counts.setdefault(recommender, {})
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        pending.append(
            (event_index + twsl.ADJUDICATION_DELAY, event.receiver_id, event.provider_id, truth)
        )

    return [
        _row(
            "TWSL", seed, attack, overlap, threshold,
            benign_total, int(benign_trusted[index]),
            malicious_total, int(malicious_trusted[index]),
        )
        for index, threshold in enumerate(thresholds)
    ]


def checkpoint_name(method: str, attack: str, overlap: float, seed: int) -> str:
    overlap_name = str(overlap).replace(".", "p")
    return f"{method}__{attack}__overlap{overlap_name}__seed{seed}.json"


def validate_checkpoint(path: Path, key: tuple, thresholds: tuple[float, ...], protocol_hash: str) -> bool:
    if not path.exists():
        return False
    payload = json.loads(path.read_text(encoding="utf-8"))
    observed = (payload["method"], payload["attack"], float(payload["overlap"]), int(payload["seed"]))
    if observed != key:
        raise RuntimeError(f"checkpoint key mismatch: {path}")
    if payload.get("protocol_sha256") != protocol_hash:
        raise RuntimeError(f"checkpoint protocol mismatch: {path}")
    if [float(row["threshold"]) for row in payload.get("rows", [])] != list(thresholds):
        raise RuntimeError(f"checkpoint threshold grid mismatch: {path}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--method", choices=("SEARPC", "TWSL"), required=True)
    parser.add_argument("--mode", choices=("original5", "full20"), required=True)
    parser.add_argument("--attack", choices=ATTACKS, required=True)
    parser.add_argument("--legacy-root", type=Path, required=True)
    parser.add_argument("--predictions", type=Path, required=True)
    parser.add_argument("--trace-bundle", type=Path, required=True)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    if digest(args.predictions) != PREDICTION_SHA256:
        raise ValueError("frozen prediction hash mismatch")
    if digest(args.trace_bundle) != TRACE_BUNDLE_SHA256:
        raise ValueError("exact RQ2 trace-bundle hash mismatch")
    protocol_hash = digest(args.protocol)
    seeds = SEEDS5 if args.mode == "original5" else SEEDS20
    args.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoints = args.output_dir / "checkpoints"
    checkpoints.mkdir(exist_ok=True)

    loaded_twsl = None
    twsl = None
    if args.method == "TWSL":
        twsl, loaded_twsl = load_twsl_attack(
            args.legacy_root, args.predictions, args.raw_root, args.attack
        )

    registered = [(args.method, args.attack, overlap, seed) for overlap in OVERLAPS for seed in seeds]
    completed = 0
    for method, attack, overlap, seed in registered:
        checkpoint = checkpoints / checkpoint_name(method, attack, overlap, seed)
        if validate_checkpoint(checkpoint, (method, attack, overlap, seed), THRESHOLDS, protocol_hash):
            completed += 1
            continue
        started = time.time()
        if method == "SEARPC":
            rows = run_searpc_cell(
                args.legacy_root, args.trace_bundle, attack, overlap, seed, THRESHOLDS
            )
        else:
            rows = run_twsl_cell(
                twsl, loaded_twsl, args.legacy_root, attack, overlap, seed, THRESHOLDS
            )
        atomic_json(checkpoint, {
            "method": method,
            "attack": attack,
            "overlap": overlap,
            "seed": seed,
            "elapsed_s": time.time() - started,
            "protocol_sha256": protocol_hash,
            "prediction_sha256": PREDICTION_SHA256,
            "trace_bundle_sha256": TRACE_BUNDLE_SHA256,
            "runner_sha256": digest(Path(__file__)),
            "rows": rows,
        })
        completed += 1
        print(f"completed {method} {attack} {completed}/{len(registered)}", flush=True)

    rows: list[dict] = []
    for key in registered:
        checkpoint = checkpoints / checkpoint_name(*key)
        rows.extend(json.loads(checkpoint.read_text(encoding="utf-8"))["rows"])
    rows.sort(key=lambda item: (item["attack"], item["overlap"], item["seed"], item["threshold"]))
    expected = len(registered) * len(THRESHOLDS)
    if len(rows) != expected:
        raise RuntimeError(f"expected {expected} raw rows, got {len(rows)}")
    raw_name = f"{args.method}_{args.attack}_{args.mode}_pareto_raw.csv"
    atomic_csv(args.output_dir / raw_name, rows)
    manifest = {
        "method": args.method,
        "attack": args.attack,
        "mode": args.mode,
        "seeds": list(seeds),
        "thresholds": list(THRESHOLDS),
        "registered_cells": len(registered),
        "raw_rows": len(rows),
        "protocol_sha256": protocol_hash,
        "prediction_sha256": PREDICTION_SHA256,
        "trace_bundle_sha256": TRACE_BUNDLE_SHA256,
        "runner_sha256": digest(Path(__file__)),
        "raw_sha256": digest(args.output_dir / raw_name),
    }
    atomic_json(args.output_dir / f"{args.method}_{args.attack}_{args.mode}_manifest.json", manifest)
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == "__main__":
    main()
