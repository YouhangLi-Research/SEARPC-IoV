#!/usr/bin/env python3
"""Run the frozen external TWSL baseline on the conditional trust event stream."""

from __future__ import annotations

import argparse
from bisect import bisect_left, bisect_right
from collections import defaultdict, deque
import csv
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import random
from statistics import mean, stdev
import sys


ROOT = Path(__file__).resolve().parent
EXPERIMENT_ROOT = ROOT.parents[1]
HANDOFF_ROOT = EXPERIMENT_ROOT
TWSL_ROOT = EXPERIMENT_ROOT / "baselines" / "TWSL_VeReMi_Adapted_Baseline"
sys.path.insert(0, str(TWSL_ROOT / "src"))

from twsl_baseline.core import (  # noqa: E402
    combine_local_and_recommended,
    interaction_frequency,
    local_opinion,
    opinion_weight,
    paper_weighted_event_count,
    weighted_opinion_from_rows,
)
from twsl_baseline.io import load_config  # noqa: E402
from twsl_baseline.models import Opinion, TrajectoryPoint, TWSLConfig  # noqa: E402
from twsl_baseline.trajectory import trajectory_similarity  # noqa: E402
from twsl_baseline.veremi import iter_veremi_receiver_directory  # noqa: E402


OUTPUT_DIR = EXPERIMENT_ROOT / "results" / "recomputed" / "twsl_external_baseline"
PROTOCOL = EXPERIMENT_ROOT / "protocols" / "frozen" / "DURAC_TWSL_EXTERNAL_BASELINE_PROTOCOL.md"
PREDICTIONS = EXPERIMENT_ROOT / "data" / "derived" / "SEARPC_holdout_holdout_predictions.csv"
DURAC_RAW = EXPERIMENT_ROOT / "results" / "rq2" / "seed20" / "RQ2_seed20_uniform_raw.csv"
DATA_ROOT = Path(__import__("os").environ.get("SEARPC_TWSL_RAW_ROOT", EXPERIMENT_ROOT / "data" / "external" / "twsl_phase13_raw"))
INNER_ROOT = Path(__import__("os").environ.get("SEARPC_TWSL_INNER_ROOT", EXPERIMENT_ROOT / "data" / "external" / "twsl_official_nested"))
OUTER_ROOT = Path(__import__("os").environ.get("SEARPC_TWSL_OUTER_ROOT", EXPERIMENT_ROOT / "data" / "external" / "twsl_official_archives"))

SEEDS = (260825, 260826, 260827, 260828, 260829)
OVERLAPS = (0.0, 0.5, 1.0)
COMMUNICATION_QUALITIES = (0.1, 0.2, 0.3, 0.4)
PRIMARY_QUALITY = 0.2
SAMPLE_STRIDE = 8
RECOMMENDERS = 9
OPINION_NOISE = 0.15
OPINION_ATTACK_PROBABILITY = 0.80
ADJUDICATION_DELAY = 50
TRUST_THRESHOLD = 0.5
TRAJECTORY_WINDOW_SECONDS = 900.0
TRAJECTORY_GRID_SECONDS = 45.0

ATTACKS = {
    "dataReplay": {
        "raw": DATA_ROOT / "dataReplay" / "urban_2_dataReplay",
        "outer": OUTER_ROOT / "InTAS_urban_2_dataReplay.zip",
        "inner": (
            INNER_ROOT
            / "InTAS_urban_2_dataReplay"
            / "Train"
            / "InTAS_urban_2_dataReplay.zip"
        ),
        "outer_md5": "3f3d752b4169475ebc5cb17fd8fa59cd",
        "outer_sha256": "9984cd0cfa32d31f607788a2a1c53c72970c6786563c785cce9b989bb7ce7777",
        "inner_md5": "3ad535432d81b1e3913ee19e6cd26d67",
        "inner_sha256": "2e46d7231012cdd2bc45cc003727696c343952e3006ee02e55913cca4d6d3b47",
    },
    "timeDelayAttack": {
        "raw": DATA_ROOT / "timeDelayAttack" / "urban_2_timeDelayAttack",
        "outer": OUTER_ROOT / "InTAS_urban_2_timeDelayAttack.zip",
        "inner": (
            INNER_ROOT
            / "InTAS_urban_2_timeDelayAttack"
            / "Train"
            / "InTAS_urban_2_timeDelayAttack.zip"
        ),
        "outer_md5": "c5fa8415f36807639e52ddcc5f473878",
        "outer_sha256": "84053356ee7f1b2057728da0679af5e3d2f353abf27ce548c33967da543b3a3d",
        "inner_md5": "d67e1db0989aeab1dbb3cc5c8f3e1d88",
        "inner_sha256": "f96649235e8efe72ee2d2cdf4234dbdae819275eb7665d4c6dfd56144b6f6c1c",
    },
}

PROFILES = {
    "table_ii_literal": TWSL_ROOT / "configs" / "veremi_table_ii_literal.json",
    "text_constraint_consistent": (
        TWSL_ROOT / "configs" / "veremi_text_constraint_consistent.json"
    ),
}


@dataclass(frozen=True)
class Event:
    receiver_id: str
    provider_id: str
    receive_time: float
    attacker: int
    contextual_probability: float
    contextual_uncertainty: float


def _digest(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def _write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty table {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _prediction_rows(attack: str):
    with PREDICTIONS.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["attack"] == attack:
                yield row


class TrajectoryIndex:
    def __init__(self, points: dict[str, dict[float, TrajectoryPoint]]):
        self._times: dict[str, tuple[float, ...]] = {}
        self._points: dict[str, tuple[TrajectoryPoint, ...]] = {}
        for identity, indexed in points.items():
            ordered = tuple(indexed[key] for key in sorted(indexed))
            self._times[identity] = tuple(point.timestamp for point in ordered)
            self._points[identity] = ordered
        self._segments: dict[tuple[str, float], tuple[TrajectoryPoint, ...]] = {}
        self._similarities: dict[tuple[str, str, float, str], float] = {}
        self.segment_requests = 0
        self.segment_cache_hits = 0
        self.similarity_requests = 0
        self.similarity_cache_hits = 0

    @property
    def identities(self) -> tuple[str, ...]:
        return tuple(sorted(self._points))

    @staticmethod
    def _grid_index(timestamp: float) -> int:
        return math.floor(timestamp / TRAJECTORY_GRID_SECONDS)

    def segment(self, identity: str, timestamp: float) -> tuple[TrajectoryPoint, ...]:
        self.segment_requests += 1
        causal_end = round(timestamp, 9)
        key = (identity, causal_end)
        cached = self._segments.get(key)
        if cached is not None:
            self.segment_cache_hits += 1
            return cached
        end = timestamp
        start = end - TRAJECTORY_WINDOW_SECONDS
        times = self._times.get(identity, ())
        left = bisect_left(times, start)
        right = bisect_right(times, end)
        raw = self._points.get(identity, ())[left:right]
        by_grid: dict[int, TrajectoryPoint] = {}
        for point in raw:
            by_grid[self._grid_index(point.timestamp)] = point
        segment = tuple(by_grid[index] for index in sorted(by_grid))
        if len(self._segments) >= 250_000:
            self._segments.clear()
        self._segments[key] = segment
        return segment

    def has_segment(self, identity: str, timestamp: float) -> bool:
        return bool(self.segment(identity, timestamp))

    def similarity(
        self,
        first: str,
        second: str,
        timestamp: float,
        config: TWSLConfig,
    ) -> float:
        self.similarity_requests += 1
        ordered = tuple(sorted((first, second)))
        causal_end = round(timestamp, 9)
        key = (ordered[0], ordered[1], causal_end, config.profile_name)
        cached = self._similarities.get(key)
        if cached is not None:
            self.similarity_cache_hits += 1
            return cached
        first_segment = self.segment(first, timestamp)
        second_segment = self.segment(second, timestamp)
        if not first_segment or not second_segment:
            raise ValueError(
                f"missing synchronized trajectory for {first}->{second} at {timestamp}"
            )
        value = trajectory_similarity(first_segment, second_segment, config)
        if len(self._similarities) >= 250_000:
            self._similarities.clear()
        self._similarities[key] = value
        return value


def _load_attack(attack: str) -> tuple[list[Event], tuple[str, ...], frozenset[int], TrajectoryIndex, dict]:
    definition = ATTACKS[attack]
    predictions = _prediction_rows(attack)
    points: dict[str, dict[float, TrajectoryPoint]] = defaultdict(dict)
    events: list[Event] = []
    identities: set[str] = set()
    attackers: set[str] = set()
    messages = 0
    for index, (message, prediction) in enumerate(
        zip(iter_veremi_receiver_directory(definition["raw"]), predictions)
    ):
        if int(prediction["holdout_row"]) != index:
            raise ValueError(f"{attack}: Phase 13 row mismatch at {index}")
        if int(prediction["attacker"]) != message.attacker:
            raise ValueError(f"{attack}: label mismatch at {index}")
        identities.add(message.provider_id)
        if message.attacker:
            attackers.add(message.provider_id)
        points[message.provider_id].setdefault(
            message.sender_point.timestamp, message.sender_point
        )
        points[message.receiver_id].setdefault(
            message.receiver_point.timestamp, message.receiver_point
        )
        if index % SAMPLE_STRIDE == 0:
            events.append(
                Event(
                    receiver_id=message.receiver_id,
                    provider_id=message.provider_id,
                    receive_time=message.receive_time,
                    attacker=message.attacker,
                    contextual_probability=float(prediction["contextual_probability"]),
                    contextual_uncertainty=float(prediction["contextual_uncertainty"]),
                )
            )
        messages += 1
    try:
        next(predictions)
        raise ValueError(f"{attack}: predictions remain after {messages} raw messages")
    except StopIteration:
        pass
    if len(events) != 36_382:
        raise ValueError(f"{attack}: expected 36,382 sampled events, got {len(events)}")
    ordered = tuple(sorted(identities))
    identity_index = {identity: index for index, identity in enumerate(ordered)}
    attacker_indices = frozenset(identity_index[item] for item in attackers)
    trajectory = TrajectoryIndex(points)
    audit = {
        "attack": attack,
        "raw_messages": messages,
        "sampled_events": len(events),
        "provider_identities": len(ordered),
        "receiver_or_provider_trajectory_identities": len(trajectory.identities),
        "data_attackers": len(attacker_indices),
        "trajectory_points_after_timestamp_deduplication": sum(
            len(items) for items in points.values()
        ),
    }
    return events, ordered, attacker_indices, trajectory, audit


def _select_opinion_attackers(
    data_attackers: frozenset[int], identities: int, overlap: float, seed: int
) -> frozenset[int]:
    rng = random.Random(seed * 1009 + int(round(overlap * 100)))
    count = len(data_attackers)
    overlap_count = round(count * overlap)
    shared = set(rng.sample(sorted(data_attackers), overlap_count))
    honest_data = sorted(set(range(identities)) - set(data_attackers))
    opinion_only = set(rng.sample(honest_data, count - overlap_count))
    return frozenset(shared | opinion_only)


def _active(event_index: int, total: int) -> bool:
    position = event_index / total
    return 0.15 <= position < 0.45 or 0.55 <= position < 0.85


def _sample_active_recommenders(
    rng: random.Random,
    provider: int,
    receiver_id: str,
    identities: tuple[str, ...],
    trajectory: TrajectoryIndex,
    timestamp: float,
) -> tuple[int, ...]:
    selected: set[int] = set()
    attempts = 0
    while len(selected) < RECOMMENDERS:
        attempts += 1
        if attempts > len(identities) * 5:
            active = [
                index
                for index, identity in enumerate(identities)
                if index != provider
                and identity != receiver_id
                and trajectory.has_segment(identity, timestamp)
            ]
            if len(active) <= RECOMMENDERS:
                return tuple(active)
            remaining = sorted(set(active) - selected)
            selected.update(rng.sample(remaining, RECOMMENDERS - len(selected)))
            break
        candidate = rng.randrange(len(identities))
        identity = identities[candidate]
        if candidate == provider or identity == receiver_id or candidate in selected:
            continue
        if trajectory.has_segment(identity, timestamp):
            selected.add(candidate)
    return tuple(sorted(selected))


def _counts(history: dict[tuple[int, int], list[int]], requestor: int, provider: int):
    return history.get((requestor, provider), [0, 0])


def _mean_raw_count(
    provider_counts: dict[int, dict[int, int]], requestor: int
) -> float:
    counts = provider_counts.get(requestor, {})
    return sum(counts.values()) / len(counts) if counts else 0.0


def _profile_weight(
    history: dict[tuple[int, int], list[int]],
    provider_counts: dict[int, dict[int, int]],
    requestor: int,
    provider: int,
    similarity: float,
    config: TWSLConfig,
) -> float:
    positive, negative = _counts(history, requestor, provider)
    weighted = paper_weighted_event_count(positive, 0, negative, 0, config)
    frequency = interaction_frequency(weighted, _mean_raw_count(provider_counts, requestor))
    return opinion_weight(frequency, similarity, config)


def _metric_template() -> dict[str, float]:
    return {
        "tp": 0,
        "fn": 0,
        "fp": 0,
        "tn": 0,
        "malicious_trusted": 0,
        "malicious_events": 0,
        "benign_restricted": 0,
        "benign_events": 0,
        "malicious_reputation_sum": 0.0,
        "benign_reputation_sum": 0.0,
    }


def _finish_metrics(accumulator: dict[str, float]) -> dict[str, float]:
    tp, fn, fp, tn = (accumulator[key] for key in ("tp", "fn", "fp", "tn"))
    recall = tp / (tp + fn) if tp + fn else math.nan
    fpr = fp / (fp + tn) if fp + tn else math.nan
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_precision = tn / (tn + fn) if tn + fn else 0.0
    benign_recall = tn / (tn + fp) if tn + fp else 0.0
    benign_f1 = (
        2 * benign_precision * benign_recall / (benign_precision + benign_recall)
        if benign_precision + benign_recall
        else 0.0
    )
    return {
        "malicious_provider_trusted_rate": accumulator["malicious_trusted"]
        / accumulator["malicious_events"],
        "benign_provider_false_restriction_rate": accumulator["benign_restricted"]
        / accumulator["benign_events"],
        "event_recall": recall,
        "event_fpr": fpr,
        "event_f1": f1,
        "event_macro_f1": (f1 + benign_f1) / 2.0,
        "malicious_event_mean_reputation": accumulator["malicious_reputation_sum"]
        / accumulator["malicious_events"],
        "benign_event_mean_reputation": accumulator["benign_reputation_sum"]
        / accumulator["benign_events"],
    }


def _run_cell(
    attack: str,
    events: list[Event],
    identities: tuple[str, ...],
    data_attackers: frozenset[int],
    trajectory: TrajectoryIndex,
    overlap: float,
    seed: int,
    configs: dict[str, TWSLConfig],
) -> list[dict]:
    identity_index = {identity: index for index, identity in enumerate(identities)}
    opinion_attackers = _select_opinion_attackers(
        data_attackers, len(identities), overlap, seed
    )
    rng = random.Random(seed * 1_000_003 + int(overlap * 1000))
    local_history: dict[tuple[str, str], list[int]] = {}
    recommendation_history: dict[tuple[int, int], list[int]] = {}
    recommendation_provider_counts: dict[int, dict[int, int]] = {}
    pending: deque[tuple[int, str, str, int]] = deque()
    accumulators = {
        (profile, quality): _metric_template()
        for profile in configs
        for quality in COMMUNICATION_QUALITIES
    }
    influence = {
        profile: {"adversarial": 0.0, "total": 0.0}
        for profile in configs
    }

    for event_index, event in enumerate(events):
        while pending and pending[0][0] <= event_index:
            _, receiver, provider_identity, truth = pending.popleft()
            counts = local_history.setdefault((receiver, provider_identity), [0, 0])
            counts[0 if truth else 1] += 1

        provider = identity_index[event.provider_id]
        truth = 1 - event.attacker
        active = _active(event_index, len(events))
        recommenders = _sample_active_recommenders(
            rng,
            provider,
            event.receiver_id,
            identities,
            trajectory,
            event.receive_time,
        )
        opinions: list[float] = []
        inverted: list[bool] = []
        similarities: list[float] = []
        for recommender in recommenders:
            base = float(truth)
            was_inverted = False
            if (
                recommender in opinion_attackers
                and active
                and rng.random() < OPINION_ATTACK_PROBABILITY
            ):
                base = 1.0 - truth
                was_inverted = True
            opinions.append(min(1.0, max(0.0, rng.gauss(base, OPINION_NOISE))))
            inverted.append(was_inverted)
            similarities.append(
                trajectory.similarity(
                    identities[recommender],
                    event.provider_id,
                    event.receive_time,
                    configs["table_ii_literal"],
                )
            )

        weights: dict[str, list[float]] = {}
        for profile, config in configs.items():
            profile_weights = [
                _profile_weight(
                    recommendation_history,
                    recommendation_provider_counts,
                    recommender,
                    provider,
                    similarity,
                    config,
                )
                for recommender, similarity in zip(recommenders, similarities)
            ]
            weights[profile] = profile_weights
            if active:
                influence[profile]["adversarial"] += sum(
                    weight for weight, flag in zip(profile_weights, inverted) if flag
                )
                influence[profile]["total"] += sum(profile_weights)

        local_positive, local_negative = local_history.get(
            (event.receiver_id, event.provider_id), [0, 0]
        )
        for profile, config in configs.items():
            for quality in COMMUNICATION_QUALITIES:
                local = local_opinion(
                    local_positive, local_negative, quality, config.gamma
                )
                rows = [
                    (
                        Opinion(
                            quality * opinion,
                            quality * (1.0 - opinion),
                            1.0 - quality,
                            config.gamma,
                        ),
                        weight,
                    )
                    for opinion, weight in zip(opinions, weights[profile])
                ]
                recommended = weighted_opinion_from_rows(rows, config.gamma)
                final = combine_local_and_recommended(local, recommended)
                reputation = final.expectation
                predicted_attack = reputation < TRUST_THRESHOLD
                accumulator = accumulators[(profile, quality)]
                if event.attacker:
                    accumulator["malicious_events"] += 1
                    accumulator["malicious_reputation_sum"] += reputation
                    accumulator["malicious_trusted"] += int(not predicted_attack)
                    accumulator["tp"] += int(predicted_attack)
                    accumulator["fn"] += int(not predicted_attack)
                else:
                    accumulator["benign_events"] += 1
                    accumulator["benign_reputation_sum"] += reputation
                    accumulator["benign_restricted"] += int(predicted_attack)
                    accumulator["fp"] += int(predicted_attack)
                    accumulator["tn"] += int(not predicted_attack)

        for recommender, opinion in zip(recommenders, opinions):
            counts = recommendation_history.setdefault((recommender, provider), [0, 0])
            counts[0 if opinion >= TRUST_THRESHOLD else 1] += 1
            provider_counts = recommendation_provider_counts.setdefault(recommender, {})
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

        pending.append(
            (
                event_index + ADJUDICATION_DELAY,
                event.receiver_id,
                event.provider_id,
                truth,
            )
        )

    rows = []
    for profile in configs:
        total_weight = influence[profile]["total"]
        for quality in COMMUNICATION_QUALITIES:
            rows.append(
                {
                    "attack": attack,
                    "overlap": overlap,
                    "seed": seed,
                    "profile": profile,
                    "communication_quality": quality,
                    "events": len(events),
                    "provider_identities": len(identities),
                    "data_attackers": len(data_attackers),
                    "opinion_attackers": len(opinion_attackers),
                    "malicious_recommendation_effective_weight_share": (
                        influence[profile]["adversarial"] / total_weight
                        if total_weight
                        else math.nan
                    ),
                    **_finish_metrics(accumulators[(profile, quality)]),
                }
            )
    return rows


def _summarize(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[key] for key in keys)].append(row)
    excluded = set(keys) | {
        "seed",
        "events",
        "provider_identities",
        "data_attackers",
        "opinion_attackers",
    }
    metrics = [key for key in rows[0] if key not in excluded]
    output = []
    t_95_n5 = 2.7764451051977987
    for group, members in sorted(groups.items()):
        item = {key: value for key, value in zip(keys, group)}
        item["repeats"] = len(members)
        for metric in metrics:
            values = [float(member[metric]) for member in members]
            center = mean(values)
            spread = stdev(values) if len(values) > 1 else 0.0
            half = t_95_n5 * spread / math.sqrt(len(values)) if len(values) == 5 else math.nan
            item[f"{metric}_mean"] = center
            item[f"{metric}_sd"] = spread
            item[f"{metric}_ci95_low"] = center - half
            item[f"{metric}_ci95_high"] = center + half
        output.append(item)
    return output


def _primary_comparison(twsl_rows: list[dict]) -> tuple[list[dict], list[dict]]:
    twsl = {
        (row["attack"], float(row["overlap"]), int(row["seed"])): row
        for row in twsl_rows
        if row["profile"] == "table_ii_literal"
        and float(row["communication_quality"]) == PRIMARY_QUALITY
    }
    durac = {}
    with DURAC_RAW.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            if row["variant"] == "dual_role_three_state":
                durac[(row["attack"], float(row["overlap"]), int(row["seed"]))] = row
    raw = []
    mapping = {
        "malicious_provider_trusted_rate": "data_malicious_trusted_rate",
        "benign_provider_false_restriction_rate": "data_honest_denied_rate",
        "event_recall": "event_recall",
        "event_fpr": "event_fpr",
        "event_f1": "event_f1",
        "event_macro_f1": "event_macro_f1",
    }
    for key in sorted(twsl):
        if key not in durac:
            raise ValueError(f"missing paired DURAC row {key}")
        item = {"attack": key[0], "overlap": key[1], "seed": key[2]}
        for twsl_metric, durac_metric in mapping.items():
            twsl_value = float(twsl[key][twsl_metric])
            durac_value = float(durac[key][durac_metric])
            item[f"twsl_{twsl_metric}"] = twsl_value
            item[f"durac_{twsl_metric}"] = durac_value
            item[f"durac_minus_twsl_{twsl_metric}"] = durac_value - twsl_value
        raw.append(item)
    summary = _summarize(raw, ("attack", "overlap"))
    return raw, summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attacks", nargs="*", choices=tuple(ATTACKS), default=tuple(ATTACKS))
    parser.add_argument("--smoke-events", type=int, default=0)
    args = parser.parse_args()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    configs = {name: load_config(path) for name, path in PROFILES.items()}
    if any(config.evaluation_protocol != "veremi_adapted" for config in configs.values()):
        raise ValueError("formal TWSL profiles must be labeled veremi_adapted")

    integrity = []
    for attack in args.attacks:
        definition = ATTACKS[attack]
        row = {
            "attack": attack,
            "outer_md5": _digest(definition["outer"], "md5"),
            "outer_sha256": _digest(definition["outer"]),
            "inner_md5": _digest(definition["inner"], "md5"),
            "inner_sha256": _digest(definition["inner"]),
        }
        row["pass"] = int(
            row["outer_md5"] == definition["outer_md5"]
            and row["outer_sha256"] == definition["outer_sha256"]
            and row["inner_md5"] == definition["inner_md5"]
            and row["inner_sha256"] == definition["inner_sha256"]
        )
        if not row["pass"]:
            raise ValueError(f"official archive integrity failed for {attack}")
        integrity.append(row)

    all_rows: list[dict] = []
    trajectory_audits: list[dict] = []
    for attack in args.attacks:
        print(f"[load and align {attack}]", flush=True)
        events, identities, data_attackers, trajectory, audit = _load_attack(attack)
        if args.smoke_events:
            events = events[: args.smoke_events]
        for overlap in OVERLAPS:
            for seed in SEEDS:
                print(
                    f"[TWSL {attack} overlap={overlap:.1f} seed={seed} events={len(events)}]",
                    flush=True,
                )
                all_rows.extend(
                    _run_cell(
                        attack,
                        events,
                        identities,
                        data_attackers,
                        trajectory,
                        overlap,
                        seed,
                        configs,
                    )
                )
        audit.update(
            {
                "segment_requests": trajectory.segment_requests,
                "segment_cache_hits": trajectory.segment_cache_hits,
                "similarity_requests": trajectory.similarity_requests,
                "similarity_cache_hits": trajectory.similarity_cache_hits,
                "segment_cache_entries": len(trajectory._segments),
                "similarity_cache_entries": len(trajectory._similarities),
            }
        )
        trajectory_audits.append(audit)

    suffix = "_smoke" if args.smoke_events else ""
    raw_path = OUTPUT_DIR / f"DURAC_twsl_raw{suffix}.csv"
    summary_path = OUTPUT_DIR / f"DURAC_twsl_summary{suffix}.csv"
    integrity_path = OUTPUT_DIR / f"DURAC_twsl_integrity{suffix}.csv"
    trajectory_path = OUTPUT_DIR / f"DURAC_twsl_trajectory_audit{suffix}.csv"
    _write_csv(raw_path, all_rows)
    _write_csv(summary_path, _summarize(all_rows, ("attack", "overlap", "profile", "communication_quality")))
    _write_csv(integrity_path, integrity)
    _write_csv(trajectory_path, trajectory_audits)

    outputs = [raw_path, summary_path, integrity_path, trajectory_path]
    if not args.smoke_events and set(args.attacks) == set(ATTACKS):
        comparison_raw, comparison_summary = _primary_comparison(all_rows)
        comparison_raw_path = OUTPUT_DIR / "DURAC_twsl_primary_comparison_raw.csv"
        comparison_summary_path = OUTPUT_DIR / "DURAC_twsl_primary_comparison_summary.csv"
        _write_csv(comparison_raw_path, comparison_raw)
        _write_csv(comparison_summary_path, comparison_summary)
        outputs.extend([comparison_raw_path, comparison_summary_path])

        stop_rows = [
            {
                "archive_integrity_pass": int(all(row["pass"] for row in integrity)),
                "phase13_alignment_and_accounting_pass": int(
                    all(row["sampled_events"] == 36_382 for row in trajectory_audits)
                ),
                "all_primary_cells_present": int(
                    len(
                        [
                            row
                            for row in all_rows
                            if row["profile"] == "table_ii_literal"
                            and row["communication_quality"] == PRIMARY_QUALITY
                        ]
                    )
                    == 30
                ),
                "all_sensitivity_cells_present": int(len(all_rows) == 240),
                "finite_results_pass": int(
                    all(
                        math.isfinite(float(value))
                        for row in all_rows
                        for key, value in row.items()
                        if key
                        not in {
                            "attack",
                            "profile",
                        }
                    )
                ),
                "publication_label": "TWSL adapted to the VeReMi evaluation protocol (independent reimplementation)",
            }
        ]
        stop_path = OUTPUT_DIR / "DURAC_twsl_stop_lines.csv"
        _write_csv(stop_path, stop_rows)
        outputs.append(stop_path)

        manifest = {
            "protocol_status": "frozen before TWSL result computation",
            "publication_label": stop_rows[0]["publication_label"],
            "official_author_code": False,
            "twsl_version": "2.0.0",
            "source_doi": "10.1109/JIOT.2018.2875542",
            "dataset_doi": "10.5281/zenodo.19665762",
            "protocol_sha256": _digest(PROTOCOL),
            "runner_sha256": _digest(Path(__file__)),
            "twsl_core_sha256": _digest(TWSL_ROOT / "src" / "twsl_baseline" / "core.py"),
            "twsl_trajectory_sha256": _digest(TWSL_ROOT / "src" / "twsl_baseline" / "trajectory.py"),
            "twsl_veremi_adapter_sha256": _digest(TWSL_ROOT / "src" / "twsl_baseline" / "veremi.py"),
            "phase13_predictions_sha256": _digest(PREDICTIONS),
            "phase13_durac_raw_sha256": _digest(DURAC_RAW),
            "profiles": {name: {"path": str(path), "sha256": _digest(path)} for name, path in PROFILES.items()},
            "seeds": SEEDS,
            "overlaps": OVERLAPS,
            "communication_qualities": COMMUNICATION_QUALITIES,
            "primary_communication_quality": PRIMARY_QUALITY,
            "sample_stride": SAMPLE_STRIDE,
            "recommenders": RECOMMENDERS,
            "adjudication_delay_events": ADJUDICATION_DELAY,
            "trajectory_window_seconds": TRAJECTORY_WINDOW_SECONDS,
            "trajectory_grid_seconds": TRAJECTORY_GRID_SECONDS,
            "outputs": {path.name: _digest(path) for path in outputs},
        }
        manifest_path = OUTPUT_DIR / "DURAC_twsl_manifest.json"
        with manifest_path.open("w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2, sort_keys=True)
            handle.write("\n")

    print(f"[wrote {len(all_rows)} rows to {OUTPUT_DIR}]", flush=True)


if __name__ == "__main__":
    main()
