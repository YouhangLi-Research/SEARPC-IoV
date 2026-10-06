from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence

from .core import (
    combine_local_and_recommended,
    interaction_frequency,
    local_opinion,
    opinion_weight,
    paper_weighted_event_count,
    recommended_opinion,
)
from .models import (
    Interaction,
    LocalOpinionRecord,
    ReputationRecord,
    TrajectoryPoint,
    TWSLConfig,
)
from .trajectory import trajectory_similarity


def _history_start(snapshot_time: float, config: TWSLConfig) -> float | None:
    if config.history_window_seconds is None:
        return None
    return snapshot_time - config.history_window_seconds


def _in_history(timestamp: float, snapshot_time: float, start: float | None) -> bool:
    return timestamp <= snapshot_time and (start is None or timestamp >= start)


def _missing_similarity(config: TWSLConfig, requestor: str, provider: str) -> float:
    policy = config.missing_trajectory_policy
    if policy == "error":
        raise ValueError(
            f"missing trajectory for pair {requestor!r}->{provider!r}; "
            "supply trajectories or declare a non-paper missing-data policy"
        )
    return {"zero": 0.0, "neutral": 0.5, "identical": 1.0}[policy]


def build_local_opinions(
    interactions: Sequence[Interaction],
    trajectories: Sequence[TrajectoryPoint],
    config: TWSLConfig,
    snapshot_time: float | None = None,
) -> list[LocalOpinionRecord]:
    """Build all observed requestor-provider opinions at one frozen snapshot."""

    if not interactions:
        return []
    if snapshot_time is None:
        snapshot_time = max(item.timestamp for item in interactions)
    start = _history_start(snapshot_time, config)
    history = [
        item
        for item in interactions
        if _in_history(item.timestamp, snapshot_time, start)
    ]
    if not history:
        return []

    pair_events: dict[tuple[str, str], list[Interaction]] = defaultdict(list)
    requestor_pair_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for item in history:
        pair_events[(item.requestor_id, item.provider_id)].append(item)
        requestor_pair_counts[item.requestor_id][item.provider_id] += 1

    mean_raw_counts: dict[str, float] = {}
    for requestor, counts in requestor_pair_counts.items():
        mean_raw_counts[requestor] = sum(counts.values()) / len(counts)

    points_by_vehicle: dict[str, list[TrajectoryPoint]] = defaultdict(list)
    for point in trajectories:
        if _in_history(point.timestamp, snapshot_time, start):
            points_by_vehicle[point.vehicle_id].append(point)
    for points in points_by_vehicle.values():
        points.sort(key=lambda point: point.timestamp)

    recent_boundary = snapshot_time - config.recent_horizon_seconds
    records: list[LocalOpinionRecord] = []
    for (requestor, provider), events in sorted(pair_events.items()):
        positive = sum(item.positive for item in events)
        negative = len(events) - positive
        communication_quality = sum(
            item.communication_quality for item in events
        ) / len(events)
        opinion = local_opinion(positive, negative, communication_quality, config.gamma)

        positive_recent = sum(
            item.positive and item.timestamp >= recent_boundary for item in events
        )
        negative_recent = sum(
            (not item.positive) and item.timestamp >= recent_boundary for item in events
        )
        positive_past = positive - positive_recent
        negative_past = negative - negative_recent
        weighted_count = paper_weighted_event_count(
            positive_recent,
            positive_past,
            negative_recent,
            negative_past,
            config,
        )
        frequency = interaction_frequency(weighted_count, mean_raw_counts[requestor])

        requestor_trajectory = points_by_vehicle.get(requestor, [])
        provider_trajectory = points_by_vehicle.get(provider, [])
        if requestor_trajectory and provider_trajectory:
            similarity = trajectory_similarity(
                requestor_trajectory, provider_trajectory, config
            )
        else:
            similarity = _missing_similarity(config, requestor, provider)

        weight = opinion_weight(frequency, similarity, config)
        records.append(
            LocalOpinionRecord(
                requestor_id=requestor,
                provider_id=provider,
                opinion=opinion,
                interaction_frequency=frequency,
                trajectory_similarity=similarity,
                weight=weight,
                positive_events=positive,
                negative_events=negative,
                communication_quality=communication_quality,
            )
        )
    return records


def compute_reputations(
    local_records: Iterable[LocalOpinionRecord],
    gamma: float = 0.5,
) -> list[ReputationRecord]:
    """Compute Eqs. (11)-(13) for every local requestor-provider pair.

    The recommendation set for i->j consists of all x->j records where x != i.
    This exactly separates the target requestor's local opinion from the
    recommended opinion pool.
    """

    records = list(local_records)
    by_provider: dict[str, list[LocalOpinionRecord]] = defaultdict(list)
    for record in records:
        by_provider[record.provider_id].append(record)

    results: list[ReputationRecord] = []
    for record in sorted(records, key=lambda item: (item.requestor_id, item.provider_id)):
        recommenders = [
            candidate
            for candidate in by_provider[record.provider_id]
            if candidate.requestor_id != record.requestor_id
        ]
        rec = recommended_opinion(recommenders, gamma)
        final = combine_local_and_recommended(record.opinion, rec)
        results.append(
            ReputationRecord(
                requestor_id=record.requestor_id,
                provider_id=record.provider_id,
                local_opinion=record.opinion,
                recommended_opinion=rec,
                final_opinion=final,
                recommendation_count=len(recommenders),
                local_weight=record.weight,
                local_interaction_frequency=record.interaction_frequency,
                local_trajectory_similarity=record.trajectory_similarity,
            )
        )
    return results

