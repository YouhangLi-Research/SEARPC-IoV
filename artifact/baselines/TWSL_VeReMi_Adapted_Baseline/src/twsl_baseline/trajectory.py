from __future__ import annotations

import math
from collections.abc import Sequence

from .models import TrajectoryPoint, TWSLConfig


_EPS = 1e-12


def _point_distance(a: TrajectoryPoint, b: TrajectoryPoint) -> float:
    return math.hypot(a.x - b.x, a.y - b.y)


def lcs_length(
    first: Sequence[TrajectoryPoint],
    second: Sequence[TrajectoryPoint],
    tolerance: float = 0.0,
) -> int:
    """LCS length for Eq. (8).

    The literal paper definition uses equality of trajectory sample points.
    tolerance=0 preserves that rule. A non-zero tolerance is an explicit
    dataset mapping for continuous GPS coordinates and must be reported.
    """

    if tolerance < 0.0:
        raise ValueError("tolerance must be non-negative")
    if not first or not second:
        return 0
    previous = [0] * (len(second) + 1)
    for left in first:
        current = [0]
        for index, right in enumerate(second, start=1):
            matched = _point_distance(left, right) <= tolerance
            if matched:
                current.append(previous[index - 1] + 1)
            else:
                current.append(max(previous[index], current[-1]))
        previous = current
    return previous[-1]


def speed_dissimilarity(
    first: Sequence[TrajectoryPoint], second: Sequence[TrajectoryPoint]
) -> float:
    """Implement Eq. (7) using segment mean and maximum observed speed."""

    speeds_first = [point.speed for point in first if point.speed is not None]
    speeds_second = [point.speed for point in second if point.speed is not None]
    if not speeds_first or not speeds_second:
        raise ValueError("speed is required for both trajectory segments")
    average_first = sum(speeds_first) / len(speeds_first)
    average_second = sum(speeds_second) / len(speeds_second)
    denominator = max(max(speeds_first), max(speeds_second))
    if denominator <= _EPS:
        return 0.0
    return min(1.0, abs(average_first - average_second) / denominator)


def location_dissimilarity(
    first: Sequence[TrajectoryPoint],
    second: Sequence[TrajectoryPoint],
    tolerance: float = 0.0,
) -> float:
    """Implement Eq. (8)."""

    denominator = max(len(first), len(second))
    if denominator == 0:
        raise ValueError("empty trajectory segments have no location similarity")
    common = lcs_length(first, second, tolerance)
    return (denominator - common) / denominator


def _segment_direction(points: Sequence[TrajectoryPoint]) -> float:
    explicit = [point.direction for point in points if point.direction is not None]
    if explicit:
        sin_mean = sum(math.sin(value) for value in explicit) / len(explicit)
        cos_mean = sum(math.cos(value) for value in explicit) / len(explicit)
        if abs(sin_mean) <= _EPS and abs(cos_mean) <= _EPS:
            return 0.0
        return math.atan2(sin_mean, cos_mean) % (2.0 * math.pi)
    if len(points) < 2:
        raise ValueError("at least two points or an explicit direction are required")
    dx = points[-1].x - points[0].x
    dy = points[-1].y - points[0].y
    if abs(dx) <= _EPS and abs(dy) <= _EPS:
        return 0.0
    return math.atan2(dy, dx) % (2.0 * math.pi)


def direction_dissimilarity(
    first: Sequence[TrajectoryPoint], second: Sequence[TrajectoryPoint]
) -> float:
    """Implement the piecewise direction difference in Eq. (9)."""

    angle_first = _segment_direction(first)
    angle_second = _segment_direction(second)
    raw = abs(angle_first - angle_second) % (2.0 * math.pi)
    phi = min(raw, 2.0 * math.pi - raw)
    if phi <= math.pi / 2.0:
        return math.sin(phi) / 2.0
    return 0.5 + abs(math.sin(phi + math.pi / 2.0)) / 2.0


def trajectory_similarity(
    first: Sequence[TrajectoryPoint],
    second: Sequence[TrajectoryPoint],
    config: TWSLConfig,
) -> float:
    """Implement Eqs. (5)-(9)."""

    speed = speed_dissimilarity(first, second)
    location = location_dissimilarity(
        first, second, config.lcs_position_tolerance
    )
    direction = direction_dissimilarity(first, second)
    dissimilarity = (
        config.psi_speed * speed
        + config.psi_location * location
        + config.psi_direction * direction
    )
    return min(1.0, max(0.0, 1.0 - dissimilarity))

