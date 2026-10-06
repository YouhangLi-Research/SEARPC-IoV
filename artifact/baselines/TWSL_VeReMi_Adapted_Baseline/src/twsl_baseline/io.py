from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core import opinion_weight
from .models import (
    Interaction,
    LocalOpinionRecord,
    Opinion,
    ReputationRecord,
    TrajectoryPoint,
    TWSLConfig,
)


def parse_timestamp(value: str) -> float:
    try:
        return float(value)
    except ValueError:
        normalized = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "positive", "success", "honest", "benign"}:
        return True
    if normalized in {"0", "false", "negative", "failure", "malicious", "attack"}:
        return False
    raise ValueError(f"cannot parse outcome {value!r}")


def load_config(path: str | Path) -> TWSLConfig:
    with Path(path).open("r", encoding="utf-8") as handle:
        return TWSLConfig.from_dict(json.load(handle))


def read_interactions(path: str | Path, config: TWSLConfig) -> list[Interaction]:
    result: list[Interaction] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "requestor_id", "provider_id", "outcome"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"interactions CSV missing columns: {sorted(missing)}")
        for line_number, row in enumerate(reader, start=2):
            quality_text = (row.get("communication_quality") or "").strip()
            if quality_text:
                quality = float(quality_text)
            elif config.communication_quality_default is not None:
                quality = config.communication_quality_default
            else:
                raise ValueError(
                    f"line {line_number}: communication_quality is required; "
                    "the paper makes it the source of uncertainty"
                )
            result.append(
                Interaction(
                    timestamp=parse_timestamp(row["timestamp"]),
                    requestor_id=row["requestor_id"].strip(),
                    provider_id=row["provider_id"].strip(),
                    positive=_parse_bool(row["outcome"]),
                    communication_quality=quality,
                )
            )
    return result


def read_trajectories(path: str | Path) -> list[TrajectoryPoint]:
    result: list[TrajectoryPoint] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "vehicle_id", "x", "y"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"trajectory CSV missing columns: {sorted(missing)}")
        for row in reader:
            speed_text = (row.get("speed") or "").strip()
            direction_text = (row.get("direction_radians") or "").strip()
            result.append(
                TrajectoryPoint(
                    timestamp=parse_timestamp(row["timestamp"]),
                    vehicle_id=row["vehicle_id"].strip(),
                    x=float(row["x"]),
                    y=float(row["y"]),
                    speed=float(speed_text) if speed_text else None,
                    direction=float(direction_text) if direction_text else None,
                )
            )
    return result


def read_local_opinions(
    path: str | Path,
    config: TWSLConfig,
    *,
    weight_tolerance: float = 1e-9,
) -> list[LocalOpinionRecord]:
    """Read externally prepared opinions and enforce Eq. (10).

    The CSV weight is retained as an auditable redundancy field, never as an
    independently trusted input. A mismatch is rejected instead of allowing an
    adapter to strengthen or weaken TWSL recommendations.
    """

    result: list[LocalOpinionRecord] = []
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "requestor_id",
            "provider_id",
            "belief",
            "distrust",
            "uncertainty",
            "interaction_frequency",
            "trajectory_similarity",
            "weight",
        }
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"local-opinion CSV missing columns: {sorted(missing)}")
        for line_number, row in enumerate(reader, start=2):
            interaction_frequency_value = float(row["interaction_frequency"])
            trajectory_similarity_value = float(row["trajectory_similarity"])
            supplied_weight = float(row["weight"])
            expected_weight = opinion_weight(
                interaction_frequency_value,
                trajectory_similarity_value,
                config,
            )
            if not math.isclose(
                supplied_weight,
                expected_weight,
                rel_tol=weight_tolerance,
                abs_tol=weight_tolerance,
            ):
                raise ValueError(
                    f"line {line_number}: weight {supplied_weight!r} violates "
                    f"TWSL Eq. (10); expected {expected_weight!r} from "
                    "interaction_frequency and trajectory_similarity"
                )
            result.append(
                LocalOpinionRecord(
                    requestor_id=row["requestor_id"].strip(),
                    provider_id=row["provider_id"].strip(),
                    opinion=Opinion(
                        float(row["belief"]),
                        float(row["distrust"]),
                        float(row["uncertainty"]),
                        config.gamma,
                    ),
                    interaction_frequency=interaction_frequency_value,
                    trajectory_similarity=trajectory_similarity_value,
                    weight=expected_weight,
                    positive_events=int(row.get("positive_events") or 0),
                    negative_events=int(row.get("negative_events") or 0),
                    communication_quality=float(row.get("communication_quality") or 0.0),
                )
            )
    return result


def write_local_opinions(path: str | Path, records: list[LocalOpinionRecord]) -> None:
    fieldnames = [
        "requestor_id",
        "provider_id",
        "belief",
        "distrust",
        "uncertainty",
        "reputation",
        "positive_events",
        "negative_events",
        "communication_quality",
        "interaction_frequency",
        "trajectory_similarity",
        "weight",
    ]
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {
                    "requestor_id": record.requestor_id,
                    "provider_id": record.provider_id,
                    **record.opinion.as_dict(),
                    "positive_events": record.positive_events,
                    "negative_events": record.negative_events,
                    "communication_quality": record.communication_quality,
                    "interaction_frequency": record.interaction_frequency,
                    "trajectory_similarity": record.trajectory_similarity,
                    "weight": record.weight,
                }
            )


def _reputation_fieldnames() -> list[str]:
    return [
        "requestor_id",
        "provider_id",
        "local_belief",
        "local_distrust",
        "local_uncertainty",
        "local_reputation",
        "recommended_belief",
        "recommended_distrust",
        "recommended_uncertainty",
        "recommended_reputation",
        "final_belief",
        "final_distrust",
        "final_uncertainty",
        "final_reputation",
        "recommendation_count",
        "local_weight",
        "local_interaction_frequency",
        "local_trajectory_similarity",
    ]


def _reputation_row(record: ReputationRecord) -> dict[str, Any]:
    recommended = record.recommended_opinion
    row: dict[str, Any] = {
        "requestor_id": record.requestor_id,
        "provider_id": record.provider_id,
        **record.local_opinion.as_dict("local_"),
        **record.final_opinion.as_dict("final_"),
        "recommendation_count": record.recommendation_count,
        "local_weight": record.local_weight,
        "local_interaction_frequency": record.local_interaction_frequency,
        "local_trajectory_similarity": record.local_trajectory_similarity,
    }
    if recommended is None:
        row.update(
            {
                "recommended_belief": "",
                "recommended_distrust": "",
                "recommended_uncertainty": "",
                "recommended_reputation": "",
            }
        )
    else:
        row.update(recommended.as_dict("recommended_"))
    return row


def write_reputations(path: str | Path, records: list[ReputationRecord]) -> None:
    fieldnames = _reputation_fieldnames()
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            writer.writerow(_reputation_row(record))


def write_reputation_series(
    path: str | Path, records: list[tuple[float, ReputationRecord]]
) -> None:
    fieldnames = ["snapshot_time", *_reputation_fieldnames()]
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for snapshot_time, record in records:
            writer.writerow({"snapshot_time": snapshot_time, **_reputation_row(record)})


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_manifest(path: str | Path, payload: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
