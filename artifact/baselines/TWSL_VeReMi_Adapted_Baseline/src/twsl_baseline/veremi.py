"""Strict VeReMi NextGen adapter for the independent TWSL baseline."""

from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
from typing import Iterator, Mapping

from .models import TrajectoryPoint


def _finite(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{field} must be finite")
    return float(value)


def _vector3(value: object, field: str) -> tuple[float, float, float]:
    if isinstance(value, str):
        try:
            values = [float(item.strip()) for item in value.split(",")]
        except ValueError as error:
            raise ValueError(f"{field} contains a non-number") from error
    elif isinstance(value, list):
        values = [_finite(item, field) for item in value]
    else:
        raise ValueError(f"{field} must be an array or comma-separated vector")
    if len(values) != 3 or not all(math.isfinite(item) for item in values):
        raise ValueError(f"{field} must contain three finite numbers")
    return values[0], values[1], values[2]


@dataclass(frozen=True)
class VeReMiMessage:
    receiver_id: str
    provider_id: str
    receive_time: float
    send_time: float
    message_id: int
    attacker: int
    sender_point: TrajectoryPoint
    receiver_point: TrajectoryPoint


def _point(
    identity: str,
    timestamp_ns: float,
    state: Mapping[str, object],
) -> TrajectoryPoint:
    x, y, _ = _vector3(state.get("pos"), f"{identity}.pos")
    speed = _finite(state.get("spd"), f"{identity}.spd")
    heading_degrees = _finite(state.get("hed"), f"{identity}.hed")
    return TrajectoryPoint(
        timestamp=timestamp_ns / 1_000_000_000.0,
        vehicle_id=identity,
        x=x,
        y=y,
        speed=speed,
        direction=math.radians(heading_degrees % 360.0),
    )


def iter_veremi_receiver_directory(path: str | Path) -> Iterator[VeReMiMessage]:
    """Yield messages in the frozen conditional trust receiver-file order."""

    files = sorted(Path(path).rglob("*.json"))
    if not files:
        raise ValueError("VeReMi receiver directory contains no JSON files")
    for file_path in files:
        receiver_id = file_path.stem
        rows = json.loads(file_path.read_text(encoding="utf-8"))
        if not isinstance(rows, list):
            raise ValueError(f"{file_path}: JSON root must be an array")
        for row_number, row in enumerate(rows):
            if not isinstance(row, Mapping):
                raise ValueError(f"{file_path}:{row_number}: row must be an object")
            sender = row.get("sender")
            receiver = row.get("receiver")
            if not isinstance(sender, Mapping) or not isinstance(receiver, Mapping):
                raise ValueError(f"{file_path}:{row_number}: missing mobility objects")
            receive_time = _finite(row.get("rcvTime"), "rcvTime")
            send_time = _finite(row.get("sendTime"), "sendTime")
            provider_id = str(row.get("sender_id", "")).strip()
            if not provider_id or provider_id == receiver_id:
                raise ValueError(f"{file_path}:{row_number}: invalid provider identity")
            attacker = int(row.get("attacker"))
            if attacker not in (0, 1):
                raise ValueError(f"{file_path}:{row_number}: attacker must be binary")
            yield VeReMiMessage(
                receiver_id=receiver_id,
                provider_id=provider_id,
                receive_time=receive_time / 1_000_000_000.0,
                send_time=send_time / 1_000_000_000.0,
                message_id=int(row.get("messageID")),
                attacker=attacker,
                sender_point=_point(provider_id, send_time, sender),
                receiver_point=_point(receiver_id, receive_time, receiver),
            )
