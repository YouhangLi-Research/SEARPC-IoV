"""Strict public-dataset schema adapters for DURAC-IoV."""

from __future__ import annotations

from collections import deque
import csv
from dataclasses import dataclass
import json
from math import atan2, degrees, hypot, isfinite, sqrt
from pathlib import Path
from statistics import median
from typing import Dict, Iterable, Iterator, Mapping, Sequence


def _number(value, field: str) -> float:
    if not isinstance(value, (int, float)) or not isfinite(float(value)):
        raise ValueError(f"{field} must be a finite number")
    return float(value)


def _vector3(value, field: str) -> tuple[float, float, float]:
    # VeReMi NextGen v1 documentation depicts arrays, while the archived JSON
    # files encode these values as comma-separated strings.  Accept exactly
    # those two representations and retain strict length/finite-value checks.
    if isinstance(value, str):
        value = [item.strip() for item in value.split(",")]
        try:
            value = [float(item) for item in value]
        except ValueError as error:
            raise ValueError(f"{field} contains a non-number") from error
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError(f"{field} must contain exactly three numbers")
    return tuple(_number(item, field) for item in value)


def _angle_difference(first: float, second: float) -> float:
    difference = abs(first - second) % 360.0
    return min(difference, 360.0 - difference)


@dataclass(frozen=True)
class VeReMiRecord:
    sender_id: str
    sender_alias: int
    message_id: int
    attacker: int
    receive_time: float
    send_time: float
    sender: Mapping[str, object]
    receiver: Mapping[str, object]

    @classmethod
    def from_mapping(cls, row: Mapping[str, object]) -> "VeReMiRecord":
        required = (
            "rcvTime",
            "sendTime",
            "sender_id",
            "sender_alias",
            "messageID",
            "attacker",
            "sender",
            "receiver",
        )
        missing = [field for field in required if field not in row]
        if missing:
            raise ValueError(f"missing VeReMi fields: {missing}")
        if not isinstance(row["sender"], Mapping) or not isinstance(
            row["receiver"], Mapping
        ):
            raise ValueError("sender and receiver must be objects")
        attacker = int(row["attacker"])
        if attacker not in (0, 1):
            raise ValueError("attacker must be 0 or 1")
        return cls(
            sender_id=str(row["sender_id"]),
            sender_alias=int(row["sender_alias"]),
            message_id=int(row["messageID"]),
            attacker=attacker,
            receive_time=_number(row["rcvTime"], "rcvTime"),
            send_time=_number(row["sendTime"], "sendTime"),
            sender=row["sender"],
            receiver=row["receiver"],
        )

    def physical_features(self) -> Dict[str, float]:
        """Return identity-free message evidence features.

        Sender identifiers, pseudonyms, and any historical trust value are
        intentionally excluded.
        """

        sender_position = _vector3(self.sender.get("pos"), "sender.pos")
        receiver_position = _vector3(self.receiver.get("pos"), "receiver.pos")
        relative = tuple(
            first - second
            for first, second in zip(sender_position, receiver_position)
        )
        sender_noise = _vector3(
            self.sender.get("pos_noise"), "sender.pos_noise"
        )
        receiver_noise = _vector3(
            self.receiver.get("pos_noise"), "receiver.pos_noise"
        )
        sender_speed = _number(self.sender.get("spd"), "sender.spd")
        receiver_speed = _number(self.receiver.get("spd"), "receiver.spd")
        sender_acceleration = _number(self.sender.get("acl"), "sender.acl")
        receiver_acceleration = _number(self.receiver.get("acl"), "receiver.acl")
        sender_heading = _number(self.sender.get("hed"), "sender.hed")
        receiver_heading = _number(self.receiver.get("hed"), "receiver.hed")
        return {
            "delivery_delay_s": max(
                0.0, self.receive_time - self.send_time
            )
            / 1_000_000_000.0,
            "relative_distance": sqrt(sum(value * value for value in relative)),
            "relative_x": relative[0],
            "relative_y": relative[1],
            "relative_z": relative[2],
            "sender_position_noise": sqrt(sum(value * value for value in sender_noise)),
            "receiver_position_noise": sqrt(sum(value * value for value in receiver_noise)),
            "speed_difference": abs(sender_speed - receiver_speed),
            "sender_speed_noise": abs(_number(self.sender.get("spd_noise"), "sender.spd_noise")),
            "receiver_speed_noise": abs(_number(self.receiver.get("spd_noise"), "receiver.spd_noise")),
            "acceleration_difference": abs(sender_acceleration - receiver_acceleration),
            "sender_acceleration_noise": abs(_number(self.sender.get("acl_noise"), "sender.acl_noise")),
            "receiver_acceleration_noise": abs(_number(self.receiver.get("acl_noise"), "receiver.acl_noise")),
            "heading_difference": _angle_difference(sender_heading, receiver_heading),
            "sender_heading_noise": abs(_number(self.sender.get("hed_noise"), "sender.hed_noise")),
            "receiver_heading_noise": abs(_number(self.receiver.get("hed_noise"), "receiver.hed_noise")),
            "distance_to_road_edge": _number(
                self.sender.get("distance_to_road_edge", 0.0),
                "sender.distance_to_road_edge",
            ),
        }

    @property
    def driver_profile(self) -> str:
        return str(self.sender.get("driversProfile", "UNKNOWN")).upper()


def iter_veremi_json(path: Path) -> Iterator[VeReMiRecord]:
    content = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(content, list):
        raise ValueError("VeReMi JSON root must be an array")
    for row in content:
        if not isinstance(row, Mapping):
            raise ValueError("every VeReMi row must be an object")
        yield VeReMiRecord.from_mapping(row)


def iter_veremi_directory(path: Path) -> Iterator[VeReMiRecord]:
    """Yield every record from a split directory in stable filename order."""

    files = sorted(path.rglob("*.json"))
    if not files:
        raise ValueError("VeReMi split directory contains no JSON files")
    for file_path in files:
        yield from iter_veremi_json(file_path)


@dataclass(frozen=True)
class VeReMiSplitAudit:
    json_files: int
    messages: int
    attack_messages: int
    attack_rate: float
    sender_ids: int
    sender_aliases: int
    driver_profiles: tuple[str, ...]
    vector_encodings: tuple[str, ...]
    feature_names: tuple[str, ...]


TEMPORAL_FEATURE_NAMES = (
    "has_previous_message",
    "receive_interval_s",
    "send_interval_s",
    "send_time_regression",
    "send_time_zero_delta",
    "reported_displacement",
    "speed_displacement_residual",
    "acceleration_speed_residual",
    "heading_change",
    "heading_rate_deg_s",
    "receive_send_interval_disagreement_s",
    "message_id_repeat",
    "message_id_regression",
)

CONTEXTUAL_FEATURE_NAMES = (
    "receiver_has_history",
    "receiver_interval_s",
    "receiver_reported_displacement",
    "receiver_speed_displacement_residual",
    "receiver_acceleration_speed_residual",
    "receiver_heading_change",
    "receiver_heading_rate_deg_s",
    "receiver_position_history_median_distance",
    "receiver_speed_history_median_difference",
    "receiver_acceleration_history_median_difference",
    "receiver_heading_history_median_difference",
    "sender_history_count_normalized",
    "sender_position_history_median_distance",
    "sender_speed_history_median_difference",
    "sender_acceleration_history_median_difference",
    "sender_heading_history_median_difference",
)


@dataclass(frozen=True)
class VeReMiTemporalExample:
    record: VeReMiRecord
    temporal_features: Mapping[str, float]


@dataclass(frozen=True)
class VeReMiContextualExample:
    record: VeReMiRecord
    temporal_features: Mapping[str, float]
    contextual_features: Mapping[str, float]


def _temporal_features(
    current: VeReMiRecord, previous: VeReMiRecord | None
) -> Dict[str, float]:
    if previous is None:
        return {name: float(name == "has_previous_message") * 0.0 for name in TEMPORAL_FEATURE_NAMES}

    receive_delta = (current.receive_time - previous.receive_time) / 1_000_000_000.0
    send_delta = (current.send_time - previous.send_time) / 1_000_000_000.0
    positive_receive_delta = max(0.0, receive_delta)
    positive_send_delta = max(0.0, send_delta)
    current_position = _vector3(current.sender.get("pos"), "sender.pos")
    previous_position = _vector3(previous.sender.get("pos"), "sender.pos")
    displacement = sqrt(
        sum((first - second) ** 2 for first, second in zip(current_position, previous_position))
    )
    current_speed = _number(current.sender.get("spd"), "sender.spd")
    previous_speed = _number(previous.sender.get("spd"), "sender.spd")
    current_acceleration = _number(current.sender.get("acl"), "sender.acl")
    previous_acceleration = _number(previous.sender.get("acl"), "sender.acl")
    expected_displacement = (
        0.5 * (current_speed + previous_speed) * positive_send_delta
    )
    expected_speed_change = (
        0.5
        * (current_acceleration + previous_acceleration)
        * positive_send_delta
    )
    actual_speed_change = current_speed - previous_speed
    heading_change = _angle_difference(
        _number(current.sender.get("hed"), "sender.hed"),
        _number(previous.sender.get("hed"), "sender.hed"),
    )
    return {
        "has_previous_message": 1.0,
        "receive_interval_s": positive_receive_delta,
        "send_interval_s": positive_send_delta,
        "send_time_regression": float(send_delta < 0.0),
        "send_time_zero_delta": float(send_delta == 0.0),
        "reported_displacement": displacement,
        "speed_displacement_residual": abs(
            displacement - expected_displacement
        ),
        "acceleration_speed_residual": abs(
            actual_speed_change - expected_speed_change
        ),
        "heading_change": heading_change,
        "heading_rate_deg_s": heading_change
        / max(positive_receive_delta, 1e-6),
        "receive_send_interval_disagreement_s": abs(
            receive_delta - send_delta
        ),
        "message_id_repeat": float(current.message_id == previous.message_id),
        "message_id_regression": float(current.message_id < previous.message_id),
    }


def iter_veremi_temporal_directory(path: Path) -> Iterator[VeReMiTemporalExample]:
    """Build per-receiver, per-sender temporal evidence without ID features."""

    files = sorted(path.rglob("*.json"))
    if not files:
        raise ValueError("VeReMi split directory contains no JSON files")
    for file_path in files:
        records = list(iter_veremi_json(file_path))
        records.sort(
            key=lambda record: (
                record.receive_time,
                record.send_time,
                record.message_id,
                record.sender_id,
            )
        )
        state: dict[str, VeReMiRecord] = {}
        for record in records:
            previous = state.get(record.sender_id)
            features = _temporal_features(record, previous)
            if tuple(features) != TEMPORAL_FEATURE_NAMES:
                raise ValueError("temporal feature schema changed")
            if not all(isfinite(value) for value in features.values()):
                raise ValueError("temporal features must be finite")
            yield VeReMiTemporalExample(
                record=record, temporal_features=features
            )
            state[record.sender_id] = record


def _median_position(records: Sequence[VeReMiRecord], role: str):
    positions = [
        _vector3(getattr(record, role).get("pos"), f"{role}.pos")
        for record in records
    ]
    return tuple(median(position[index] for position in positions) for index in range(3))


def _history_context_features(
    current: VeReMiRecord,
    receiver_history: Sequence[VeReMiRecord],
    sender_history: Sequence[VeReMiRecord],
) -> Dict[str, float]:
    features = {name: 0.0 for name in CONTEXTUAL_FEATURE_NAMES}

    if receiver_history:
        previous = receiver_history[-1]
        receive_delta = max(
            0.0,
            (current.receive_time - previous.receive_time) / 1_000_000_000.0,
        )
        current_position = _vector3(current.receiver.get("pos"), "receiver.pos")
        previous_position = _vector3(previous.receiver.get("pos"), "receiver.pos")
        displacement = sqrt(
            sum(
                (first - second) ** 2
                for first, second in zip(current_position, previous_position)
            )
        )
        current_speed = _number(current.receiver.get("spd"), "receiver.spd")
        previous_speed = _number(previous.receiver.get("spd"), "receiver.spd")
        current_acceleration = _number(
            current.receiver.get("acl"), "receiver.acl"
        )
        previous_acceleration = _number(
            previous.receiver.get("acl"), "receiver.acl"
        )
        expected_displacement = (
            0.5 * (current_speed + previous_speed) * receive_delta
        )
        expected_speed_change = (
            0.5
            * (current_acceleration + previous_acceleration)
            * receive_delta
        )
        heading_change = _angle_difference(
            _number(current.receiver.get("hed"), "receiver.hed"),
            _number(previous.receiver.get("hed"), "receiver.hed"),
        )
        receiver_median_position = _median_position(receiver_history, "receiver")
        features.update(
            {
                "receiver_has_history": 1.0,
                "receiver_interval_s": receive_delta,
                "receiver_reported_displacement": displacement,
                "receiver_speed_displacement_residual": abs(
                    displacement - expected_displacement
                ),
                "receiver_acceleration_speed_residual": abs(
                    (current_speed - previous_speed) - expected_speed_change
                ),
                "receiver_heading_change": heading_change,
                "receiver_heading_rate_deg_s": heading_change
                / max(receive_delta, 1e-6),
                "receiver_position_history_median_distance": sqrt(
                    sum(
                        (first - second) ** 2
                        for first, second in zip(
                            current_position, receiver_median_position
                        )
                    )
                ),
                "receiver_speed_history_median_difference": abs(
                    current_speed
                    - median(
                        _number(record.receiver.get("spd"), "receiver.spd")
                        for record in receiver_history
                    )
                ),
                "receiver_acceleration_history_median_difference": abs(
                    current_acceleration
                    - median(
                        _number(record.receiver.get("acl"), "receiver.acl")
                        for record in receiver_history
                    )
                ),
                "receiver_heading_history_median_difference": median(
                    _angle_difference(
                        _number(current.receiver.get("hed"), "receiver.hed"),
                        _number(record.receiver.get("hed"), "receiver.hed"),
                    )
                    for record in receiver_history
                ),
            }
        )

    if sender_history:
        current_position = _vector3(current.sender.get("pos"), "sender.pos")
        sender_median_position = _median_position(sender_history, "sender")
        current_speed = _number(current.sender.get("spd"), "sender.spd")
        current_acceleration = _number(current.sender.get("acl"), "sender.acl")
        current_heading = _number(current.sender.get("hed"), "sender.hed")
        features.update(
            {
                "sender_history_count_normalized": len(sender_history) / 5.0,
                "sender_position_history_median_distance": sqrt(
                    sum(
                        (first - second) ** 2
                        for first, second in zip(
                            current_position, sender_median_position
                        )
                    )
                ),
                "sender_speed_history_median_difference": abs(
                    current_speed
                    - median(
                        _number(record.sender.get("spd"), "sender.spd")
                        for record in sender_history
                    )
                ),
                "sender_acceleration_history_median_difference": abs(
                    current_acceleration
                    - median(
                        _number(record.sender.get("acl"), "sender.acl")
                        for record in sender_history
                    )
                ),
                "sender_heading_history_median_difference": median(
                    _angle_difference(
                        current_heading,
                        _number(record.sender.get("hed"), "sender.hed"),
                    )
                    for record in sender_history
                ),
            }
        )

    if tuple(features) != CONTEXTUAL_FEATURE_NAMES:
        raise ValueError("contextual feature schema changed")
    if not all(isfinite(value) for value in features.values()):
        raise ValueError("contextual features must be finite")
    return features


def iter_veremi_contextual_directory(
    path: Path,
) -> Iterator[VeReMiContextualExample]:
    """Build causal receiver-wide and per-sender rolling context evidence."""

    files = sorted(path.rglob("*.json"))
    if not files:
        raise ValueError("VeReMi split directory contains no JSON files")
    for file_path in files:
        records = list(iter_veremi_json(file_path))
        records.sort(
            key=lambda record: (
                record.receive_time,
                record.send_time,
                record.message_id,
                record.sender_id,
            )
        )
        previous_by_sender: dict[str, VeReMiRecord] = {}
        history_by_sender: dict[str, deque[VeReMiRecord]] = {}
        receiver_history: deque[VeReMiRecord] = deque(maxlen=5)
        for record in records:
            sender_history = history_by_sender.setdefault(
                record.sender_id, deque(maxlen=5)
            )
            temporal = _temporal_features(
                record, previous_by_sender.get(record.sender_id)
            )
            contextual = _history_context_features(
                record, tuple(receiver_history), tuple(sender_history)
            )
            yield VeReMiContextualExample(
                record=record,
                temporal_features=temporal,
                contextual_features=contextual,
            )
            previous_by_sender[record.sender_id] = record
            sender_history.append(record)
            receiver_history.append(record)


def audit_veremi_directory(path: Path) -> VeReMiSplitAudit:
    """Strictly validate and account for one official VeReMi split."""

    files = sorted(path.rglob("*.json"))
    if not files:
        raise ValueError("VeReMi split directory contains no JSON files")
    messages = 0
    attacks = 0
    sender_ids: set[str] = set()
    aliases: set[int] = set()
    profiles: set[str] = set()
    encodings: set[str] = set()
    feature_names: tuple[str, ...] | None = None
    for file_path in files:
        content = json.loads(file_path.read_text(encoding="utf-8"))
        if not isinstance(content, list):
            raise ValueError(f"VeReMi JSON root must be an array: {file_path}")
        for row in content:
            if not isinstance(row, Mapping):
                raise ValueError("every VeReMi row must be an object")
            sender = row.get("sender")
            if isinstance(sender, Mapping):
                encodings.add(type(sender.get("pos")).__name__)
            record = VeReMiRecord.from_mapping(row)
            features = record.physical_features()
            if not all(isfinite(value) for value in features.values()):
                raise ValueError("VeReMi physical features must be finite")
            current_names = tuple(features)
            if feature_names is None:
                feature_names = current_names
            elif current_names != feature_names:
                raise ValueError("VeReMi feature schema changes within split")
            messages += 1
            attacks += record.attacker
            sender_ids.add(record.sender_id)
            aliases.add(record.sender_alias)
            profiles.add(record.driver_profile)
    if messages == 0:
        raise ValueError("VeReMi split contains no messages")
    return VeReMiSplitAudit(
        json_files=len(files),
        messages=messages,
        attack_messages=attacks,
        attack_rate=attacks / messages,
        sender_ids=len(sender_ids),
        sender_aliases=len(aliases),
        driver_profiles=tuple(sorted(profiles)),
        vector_encodings=tuple(sorted(encodings)),
        feature_names=feature_names or (),
    )


TRUST_IOV_ALIASES: Mapping[str, tuple[str, ...]] = {
    "trustor": ("trustor", "trustor_id", "evaluator", "source_vehicle"),
    "trustee": ("trustee", "trustee_id", "target", "target_vehicle"),
    "time": ("time", "timestamp", "time_instance", "interaction_time"),
    "experience": ("experience", "interaction_experience"),
    "frequency": ("frequency", "interaction_frequency"),
    "timeliness": ("timeliness", "interaction_timeliness"),
    "message_quality": ("message_quality", "quality_of_received_messages", "quality"),
    "attack_label": ("attack", "attack_label", "label", "malicious"),
    "opinion": ("opinion", "rating", "recommendation", "recommendation_value"),
    "adjudicated_truth": ("ground_truth", "event_truth", "adjudicated_truth"),
}


@dataclass(frozen=True)
class CsvSchemaAudit:
    columns: tuple[str, ...]
    semantic_mapping: Mapping[str, str]
    missing_core_fields: tuple[str, ...]
    has_native_opinion_pair: bool
    has_adjudicated_opinion_truth: bool


def audit_trust_iov_csv(path: Path) -> CsvSchemaAudit:
    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.reader(handle)
        try:
            columns = tuple(next(reader))
        except StopIteration as error:
            raise ValueError("CSV is empty") from error
    normalized = {column.strip().lower(): column for column in columns}
    mapping: dict[str, str] = {}
    for semantic, aliases in TRUST_IOV_ALIASES.items():
        for alias in aliases:
            if alias in normalized:
                mapping[semantic] = normalized[alias]
                break
    core = (
        "trustor",
        "trustee",
        "time",
        "experience",
        "frequency",
        "timeliness",
        "message_quality",
        "attack_label",
    )
    missing = tuple(field for field in core if field not in mapping)
    has_opinion = all(field in mapping for field in ("trustor", "trustee", "opinion"))
    has_truth = has_opinion and "adjudicated_truth" in mapping
    return CsvSchemaAudit(
        columns=columns,
        semantic_mapping=mapping,
        missing_core_fields=missing,
        has_native_opinion_pair=has_opinion,
        has_adjudicated_opinion_truth=has_truth,
    )
