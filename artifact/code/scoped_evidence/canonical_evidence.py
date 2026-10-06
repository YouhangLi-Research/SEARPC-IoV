"""scoped evidence canonical evidence-cut helpers.

This module separates local application evidence from evidence that is allowed
write access to replicated protocol state.  Committee/admission decisions bind
their deterministic seed to the canonical evidence-state root.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Iterable, Mapping, Sequence


@dataclass(frozen=True, order=True)
class CanonicalEvidenceRecord:
    evidence_id: str
    subject_id: int
    evidence_kind: str
    outcome: float
    source_domain: str
    effective_height: int

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id cannot be empty")
        if self.subject_id < 0:
            raise ValueError("subject_id must be non-negative")
        if not 0.0 <= float(self.outcome) <= 1.0:
            raise ValueError("outcome must lie in [0,1]")
        if self.effective_height < 0:
            raise ValueError("effective_height must be non-negative")


def canonical_cut(
    records: Iterable[CanonicalEvidenceRecord], *, decision_height: int
) -> tuple[CanonicalEvidenceRecord, ...]:
    """Return the deterministic evidence snapshot visible to height `decision_height`.

    Records whose effective height is strictly before the decision height may
    write replicated protocol state.  Sorting by a stable tuple means physical
    network-arrival order cannot change the snapshot.
    """
    if decision_height < 0:
        raise ValueError("decision_height must be non-negative")
    visible = [r for r in records if r.effective_height < decision_height]
    return tuple(sorted(visible, key=lambda r: (
        r.effective_height,
        r.evidence_kind,
        r.subject_id,
        r.source_domain,
        r.evidence_id,
        float(r.outcome),
    )))


def evidence_state_root(records: Sequence[CanonicalEvidenceRecord]) -> str:
    payload = [
        {
            "id": r.evidence_id,
            "subject": int(r.subject_id),
            "kind": r.evidence_kind,
            "outcome": format(float(r.outcome), ".17g"),
            "source_domain": r.source_domain,
            "effective_height": int(r.effective_height),
        }
        for r in records
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def derive_bound_seed(
    *,
    base_seed: int,
    height: int,
    view: int,
    evidence_root: str,
    purpose: str,
) -> int:
    if base_seed < 0 or height < 0 or view < 0:
        raise ValueError("base_seed, height and view must be non-negative")
    if len(evidence_root) != 64:
        raise ValueError("evidence_root must be a SHA-256 hex digest")
    material = f"{base_seed}|{height}|{view}|{evidence_root}|{purpose}".encode("utf-8")
    # 63-bit non-negative integer keeps downstream RNG APIs portable.
    return int.from_bytes(sha256(material).digest()[:8], "big") & ((1 << 63) - 1)


def deterministic_state_projection(
    records: Sequence[CanonicalEvidenceRecord],
) -> Mapping[int, tuple[float, ...]]:
    """Minimal deterministic projection used by replica-agreement tests.

    Production code may keep richer finite-state metadata; this helper proves
    that the same canonical cut produces the same subject-wise audit stream
    independent of physical arrival order.
    """
    by_subject: dict[int, list[float]] = {}
    for record in records:
        by_subject.setdefault(record.subject_id, []).append(float(record.outcome))
    return {subject: tuple(values) for subject, values in sorted(by_subject.items())}

class RollingEvidenceRoot:
    """Deterministic hash-chain representation of the canonical evidence state.

    Each canonical delivery batch is sorted using the same key as `canonical_cut`
    before being incorporated. This is an efficient implementation of a stable
    serialized canonical history and is independent of physical arrival order
    within the cut.
    """
    def __init__(self) -> None:
        self._root = sha256(bytes.fromhex("52454341502d56332e337c63616e6f6e6963616c2d65766964656e63657c656d707479")).hexdigest()
        self._records = 0

    @property
    def root(self) -> str:
        return self._root

    @property
    def records(self) -> int:
        return self._records

    def append_batch(self, records: Iterable[CanonicalEvidenceRecord]) -> str:
        ordered = canonical_cut(records, decision_height=10**18)
        if not ordered:
            return self._root
        payload = [
            {
                "id": r.evidence_id,
                "subject": int(r.subject_id),
                "kind": r.evidence_kind,
                "outcome": format(float(r.outcome), ".17g"),
                "source_domain": r.source_domain,
                "effective_height": int(r.effective_height),
            }
            for r in ordered
        ]
        batch = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self._root = sha256(f"{self._root}|{batch}".encode("utf-8")).hexdigest()
        self._records += len(ordered)
        return self._root
