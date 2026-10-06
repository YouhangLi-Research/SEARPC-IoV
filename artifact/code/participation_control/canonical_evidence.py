"""Replay-safe evidence, purpose projections, and authority-bound seeds.

SEARPC participation control closes three protocol gaps without changing the high-level
participation method:

* audit responses are unique by a registered challenge namespace across
  heights, rather than only within one delivery batch;
* committee selection receives a typed seed capability and no caller-supplied
  event label;
* the registry commitment covers complete canonical validator entries.

The full control snapshot remains an archival commitment. Committee selection,
core audit planning, and the optional content extension consume distinct
runtime-checked capabilities.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from typing import Iterable, Mapping, Sequence

from typed_authority import (
    AuthorityCapability,
    AuthorityTarget,
    authority_meet,
    require_authority,
)


SCHEMA_VERSION = bytes.fromhex("72656361702d636f6e74726f6c2d76332e352e31").decode("ascii")
CHAIN_ID = bytes.fromhex("72656361702d7065726d697373696f6e65642d696f76").decode("ascii")

VALIDATOR_AUDIT_AUTHORITY = frozenset({
    AuthorityTarget.CORE_PARTICIPATION_FSM,
    AuthorityTarget.COMMITTEE_SEED,
    AuthorityTarget.CORE_AUDIT_PLAN,
})
CONTENT_RISK_AUTHORITY = frozenset({
    AuthorityTarget.EVENT_RISK,
    AuthorityTarget.EXTENSION_GAMMA,
    AuthorityTarget.EXTENSION_AUDIT_PLAN,
})
REGISTRY_AUTHORITY = frozenset({
    AuthorityTarget.COMMITTEE_SEED,
    AuthorityTarget.CORE_AUDIT_PLAN,
    AuthorityTarget.EXTENSION_AUDIT_PLAN,
})
POLICY_AUTHORITY = frozenset({
    AuthorityTarget.COMMITTEE_SEED,
    AuthorityTarget.CORE_AUDIT_PLAN,
    AuthorityTarget.EXTENSION_GAMMA,
    AuthorityTarget.EXTENSION_AUDIT_PLAN,
})


def _hash(value) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def canonical_hash(value) -> str:
    """Public deterministic hash helper for protocol commitments."""

    return _hash(value)


def _validate_root(value: str, label: str) -> None:
    if len(value) != 64:
        raise ValueError(f"invalid {label}")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ValueError(f"invalid {label}") from exc


@dataclass(frozen=True)
class CanonicalEvidenceRecord:
    evidence_id: str
    subject_id: int
    evidence_kind: str
    outcome: float
    source_domain: str
    effective_height: int
    delivery_height: int
    source_height: int
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not self.evidence_id or self.subject_id < 0 or not self.source_domain:
            raise ValueError("invalid evidence identity")
        if not 0 <= float(self.outcome) <= 1:
            raise ValueError("outcome outside [0,1]")
        if min(self.effective_height, self.delivery_height, self.source_height) < 0:
            raise ValueError("negative height")

    @property
    def challenge_key(self):
        """Issuer-scoped challenge identity; envelope IDs add no authority."""

        return (
            self.evidence_kind,
            self.subject_id,
            self.source_domain,
            self.source_height,
            self.schema_version,
        )

    @property
    def challenge_id(self) -> str:
        return _hash({
            "schema": bytes.fromhex("72656361702d61756469742d6368616c6c656e67652d7631").decode("ascii"),
            "key": self.challenge_key,
        })

    @property
    def logical_key(self):
        return self.challenge_key

    def payload(self):
        """Raw archival envelope, including the transport evidence ID."""

        data = asdict(self)
        data["outcome"] = format(float(self.outcome), ".17g")
        return data

    def canonical_payload(self):
        """Replay-stable payload committed to the rolling evidence root."""

        return {
            "schema_version": self.schema_version,
            "challenge_id": self.challenge_id,
            "subject_id": self.subject_id,
            "evidence_kind": self.evidence_kind,
            "outcome": format(float(self.outcome), ".17g"),
            "source_domain": self.source_domain,
            "effective_height": self.effective_height,
            "delivery_height": self.delivery_height,
            "source_height": self.source_height,
        }

    @property
    def response_digest(self) -> str:
        return _hash(self.canonical_payload())


def _record_sort_key(record: CanonicalEvidenceRecord):
    return (
        record.effective_height,
        record.delivery_height,
        record.evidence_kind,
        record.subject_id,
        record.source_domain,
        record.source_height,
        record.response_digest,
    )


def resolve_evidence(
    records: Iterable[CanonicalEvidenceRecord], *, decision_height: int
):
    """Collapse equivalent responses and reject same-challenge conflicts."""

    if decision_height < 0:
        raise ValueError("negative decision height")
    grouped: dict[tuple, dict[str, list[CanonicalEvidenceRecord]]] = {}
    for record in records:
        variants = grouped.setdefault(record.challenge_key, {})
        variants.setdefault(record.response_digest, []).append(record)

    accepted: list[CanonicalEvidenceRecord] = []
    rejected: list[CanonicalEvidenceRecord] = []
    for key in sorted(grouped):
        variants = grouped[key]
        if len(variants) != 1:
            for copies in variants.values():
                rejected.extend(copies)
            continue
        copies = next(iter(variants.values()))
        record = min(copies, key=lambda item: item.evidence_id)
        if record.schema_version != SCHEMA_VERSION:
            rejected.extend(copies)
        elif (
            record.delivery_height <= decision_height
            and record.effective_height < decision_height
        ):
            accepted.append(record)

    accepted.sort(key=_record_sort_key)
    rejected.sort(
        key=lambda item: (
            *item.challenge_key,
            item.response_digest,
            item.evidence_id,
        )
    )
    return tuple(accepted), tuple(rejected)


def canonical_cut(
    records: Iterable[CanonicalEvidenceRecord], *, decision_height: int
):
    return resolve_evidence(records, decision_height=decision_height)[0]


class RollingEvidenceRoot:
    """Deterministic accumulator for already-canonicalized records."""

    def __init__(self):
        self._root = _hash({"schema": SCHEMA_VERSION, "records": []})
        self._records = 0

    @property
    def records(self):
        return self._records

    @property
    def root(self):
        return self._root

    def append_batch(self, records: Iterable[CanonicalEvidenceRecord]):
        unique = {record.response_digest: record for record in records}
        if not unique:
            return self.root
        payload = [unique[key].canonical_payload() for key in sorted(unique)]
        self._root = _hash({"previous": self._root, "batch": payload})
        self._records += len(payload)
        return self.root


@dataclass(frozen=True)
class EvidenceCommitResult:
    accepted: tuple[CanonicalEvidenceRecord, ...]
    rejected: tuple[CanonicalEvidenceRecord, ...]
    replayed: tuple[CanonicalEvidenceRecord, ...]
    conflicts: tuple[CanonicalEvidenceRecord, ...]


class CanonicalEvidenceLog:
    """Stateful, cross-height, replay-safe canonical audit log."""

    def __init__(self):
        self._rolling = RollingEvidenceRoot()
        self._seen: dict[str, str] = {}

    @property
    def records(self):
        return self._rolling.records

    @property
    def root(self):
        return self._rolling.root

    @property
    def seen_challenges(self):
        return frozenset(self._seen)

    def commit(
        self,
        records: Iterable[CanonicalEvidenceRecord],
        *,
        decision_height: int,
    ) -> EvidenceCommitResult:
        accepted_batch, rejected = resolve_evidence(
            records, decision_height=decision_height
        )
        accepted: list[CanonicalEvidenceRecord] = []
        replayed: list[CanonicalEvidenceRecord] = []
        conflicts: list[CanonicalEvidenceRecord] = []
        for record in accepted_batch:
            previous = self._seen.get(record.challenge_id)
            if previous is None:
                self._seen[record.challenge_id] = record.response_digest
                accepted.append(record)
            elif previous == record.response_digest:
                replayed.append(record)
            else:
                conflicts.append(record)
        self._rolling.append_batch(accepted)
        return EvidenceCommitResult(
            tuple(accepted), tuple(rejected), tuple(replayed), tuple(conflicts)
        )


@dataclass(frozen=True)
class CanonicalRiskRecord:
    source_height: int
    risk_score: float
    risk_level: str
    risk_trigger: int
    event_digest: str
    status: str = "valid"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.source_height < 0 or not 0 <= float(self.risk_score) <= 1:
            raise ValueError("invalid risk record")
        if self.risk_level not in {"low", "medium", "high", "none"}:
            raise ValueError("invalid risk level")
        if self.risk_trigger not in {0, 1}:
            raise ValueError("invalid trigger")

    @property
    def digest(self):
        data = asdict(self)
        data["risk_score"] = format(float(self.risk_score), ".17g")
        return _hash(data)


def neutral_risk_record(source_height: int, event_digest: str = "none"):
    return CanonicalRiskRecord(
        max(0, source_height), 0.0, "none", 0, event_digest, "not-authorized"
    )


@dataclass(frozen=True)
class SeedProjectionCommitment:
    height: int
    root: str
    capability: AuthorityCapability
    phase: str = "committed-before-beacon"


@dataclass(frozen=True)
class SelectionCapability:
    seed: int
    purpose: str
    seed_projection_root: str
    beacon_digest: str
    authority: AuthorityCapability


@dataclass(frozen=True)
class AuditCapability:
    projection_root: str
    content_aware: bool
    authority: AuthorityCapability


@dataclass(frozen=True)
class RiskCapability:
    projection_root: str
    authority: AuthorityCapability


def recorded_seed_commitment(
    *, height: int, root: str
) -> SeedProjectionCommitment:
    """Rehydrate a previously recorded, pre-reveal projection commitment."""

    _validate_root(root, "seed projection root")
    capability = AuthorityCapability(
        source="recorded-Proj_seed",
        commitment=root,
        authority_scope=frozenset({AuthorityTarget.COMMITTEE_SEED}),
    )
    return SeedProjectionCommitment(height, root.lower(), capability)


@dataclass(frozen=True)
class ControlSnapshot:
    """Full archival envelope plus explicit least-authority projections."""

    height: int
    view: int
    audit_root: str
    risk_digest: str
    risk_trigger: int
    risk_status: str
    event_digest: str
    registry_root: str
    chain_id: str = CHAIN_ID
    policy_version: str = SCHEMA_VERSION

    @property
    def root(self):
        """Full archival commitment; never accepted by a control sink."""

        return _hash(asdict(self))

    def seed_projection(self):
        return {
            "schema": bytes.fromhex("72656361702d736565642d70726f6a656374696f6e2d7632").decode("ascii"),
            "chain_id": self.chain_id,
            "height": self.height,
            "audit_root": self.audit_root,
            "registry_root": self.registry_root,
            "policy_version": self.policy_version,
        }

    @property
    def seed_root(self):
        return _hash(self.seed_projection())

    def commit_seed_projection(self) -> SeedProjectionCommitment:
        root = self.seed_root
        capability = AuthorityCapability(
            source="Proj_seed",
            commitment=root,
            authority_scope=frozenset({AuthorityTarget.COMMITTEE_SEED}),
        )
        return SeedProjectionCommitment(self.height, root, capability)

    def risk_projection(self):
        return {
            "schema": bytes.fromhex("72656361702d7269736b2d70726f6a656374696f6e2d7632").decode("ascii"),
            "chain_id": self.chain_id,
            "height": self.height,
            "risk_digest": self.risk_digest,
            "risk_trigger": self.risk_trigger,
            "risk_status": self.risk_status,
            "event_digest": self.event_digest,
            "policy_version": self.policy_version,
        }

    @property
    def risk_root(self):
        return _hash(self.risk_projection())

    def risk_capability(self) -> RiskCapability:
        root = self.risk_root
        return RiskCapability(
            projection_root=root,
            authority=AuthorityCapability(
                source="Proj_risk",
                commitment=root,
                authority_scope=frozenset({
                    AuthorityTarget.EVENT_RISK,
                    AuthorityTarget.EXTENSION_GAMMA,
                    AuthorityTarget.EXTENSION_AUDIT_PLAN,
                }),
            ),
        )

    def audit_projection(self, *, content_aware: bool):
        projection = {
            "schema": bytes.fromhex("72656361702d61756469742d70726f6a656374696f6e2d7632").decode("ascii"),
            "chain_id": self.chain_id,
            "height": self.height,
            "audit_root": self.audit_root,
            "registry_root": self.registry_root,
            "policy_version": self.policy_version,
            "mode": "content-extension" if content_aware else "pure-core",
        }
        if content_aware:
            projection.update(
                risk_digest=self.risk_digest,
                risk_trigger=self.risk_trigger,
                risk_status=self.risk_status,
            )
        return projection

    def audit_capability(self, *, content_aware: bool) -> AuditCapability:
        root = _hash(self.audit_projection(content_aware=content_aware))
        target = (
            AuthorityTarget.EXTENSION_AUDIT_PLAN
            if content_aware
            else AuthorityTarget.CORE_AUDIT_PLAN
        )
        return AuditCapability(
            projection_root=root,
            content_aware=content_aware,
            authority=AuthorityCapability(
                source="Proj_audit,ext" if content_aware else "Proj_audit,core",
                commitment=root,
                authority_scope=frozenset({target}),
            ),
        )

    def audit_plan_root(self, *, content_aware: bool):
        """Compatibility alias for the audit-input projection commitment."""

        return self.audit_capability(
            content_aware=content_aware
        ).projection_root


def build_snapshot(
    *,
    height: int,
    view: int,
    audit_root: str,
    risk: CanonicalRiskRecord,
    registry_root: str,
    chain_id: str = CHAIN_ID,
):
    expected = max(0, height - 1)
    if risk.source_height != expected:
        risk = neutral_risk_record(expected, "slot-mismatch")
    return ControlSnapshot(
        height,
        view,
        audit_root,
        risk.digest,
        risk.risk_trigger,
        risk.status,
        risk.event_digest,
        registry_root,
        chain_id,
    )


def derive_committee_capability(
    *,
    beacon: str,
    seed_commitment: SeedProjectionCommitment,
    purpose: str,
) -> SelectionCapability:
    """Reveal randomness only after receiving a committed seed projection."""

    _validate_root(beacon, "beacon")
    if not isinstance(seed_commitment, SeedProjectionCommitment):
        raise TypeError(
            "a committed seed projection is required before beacon reveal"
        )
    require_authority(
        seed_commitment.capability, AuthorityTarget.COMMITTEE_SEED
    )
    if seed_commitment.phase != "committed-before-beacon":
        raise ValueError("seed projection was not frozen before beacon reveal")
    if purpose not in {"primary", "resample", "reputation-top"}:
        raise ValueError("invalid seed purpose")
    beacon_capability = AuthorityCapability(
        source="random-beacon",
        commitment=beacon.lower(),
        authority_scope=frozenset({AuthorityTarget.COMMITTEE_SEED}),
    )
    inherited = authority_meet(
        seed_commitment.capability.authority_scope,
        beacon_capability.authority_scope,
    )
    if AuthorityTarget.COMMITTEE_SEED not in inherited:
        raise PermissionError("seed derivation lost committee authority")
    material = {
        "schema": bytes.fromhex("72656361702d636f6d6d69747465652d736565642d7632").decode("ascii"),
        "beacon": beacon.lower(),
        "seed_projection_root": seed_commitment.root.lower(),
        "purpose": purpose,
    }
    digest = _hash(material)
    seed = (
        int.from_bytes(bytes.fromhex(digest)[:8], "big")
        & ((1 << 63) - 1)
    )
    authority = AuthorityCapability(
        source=f"committee-seed:{purpose}",
        commitment=digest,
        authority_scope=frozenset({AuthorityTarget.COMMITTEE_SEED}),
    )
    return SelectionCapability(
        seed=seed,
        purpose=purpose,
        seed_projection_root=seed_commitment.root,
        beacon_digest=beacon.lower(),
        authority=authority,
    )


def derive_committee_seed(
    *,
    beacon: str,
    seed_commitment: SeedProjectionCommitment,
    purpose: str,
):
    return derive_committee_capability(
        beacon=beacon,
        seed_commitment=seed_commitment,
        purpose=purpose,
    ).seed


def audit_plan_output_root(
    capability: AuditCapability,
    *,
    targets: Iterable[int],
    coverage: float,
) -> str:
    target = (
        AuthorityTarget.EXTENSION_AUDIT_PLAN
        if capability.content_aware
        else AuthorityTarget.CORE_AUDIT_PLAN
    )
    require_authority(capability.authority, target)
    if not 0 <= float(coverage) <= 1:
        raise ValueError("coverage outside [0,1]")
    return _hash({
        "schema": bytes.fromhex("72656361702d61756469742d706c616e2d6f75747075742d7631").decode("ascii"),
        "input_projection_root": capability.projection_root,
        "targets": sorted({int(item) for item in targets}),
        "coverage": format(float(coverage), ".17g"),
    })


def synthetic_frozen_beacon(*, experiment_seed: int, source_height: int) -> str:
    """Deterministic replay substitute; not a production unpredictability claim."""

    if experiment_seed < 0 or source_height < 0:
        raise ValueError("invalid synthetic beacon input")
    return _hash({
        "schema": bytes.fromhex("72656361702d73796e7468657469632d626561636f6e2d7632").decode("ascii"),
        "experiment_seed": experiment_seed,
        "source_height": source_height,
    })


@dataclass(frozen=True)
class CanonicalRegistryEntry:
    validator_id: int
    credential_digest: str
    correlation_domain: str
    eligible: bool
    registry_epoch: int
    configuration_digest: str

    def __post_init__(self) -> None:
        if self.validator_id < 0 or self.registry_epoch < 0:
            raise ValueError("invalid registry identity or epoch")
        if not self.correlation_domain:
            raise ValueError("correlation domain is required")
        _validate_root(self.credential_digest, "credential digest")
        _validate_root(self.configuration_digest, "configuration digest")

    def payload(self):
        return {
            "validator_id": self.validator_id,
            "credential_digest": self.credential_digest.lower(),
            "correlation_domain": self.correlation_domain,
            "eligible": bool(self.eligible),
            "registry_epoch": self.registry_epoch,
            "configuration_digest": self.configuration_digest.lower(),
        }


def registry_root(
    entries: Sequence[CanonicalRegistryEntry | Mapping]
):
    normalized = [
        entry
        if isinstance(entry, CanonicalRegistryEntry)
        else CanonicalRegistryEntry(**dict(entry))
        for entry in entries
    ]
    if not normalized:
        raise ValueError("registry cannot be empty")
    ids = [entry.validator_id for entry in normalized]
    if len(ids) != len(set(ids)):
        raise ValueError("validator identifiers must be unique")
    payload = [
        entry.payload()
        for entry in sorted(
            normalized, key=lambda item: item.validator_id
        )
    ]
    return _hash({"schema": bytes.fromhex("72656361702d72656769737472792d7632").decode("ascii"), "entries": payload})


def experiment_registry_entries(
    domains: Sequence[str],
    *,
    registry_epoch: int = 0,
    configuration: Mapping | None = None,
):
    """Build explicit deterministic registry entries for the frozen simulator."""

    configuration_digest = _hash({
        "schema": bytes.fromhex("72656361702d6578706572696d656e742d72656769737472792d636f6e66696775726174696f6e2d7631").decode("ascii"),
        "configuration": dict(configuration or {}),
    })
    return tuple(
        CanonicalRegistryEntry(
            validator_id=validator_id,
            credential_digest=_hash({
                "schema": bytes.fromhex("72656361702d73796e7468657469632d63726564656e7469616c2d7631").decode("ascii"),
                "validator_id": validator_id,
            }),
            correlation_domain=str(domain),
            eligible=True,
            registry_epoch=registry_epoch,
            configuration_digest=configuration_digest,
        )
        for validator_id, domain in enumerate(domains)
    )
