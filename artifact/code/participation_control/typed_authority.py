"""Executable evidence-authority capabilities for SEARPC participation control.

The authority model is deliberately sink-oriented. A hash, serialization, or
wrapper may preserve authority but can never add a new target. Runtime sinks
therefore accept an ``AuthorityCapability`` and reject raw roots or records.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class EvidenceKind(str, Enum):
    MESSAGE_RISK = "message_risk"
    DATA_ADJUDICATION = "data_adjudication"
    OPINION_ADJUDICATION = "opinion_adjudication"
    VALIDATOR_AUDIT = "validator_audit"
    CONTENT_RISK = "content_risk"
    REGISTRY = "registry"
    POLICY = "policy"
    RANDOM_BEACON = "random_beacon"
    HIDDEN_LABEL = "hidden_label"
    EXTERNAL_EVENT_LABEL = "external_event_label"
    FAST_HINT = "fast_hint"


class AuthorityTarget(str, Enum):
    EVENT_RISK = "event_risk"
    DATA_ROLE_STATE = "data_role_state"
    OPINION_ROLE_STATE = "opinion_role_state"
    CORE_PARTICIPATION_FSM = "core_participation_fsm"
    COMMITTEE_SEED = "committee_seed"
    CORE_AUDIT_PLAN = "core_audit_plan"
    EXTENSION_GAMMA = "extension_gamma"
    EXTENSION_AUDIT_PLAN = "extension_audit_plan"
    PARTICIPATION_METADATA = "participation_metadata"
    FINAL_QUORUM = "final_quorum"
    FINAL_LOCK = "final_lock"
    VIEW_CHANGE = "view_change"
    COMMIT = "commit"


@dataclass(frozen=True)
class EvidenceType:
    role: str
    provenance_scope: str
    visibility_scope: str
    authority_scope: frozenset[AuthorityTarget]


@dataclass(frozen=True)
class AuthorityCapability:
    """An API token for one or more explicitly named authority sinks."""

    source: str
    commitment: str
    authority_scope: frozenset[AuthorityTarget]

    def __post_init__(self) -> None:
        if not self.source:
            raise ValueError("capability source is required")
        if len(self.commitment) != 64:
            raise ValueError("capability commitment must be a SHA-256 digest")
        try:
            int(self.commitment, 16)
        except ValueError as exc:
            raise ValueError("capability commitment must be hexadecimal") from exc


_ALLOWED: dict[EvidenceKind, frozenset[AuthorityTarget]] = {
    EvidenceKind.MESSAGE_RISK: frozenset({AuthorityTarget.EVENT_RISK}),
    EvidenceKind.DATA_ADJUDICATION: frozenset({AuthorityTarget.DATA_ROLE_STATE}),
    EvidenceKind.OPINION_ADJUDICATION: frozenset({AuthorityTarget.OPINION_ROLE_STATE}),
    EvidenceKind.VALIDATOR_AUDIT: frozenset({
        AuthorityTarget.CORE_PARTICIPATION_FSM,
        AuthorityTarget.COMMITTEE_SEED,
        AuthorityTarget.CORE_AUDIT_PLAN,
    }),
    EvidenceKind.CONTENT_RISK: frozenset({
        AuthorityTarget.EVENT_RISK,
        AuthorityTarget.EXTENSION_GAMMA,
        AuthorityTarget.EXTENSION_AUDIT_PLAN,
    }),
    EvidenceKind.REGISTRY: frozenset({
        AuthorityTarget.COMMITTEE_SEED,
        AuthorityTarget.CORE_AUDIT_PLAN,
        AuthorityTarget.EXTENSION_AUDIT_PLAN,
    }),
    EvidenceKind.POLICY: frozenset({
        AuthorityTarget.COMMITTEE_SEED,
        AuthorityTarget.CORE_AUDIT_PLAN,
        AuthorityTarget.EXTENSION_GAMMA,
        AuthorityTarget.EXTENSION_AUDIT_PLAN,
    }),
    EvidenceKind.RANDOM_BEACON: frozenset({AuthorityTarget.COMMITTEE_SEED}),
    EvidenceKind.HIDDEN_LABEL: frozenset(),
    EvidenceKind.EXTERNAL_EVENT_LABEL: frozenset(),
    EvidenceKind.FAST_HINT: frozenset({AuthorityTarget.PARTICIPATION_METADATA}),
}


def can_write(kind: EvidenceKind | str, target: AuthorityTarget | str) -> bool:
    return AuthorityTarget(target) in _ALLOWED[EvidenceKind(kind)]


def allowed_targets(kind: EvidenceKind | str) -> frozenset[AuthorityTarget]:
    return _ALLOWED[EvidenceKind(kind)]


def authority_meet(*scopes: Iterable[AuthorityTarget | str]) -> frozenset[AuthorityTarget]:
    """Return the non-escalating intersection inherited by a derived value."""

    normalized = [frozenset(AuthorityTarget(item) for item in scope) for scope in scopes]
    if not normalized:
        return frozenset()
    inherited = normalized[0]
    for scope in normalized[1:]:
        inherited = inherited.intersection(scope)
    return frozenset(inherited)


def require_authority(
    capability: AuthorityCapability, target: AuthorityTarget | str
) -> AuthorityCapability:
    """Fail closed unless ``capability`` explicitly authorizes ``target``."""

    if not isinstance(capability, AuthorityCapability):
        raise TypeError("an AuthorityCapability is required")
    normalized = AuthorityTarget(target)
    if normalized not in capability.authority_scope:
        raise PermissionError(
            f"{capability.source!r} cannot write authority sink {normalized.value!r}"
        )
    return capability
