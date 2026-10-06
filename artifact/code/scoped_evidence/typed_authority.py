"""Formalized evidence-authority relation for SEARPC scoped evidence."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EvidenceKind(str, Enum):
    MESSAGE_RISK = "message_risk"
    DATA_ADJUDICATION = "data_adjudication"
    OPINION_ADJUDICATION = "opinion_adjudication"
    VALIDATOR_AUDIT = "validator_audit"
    CONTENT_RISK = "content_risk"
    HIDDEN_LABEL = "hidden_label"
    FAST_HINT = "fast_hint"


class AuthorityTarget(str, Enum):
    EVENT_RISK = "event_risk"
    DATA_ROLE_STATE = "data_role_state"
    OPINION_ROLE_STATE = "opinion_role_state"
    VALIDATOR_ADMISSION = "validator_admission"
    AUDIT_POLICY = "audit_policy"
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


_ALLOWED: dict[EvidenceKind, frozenset[AuthorityTarget]] = {
    EvidenceKind.MESSAGE_RISK: frozenset({AuthorityTarget.EVENT_RISK}),
    EvidenceKind.DATA_ADJUDICATION: frozenset({AuthorityTarget.DATA_ROLE_STATE}),
    EvidenceKind.OPINION_ADJUDICATION: frozenset({AuthorityTarget.OPINION_ROLE_STATE}),
    EvidenceKind.VALIDATOR_AUDIT: frozenset({AuthorityTarget.VALIDATOR_ADMISSION, AuthorityTarget.AUDIT_POLICY}),
    EvidenceKind.CONTENT_RISK: frozenset({AuthorityTarget.AUDIT_POLICY, AuthorityTarget.PARTICIPATION_METADATA}),
    EvidenceKind.HIDDEN_LABEL: frozenset(),
    EvidenceKind.FAST_HINT: frozenset({AuthorityTarget.PARTICIPATION_METADATA}),
}


def can_write(kind: EvidenceKind | str, target: AuthorityTarget | str) -> bool:
    return AuthorityTarget(target) in _ALLOWED[EvidenceKind(kind)]


def allowed_targets(kind: EvidenceKind | str) -> frozenset[AuthorityTarget]:
    return _ALLOWED[EvidenceKind(kind)]
