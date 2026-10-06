"""Fair certified-committee baselines and finality fault injection.

This module is independent from the frozen CBTDS trust implementation and does
not alter the frozen DURAC v2 executor.  It exists to compare the v2
architecture with size-matched committee-selection baselines under one common
certificate and fallback policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from typing import Iterable, Sequence

from .consensus import ValidatorCandidate, pbft_protocol_message_count
from .dual_path import select_diverse_random_committee
from .security import (
    CommitteeMethod,
    select_committee_leader,
    select_size_matched_committee,
)


class CertifiedSelection(str, Enum):
    DIVERSE_UNIFORM = "diverse_uniform"
    UNIFORM = "uniform"
    REPUTATION_TOP = "reputation_top"
    POS_WEIGHTED = "pos_weighted"


@dataclass(frozen=True)
class CertifiedConsensusOutcome:
    selection: str
    path: str
    committee_size: int
    member_ids: tuple[int, ...]
    leader_id: int
    actual_byzantine: int
    max_byzantine: int
    safety_budget_breach: int
    fast_illegal_proposal: int
    certificate_available: int
    collector_fault: int
    fallback_triggered: int
    final_legal_eventual_commit: int
    final_illegal_block_accepted: int
    final_refusal: int
    protocol_message_count: int
    primary_collector_id: int = -1
    backup_collector_id: int = -1
    backup_collector_attempted: int = 0
    backup_collector_fault: int = 0
    backup_certificate_available: int = 0
    certificate_collector: str = "none"


@dataclass(frozen=True)
class CollectorPair:
    primary_id: int
    backup_id: int
    primary_domain: object
    backup_domain: object


def _collector_priority(
    candidate: ValidatorCandidate, *, seed: int, event_id: str
) -> bytes:
    return sha256(
        f"{seed}|{event_id}|{candidate.validator_id}|collector".encode("utf-8")
    ).digest()


def select_cross_domain_collectors(
    candidates: Iterable[ValidatorCandidate], *, seed: int, event_id: str
) -> CollectorPair:
    """Select a rotating primary and a cross-domain backup deterministically."""

    pool = list(candidates)
    if len(pool) < 2:
        raise ValueError("at least two registered collectors are required")
    if len({candidate.validator_id for candidate in pool}) != len(pool):
        raise ValueError("collector identifiers must be unique")
    ordered = sorted(
        pool,
        key=lambda candidate: (
            _collector_priority(candidate, seed=seed, event_id=event_id),
            candidate.validator_id,
        ),
    )
    primary = ordered[0]
    backup = next(
        (
            candidate
            for candidate in ordered[1:]
            if candidate.domain != primary.domain
        ),
        ordered[1],
    )
    return CollectorPair(
        primary_id=primary.validator_id,
        backup_id=backup.validator_id,
        primary_domain=primary.domain,
        backup_domain=backup.domain,
    )


def basic_hotstuff_message_count(
    num_validators: int, *, failed_leader_views: int = 0
) -> int:
    """Registered Basic HotStuff transmission proxy from the detector baselines spec."""

    if num_validators < 1:
        raise ValueError("num_validators must be positive")
    if failed_leader_views < 0:
        raise ValueError("failed_leader_views must be non-negative")
    followers = num_validators - 1
    return 7 * followers + failed_leader_views * 2 * followers


def _select(
    candidates: Sequence[ValidatorCandidate],
    *,
    size: int,
    selection: CertifiedSelection,
    seed: int,
    event_id: str,
) -> tuple[ValidatorCandidate, ...]:
    if selection is CertifiedSelection.DIVERSE_UNIFORM:
        return select_diverse_random_committee(
            candidates,
            size=size,
            seed=seed,
            event_id=event_id,
        )
    method = {
        CertifiedSelection.UNIFORM: CommitteeMethod.UNIFORM_SIZE_MATCHED,
        CertifiedSelection.REPUTATION_TOP: (
            CommitteeMethod.REPUTATION_TOP_SIZE_MATCHED
        ),
        CertifiedSelection.POS_WEIGHTED: CommitteeMethod.POS_WEIGHTED_SIZE_MATCHED,
    }[selection]
    return select_size_matched_committee(
        candidates,
        size=size,
        method=method,
        seed=seed,
        event_id=event_id,
    )


def execute_certified_committee_consensus(
    candidates: Iterable[ValidatorCandidate],
    registered_candidates: Iterable[ValidatorCandidate],
    *,
    size: int,
    selection: CertifiedSelection | str,
    byzantine_ids: Iterable[int],
    seed: int,
    event_id: str,
    leader_reputation_weighted: bool,
    use_full_certificate: bool = True,
    fallback_enabled: bool = True,
    collector_available: bool = True,
    collector_withholds: bool = False,
    backup_collector_enabled: bool = False,
    backup_collector_available: bool = True,
    backup_collector_withholds: bool = False,
    unavailable_ids: Iterable[int] = (),
) -> CertifiedConsensusOutcome:
    """Execute one size-matched path under shared finality assumptions.

    Byzantine validators are conservatively allowed to withhold legal votes.
    Honest online validators sign legal digests only.  Byzantine collectors
    can withhold but cannot forge their signatures.  When enabled, one backup
    collector retries the same digest-bound signed shares before full PBFT.
    """

    selection = CertifiedSelection(selection)
    pool = list(candidates)
    registered = sorted(
        registered_candidates, key=lambda candidate: candidate.validator_id
    )
    registered_ids = {candidate.validator_id for candidate in registered}
    if not registered:
        raise ValueError("registered validator set cannot be empty")
    if len(registered_ids) != len(registered):
        raise ValueError("registered validator identifiers must be unique")
    if not {candidate.validator_id for candidate in pool} <= registered_ids:
        raise ValueError("candidates must belong to the registered set")
    if size < 1:
        raise ValueError("size must be positive")

    collectors = (
        select_cross_domain_collectors(
            registered,
            seed=seed + 17,
            event_id=f"{event_id}|collectors",
        )
        if backup_collector_enabled
        else None
    )

    byzantine = set(byzantine_ids)
    unavailable = set(unavailable_ids)
    if not byzantine <= registered_ids or not unavailable <= registered_ids:
        raise ValueError("fault identifiers must belong to the registered set")

    if len(pool) < size:
        online_ids = registered_ids - unavailable
        online_byzantine = byzantine & online_ids
        online_honest = online_ids - byzantine
        full_f = (len(registered) - 1) // 3
        full_certificate = 2 * full_f + 1
        full_legal = len(online_honest) >= full_certificate
        full_illegal = len(online_byzantine) >= full_certificate
        if not fallback_enabled:
            full_legal = False
            full_illegal = False
        refusal = int(not full_legal and not full_illegal)
        return CertifiedConsensusOutcome(
            selection=selection.value,
            path="direct_fallback" if not refusal else "refused",
            committee_size=0,
            member_ids=(),
            leader_id=-1,
            actual_byzantine=0,
            max_byzantine=0,
            safety_budget_breach=0,
            fast_illegal_proposal=0,
            certificate_available=0,
            collector_fault=int(not collector_available or collector_withholds),
            fallback_triggered=int(fallback_enabled),
            final_legal_eventual_commit=int(full_legal),
            final_illegal_block_accepted=int(full_illegal),
            final_refusal=refusal,
            protocol_message_count=(
                pbft_protocol_message_count(len(registered))
                if fallback_enabled
                else 0
            ),
        )

    committee = _select(
        pool,
        size=size,
        selection=selection,
        seed=seed,
        event_id=event_id,
    )
    leader = select_committee_leader(
        committee,
        seed=seed + 7,
        event_id=f"{event_id}|leader",
        reputation_weighted=leader_reputation_weighted,
    )
    member_ids = {candidate.validator_id for candidate in committee}
    online_ids = registered_ids - unavailable
    online_byzantine = byzantine & online_ids
    online_honest = online_ids - byzantine

    fast_f = (size - 1) // 3
    fast_certificate = 2 * fast_f + 1
    fast_byzantine = len(member_ids & byzantine)
    fast_online_byzantine = len(member_ids & online_byzantine)
    fast_online_honest = len(member_ids & online_honest)
    fast_illegal = int(
        leader.validator_id in online_byzantine
        and fast_online_byzantine >= fast_certificate
    )
    fast_legal = fast_online_honest >= fast_certificate

    full_size = len(registered)
    full_f = (full_size - 1) // 3
    full_certificate = 2 * full_f + 1
    primary_collector_fault = int(
        not collector_available or collector_withholds
    )
    primary_certificate_available = int(
        use_full_certificate
        and fast_legal
        and collector_available
        and not collector_withholds
        and len(online_honest) >= full_certificate
    )
    backup_collector_attempted = int(
        use_full_certificate
        and backup_collector_enabled
        and primary_collector_fault
    )
    backup_collector_fault = int(
        backup_collector_attempted
        and (
            not backup_collector_available
            or backup_collector_withholds
        )
    )
    backup_certificate_available = int(
        backup_collector_attempted
        and fast_legal
        and backup_collector_available
        and not backup_collector_withholds
        and len(online_honest) >= full_certificate
    )
    certificate_available = int(
        primary_certificate_available or backup_certificate_available
    )
    certificate_collector = (
        "primary"
        if primary_certificate_available
        else "backup"
        if backup_certificate_available
        else "none"
    )
    fast_messages = pbft_protocol_message_count(size)
    if use_full_certificate:
        # The timeout path is charged after request/vote traffic, even when the
        # collector later withholds the certificate.
        fast_messages += 2 * full_size
        if backup_collector_attempted:
            # Timeout/retry request plus retransmission of digest-bound shares.
            fast_messages += 2 * full_size

    collector_fields = {
        "primary_collector_id": (
            collectors.primary_id if collectors is not None else -1
        ),
        "backup_collector_id": (
            collectors.backup_id if collectors is not None else -1
        ),
        "backup_collector_attempted": backup_collector_attempted,
        "backup_collector_fault": backup_collector_fault,
        "backup_certificate_available": backup_certificate_available,
        "certificate_collector": certificate_collector,
    }

    if not use_full_certificate and (fast_legal or fast_illegal):
        return CertifiedConsensusOutcome(
            selection=selection.value,
            path="fast_uncertified",
            committee_size=size,
            member_ids=tuple(candidate.validator_id for candidate in committee),
            leader_id=leader.validator_id,
            actual_byzantine=fast_byzantine,
            max_byzantine=fast_f,
            safety_budget_breach=int(fast_byzantine > fast_f),
            fast_illegal_proposal=fast_illegal,
            certificate_available=0,
            collector_fault=primary_collector_fault,
            fallback_triggered=0,
            final_legal_eventual_commit=int(fast_legal and not fast_illegal),
            final_illegal_block_accepted=fast_illegal,
            final_refusal=0,
            protocol_message_count=fast_messages,
            **collector_fields,
        )

    if certificate_available:
        return CertifiedConsensusOutcome(
            selection=selection.value,
            path=(
                "fast_certified_backup"
                if backup_certificate_available
                else "fast_certified"
            ),
            committee_size=size,
            member_ids=tuple(candidate.validator_id for candidate in committee),
            leader_id=leader.validator_id,
            actual_byzantine=fast_byzantine,
            max_byzantine=fast_f,
            safety_budget_breach=int(fast_byzantine > fast_f),
            fast_illegal_proposal=fast_illegal,
            certificate_available=1,
            collector_fault=primary_collector_fault,
            fallback_triggered=0,
            final_legal_eventual_commit=1,
            final_illegal_block_accepted=0,
            final_refusal=0,
            protocol_message_count=fast_messages,
            **collector_fields,
        )

    if not fallback_enabled:
        return CertifiedConsensusOutcome(
            selection=selection.value,
            path="refused",
            committee_size=size,
            member_ids=tuple(candidate.validator_id for candidate in committee),
            leader_id=leader.validator_id,
            actual_byzantine=fast_byzantine,
            max_byzantine=fast_f,
            safety_budget_breach=int(fast_byzantine > fast_f),
            fast_illegal_proposal=fast_illegal,
            certificate_available=0,
            collector_fault=primary_collector_fault,
            fallback_triggered=0,
            final_legal_eventual_commit=0,
            final_illegal_block_accepted=0,
            final_refusal=1,
            protocol_message_count=fast_messages,
            **collector_fields,
        )

    full_legal = len(online_honest) >= full_certificate
    full_illegal = len(online_byzantine) >= full_certificate
    final_refusal = int(not full_legal and not full_illegal)
    return CertifiedConsensusOutcome(
        selection=selection.value,
        path="fast_then_fallback" if not final_refusal else "refused",
        committee_size=size,
        member_ids=tuple(candidate.validator_id for candidate in committee),
        leader_id=leader.validator_id,
        actual_byzantine=fast_byzantine,
        max_byzantine=fast_f,
        safety_budget_breach=int(fast_byzantine > fast_f),
        fast_illegal_proposal=fast_illegal,
        certificate_available=0,
        collector_fault=primary_collector_fault,
        fallback_triggered=1,
        final_legal_eventual_commit=int(full_legal),
        final_illegal_block_accepted=int(full_illegal),
        final_refusal=final_refusal,
        protocol_message_count=(
            fast_messages + pbft_protocol_message_count(full_size)
        ),
        **collector_fields,
    )
