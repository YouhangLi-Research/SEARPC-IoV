"""Safety-decoupled fast committee with full-set finality and PBFT fallback."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import ceil
from typing import Iterable, Sequence

from .consensus import RiskLevel, ValidatorCandidate, pbft_protocol_message_count
from .security import evaluate_committee_security, select_committee_leader


FAST_COMMITTEE_SIZES = {
    RiskLevel.LOW: 13,
    RiskLevel.MEDIUM: 19,
    RiskLevel.HIGH: 25,
}


class ConsensusPath(str, Enum):
    FAST = "fast"
    FAST_THEN_FALLBACK = "fast_then_fallback"
    FULL_FALLBACK = "full_fallback"
    REFUSED = "refused"


@dataclass(frozen=True)
class DualPathOutcome:
    risk_level: str
    path: str
    fast_committee_size: int
    fast_member_ids: tuple[int, ...]
    fast_max_byzantine: int
    fast_actual_byzantine: int
    fast_safety_budget_breach: int
    fast_illegal_proposal: int
    full_committee_size: int
    full_certificate_size: int
    full_actual_byzantine: int
    final_illegal_block_accepted: int
    final_legal_eventual_commit: int
    final_refusal: int
    fallback_triggered: int
    protocol_message_count: int


def _priority(candidate: ValidatorCandidate, *, seed: int, event_id: str) -> bytes:
    return sha256(
        f"{seed}|{event_id}|{candidate.validator_id}|fast-member".encode("utf-8")
    ).digest()


def select_diverse_random_committee(
    candidates: Iterable[ValidatorCandidate],
    *,
    size: int,
    seed: int,
    event_id: str,
    domain_seat_fraction: float = 0.40,
) -> tuple[ValidatorCandidate, ...]:
    """Verifiable uniform ordering with a registered domain seat cap."""

    pool = list(candidates)
    if len({candidate.validator_id for candidate in pool}) != len(pool):
        raise ValueError("validator identifiers must be unique")
    if not 1 <= size <= len(pool):
        raise ValueError("size must be within the candidate pool")
    if not 0.0 < domain_seat_fraction <= 1.0:
        raise ValueError("domain_seat_fraction must be in (0, 1]")
    limit = ceil(domain_seat_fraction * size)
    ordered = sorted(
        pool,
        key=lambda candidate: (
            _priority(candidate, seed=seed, event_id=event_id),
            candidate.validator_id,
        ),
    )
    selected: list[ValidatorCandidate] = []
    seats: Counter = Counter()
    for candidate in ordered:
        if seats[candidate.domain] >= limit:
            continue
        selected.append(candidate)
        seats[candidate.domain] += 1
        if len(selected) == size:
            return tuple(selected)
    raise ValueError("domain cap prevents the requested committee size")


def _full_outcome(
    registered: Sequence[ValidatorCandidate],
    *,
    byzantine_ids: Iterable[int],
    seed: int,
    event_id: str,
):
    leader = select_committee_leader(
        registered,
        seed=seed,
        event_id=event_id,
        reputation_weighted=True,
    )
    return evaluate_committee_security(
        registered,
        leader_id=leader.validator_id,
        byzantine_ids=byzantine_ids,
    )


def execute_dual_path_consensus(
    active_candidates: Iterable[ValidatorCandidate],
    registered_candidates: Iterable[ValidatorCandidate],
    *,
    risk_level: RiskLevel | str,
    byzantine_ids: Iterable[int],
    seed: int,
    event_id: str,
    direct_fallback: bool = False,
) -> DualPathOutcome:
    """Execute the registered v2 safety guard and fallback policy."""

    risk_level = RiskLevel(risk_level)
    active = list(active_candidates)
    registered = sorted(
        registered_candidates, key=lambda candidate: candidate.validator_id
    )
    registered_ids = {candidate.validator_id for candidate in registered}
    if len(registered_ids) != len(registered):
        raise ValueError("registered validator identifiers must be unique")
    if not {candidate.validator_id for candidate in active} <= registered_ids:
        raise ValueError("active candidates must belong to the registered set")
    if not registered:
        raise ValueError("registered validator set cannot be empty")

    byzantine = set(byzantine_ids)
    full_size = len(registered)
    full_f = (full_size - 1) // 3
    full_certificate = 2 * full_f + 1
    full_actual = len(registered_ids & byzantine)
    fast_size = FAST_COMMITTEE_SIZES[risk_level]

    if direct_fallback or len(active) < fast_size:
        full = _full_outcome(
            registered,
            byzantine_ids=byzantine,
            seed=seed + 11,
            event_id=f"{event_id}|full",
        )
        return DualPathOutcome(
            risk_level=risk_level.value,
            path=(
                ConsensusPath.FULL_FALLBACK.value
                if full.legal_eventual_commit or full.illegal_block_accepted
                else ConsensusPath.REFUSED.value
            ),
            fast_committee_size=0,
            fast_member_ids=(),
            fast_max_byzantine=0,
            fast_actual_byzantine=0,
            fast_safety_budget_breach=0,
            fast_illegal_proposal=0,
            full_committee_size=full_size,
            full_certificate_size=full_certificate,
            full_actual_byzantine=full_actual,
            final_illegal_block_accepted=full.illegal_block_accepted,
            final_legal_eventual_commit=full.legal_eventual_commit,
            final_refusal=int(
                not full.legal_eventual_commit and not full.illegal_block_accepted
            ),
            fallback_triggered=1,
            protocol_message_count=pbft_protocol_message_count(full_size),
        )

    fast = select_diverse_random_committee(
        active,
        size=fast_size,
        seed=seed,
        event_id=event_id,
    )
    fast_leader = select_committee_leader(
        fast,
        seed=seed + 7,
        event_id=f"{event_id}|fast-leader",
        reputation_weighted=True,
    )
    fast_result = evaluate_committee_security(
        fast,
        leader_id=fast_leader.validator_id,
        byzantine_ids=byzantine,
    )
    full_honest = full_size - full_actual
    full_finality_available = full_honest >= full_certificate
    fast_success = bool(
        fast_result.legal_eventual_commit and full_finality_available
    )
    fast_messages = pbft_protocol_message_count(fast_size) + 2 * full_size

    if fast_success:
        return DualPathOutcome(
            risk_level=risk_level.value,
            path=ConsensusPath.FAST.value,
            fast_committee_size=fast_size,
            fast_member_ids=tuple(item.validator_id for item in fast),
            fast_max_byzantine=fast_result.max_byzantine,
            fast_actual_byzantine=fast_result.actual_byzantine,
            fast_safety_budget_breach=fast_result.safety_budget_breach,
            fast_illegal_proposal=fast_result.illegal_block_accepted,
            full_committee_size=full_size,
            full_certificate_size=full_certificate,
            full_actual_byzantine=full_actual,
            final_illegal_block_accepted=0,
            final_legal_eventual_commit=1,
            final_refusal=0,
            fallback_triggered=0,
            protocol_message_count=fast_messages,
        )

    full = _full_outcome(
        registered,
        byzantine_ids=byzantine,
        seed=seed + 11,
        event_id=f"{event_id}|full",
    )
    final_refusal = int(
        not full.legal_eventual_commit and not full.illegal_block_accepted
    )
    return DualPathOutcome(
        risk_level=risk_level.value,
        path=(
            ConsensusPath.FAST_THEN_FALLBACK.value
            if not final_refusal
            else ConsensusPath.REFUSED.value
        ),
        fast_committee_size=fast_size,
        fast_member_ids=tuple(item.validator_id for item in fast),
        fast_max_byzantine=fast_result.max_byzantine,
        fast_actual_byzantine=fast_result.actual_byzantine,
        fast_safety_budget_breach=fast_result.safety_budget_breach,
        fast_illegal_proposal=fast_result.illegal_block_accepted,
        full_committee_size=full_size,
        full_certificate_size=full_certificate,
        full_actual_byzantine=full_actual,
        final_illegal_block_accepted=full.illegal_block_accepted,
        final_legal_eventual_commit=full.legal_eventual_commit,
        final_refusal=final_refusal,
        fallback_triggered=1,
        protocol_message_count=(
            fast_messages + pbft_protocol_message_count(full_size)
        ),
    )
