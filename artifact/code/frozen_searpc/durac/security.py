"""Explicit fault sampling and fair committee-security baselines.

This module is independent from the frozen CBTDS trust implementation.  It
models externally adjudicated Byzantine labels; consensus votes are never used
as truth labels.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import log
from random import Random
from typing import Hashable, Iterable, Mapping, Sequence

from .consensus import ValidatorCandidate


class CommitteeMethod(str, Enum):
    FIXED_FULL_CBTDS = "fixed_full_cbtds"
    UNIFORM_SIZE_MATCHED = "uniform_size_matched"
    REPUTATION_TOP_SIZE_MATCHED = "reputation_top_size_matched"
    POS_WEIGHTED_SIZE_MATCHED = "pos_weighted_size_matched"
    DURAC_RISK_PBFT = "durac_risk_pbft"


@dataclass(frozen=True)
class CommitteeSecurityOutcome:
    committee_size: int
    max_byzantine: int
    certificate_size: int
    actual_byzantine: int
    leader_byzantine: int
    safety_budget_breach: int
    illegal_block_accepted: int
    legal_first_round_commit: int
    legal_eventual_commit: int
    view_change: int


def _uniform(seed: int, event_id: str, validator_id: int, purpose: str) -> float:
    digest = sha256(
        f"{seed}|{event_id}|{validator_id}|{purpose}".encode("utf-8")
    ).digest()
    integer = int.from_bytes(digest, "big")
    return (integer + 1) / (2 ** (8 * len(digest)) + 1)


def _weighted_priority(
    candidate: ValidatorCandidate,
    *,
    seed: int,
    event_id: str,
    purpose: str,
    weighted: bool,
    minimum_weight: float = 0.05,
    maximum_weight: float = 0.80,
) -> tuple[float, int]:
    weight = (
        minimum_weight
        + (maximum_weight - minimum_weight) * candidate.honesty_lcb
        if weighted
        else 1.0
    )
    uniform = _uniform(seed, event_id, candidate.validator_id, purpose)
    return -log(uniform) / weight, candidate.validator_id


def select_size_matched_committee(
    candidates: Iterable[ValidatorCandidate],
    *,
    size: int,
    method: CommitteeMethod | str,
    seed: int,
    event_id: str,
) -> tuple[ValidatorCandidate, ...]:
    """Select a registered baseline committee with a caller-supplied size."""

    method = CommitteeMethod(method)
    pool = list(candidates)
    if len({candidate.validator_id for candidate in pool}) != len(pool):
        raise ValueError("validator identifiers must be unique")
    if not 1 <= size <= len(pool):
        raise ValueError("size must be within the candidate pool")
    if method is CommitteeMethod.DURAC_RISK_PBFT:
        raise ValueError("DURAC selection requires its chance constraint")
    if method is CommitteeMethod.FIXED_FULL_CBTDS:
        if size != len(pool):
            raise ValueError("fixed full CBTDS must use the complete pool")
        return tuple(sorted(pool, key=lambda candidate: candidate.validator_id))
    if method is CommitteeMethod.REPUTATION_TOP_SIZE_MATCHED:
        ordered = sorted(
            pool,
            key=lambda candidate: (-candidate.honesty_lcb, candidate.validator_id),
        )
    else:
        weighted = method is CommitteeMethod.POS_WEIGHTED_SIZE_MATCHED
        ordered = sorted(
            pool,
            key=lambda candidate: _weighted_priority(
                candidate,
                seed=seed,
                event_id=event_id,
                purpose="committee",
                weighted=weighted,
            ),
        )
    return tuple(ordered[:size])


def select_committee_leader(
    committee: Sequence[ValidatorCandidate],
    *,
    seed: int,
    event_id: str,
    reputation_weighted: bool,
) -> ValidatorCandidate:
    if not committee:
        raise ValueError("committee cannot be empty")
    return min(
        committee,
        key=lambda candidate: _weighted_priority(
            candidate,
            seed=seed,
            event_id=event_id,
            purpose="leader",
            weighted=reputation_weighted,
        ),
    )


def sample_byzantine_ids(
    candidates: Iterable[ValidatorCandidate],
    *,
    seed: int,
    true_honesty: Mapping[int, float],
    domain_compromise_probability: Mapping[Hashable, float] | None = None,
    forced_byzantine_ids: Iterable[int] = (),
) -> frozenset[int]:
    """Sample domain-correlated and independent faults once for one block."""

    pool = list(candidates)
    pool_ids = {candidate.validator_id for candidate in pool}
    if set(true_honesty) != pool_ids:
        raise ValueError("true_honesty must contain every candidate exactly once")
    if any(not 0.0 <= probability <= 1.0 for probability in true_honesty.values()):
        raise ValueError("true honesty probabilities must be in [0, 1]")
    forced = set(forced_byzantine_ids)
    if not forced <= pool_ids:
        raise ValueError("forced Byzantine id outside candidate pool")
    domain_probabilities = domain_compromise_probability or {}
    domains = sorted({candidate.domain for candidate in pool}, key=str)
    if any(
        not 0.0 <= float(domain_probabilities.get(domain, 0.0)) <= 1.0
        for domain in domains
    ):
        raise ValueError("domain compromise probabilities must be in [0, 1]")

    rng = Random(seed)
    compromised_domains = {
        domain
        for domain in domains
        if rng.random() < float(domain_probabilities.get(domain, 0.0))
    }
    byzantine = set(forced)
    for candidate in sorted(pool, key=lambda item: item.validator_id):
        if candidate.domain in compromised_domains:
            byzantine.add(candidate.validator_id)
        elif candidate.validator_id not in byzantine:
            if rng.random() > true_honesty[candidate.validator_id]:
                byzantine.add(candidate.validator_id)
    return frozenset(byzantine)


def evaluate_committee_security(
    committee: Sequence[ValidatorCandidate],
    *,
    leader_id: int,
    byzantine_ids: Iterable[int],
) -> CommitteeSecurityOutcome:
    """Evaluate the registered silent-on-legal/sign-on-illegal attack policy."""

    if not committee:
        raise ValueError("committee cannot be empty")
    member_ids = {candidate.validator_id for candidate in committee}
    if len(member_ids) != len(committee):
        raise ValueError("committee identifiers must be unique")
    if leader_id not in member_ids:
        raise ValueError("leader must be a committee member")
    byzantine_set = set(byzantine_ids)
    byzantine_count = len(member_ids & byzantine_set)
    committee_size = len(committee)
    max_byzantine = (committee_size - 1) // 3
    certificate_size = 2 * max_byzantine + 1
    honest_count = committee_size - byzantine_count
    leader_byzantine = int(leader_id in byzantine_set)
    legal_quorum = honest_count >= certificate_size
    return CommitteeSecurityOutcome(
        committee_size=committee_size,
        max_byzantine=max_byzantine,
        certificate_size=certificate_size,
        actual_byzantine=byzantine_count,
        leader_byzantine=leader_byzantine,
        safety_budget_breach=int(byzantine_count > max_byzantine),
        illegal_block_accepted=int(
            leader_byzantine and byzantine_count >= certificate_size
        ),
        legal_first_round_commit=int(not leader_byzantine and legal_quorum),
        legal_eventual_commit=int(legal_quorum),
        view_change=leader_byzantine,
    )
