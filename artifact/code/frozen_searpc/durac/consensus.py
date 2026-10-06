"""Risk-constrained, domain-diverse PBFT committee selection for DURAC-IoV."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import ceil, log
from typing import Hashable, Iterable, Mapping, Sequence


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RISK_BUDGETS = {
    RiskLevel.LOW: 0.05,
    RiskLevel.MEDIUM: 0.01,
    RiskLevel.HIGH: 0.001,
}


class UnsafeCommitteeError(RuntimeError):
    """Raised when no available committee meets the requested safety budget."""


@dataclass(frozen=True)
class ValidatorCandidate:
    validator_id: int
    honesty_lcb: float
    domain: Hashable
    latency_ms: float = 0.0

    def __post_init__(self) -> None:
        if self.validator_id < 0:
            raise ValueError("validator_id must be non-negative")
        if not 0.0 <= self.honesty_lcb <= 1.0:
            raise ValueError("honesty_lcb must be in [0, 1]")
        if self.latency_ms < 0.0:
            raise ValueError("latency_ms must be non-negative")


@dataclass(frozen=True)
class CommitteeSelection:
    risk_level: str
    failure_budget: float
    estimated_failure_probability: float
    committee_size: int
    max_byzantine: int
    member_ids: tuple[int, ...]
    represented_domains: int
    maximum_domain_seats: int
    protocol_message_count: int
    mean_latency_ms: float


def _convolve(first: Sequence[float], second: Sequence[float]) -> list[float]:
    output = [0.0] * (len(first) + len(second) - 1)
    for first_count, first_probability in enumerate(first):
        for second_count, second_probability in enumerate(second):
            output[first_count + second_count] += (
                first_probability * second_probability
            )
    return output


def _independent_distribution(failure_probabilities: Sequence[float]) -> list[float]:
    distribution = [1.0]
    for probability in failure_probabilities:
        distribution = _convolve(distribution, [1.0 - probability, probability])
    return distribution


def committee_failure_probability(
    committee: Sequence[ValidatorCandidate],
    domain_compromise_probability: Mapping[Hashable, float] | None = None,
) -> float:
    if len(committee) < 1:
        raise ValueError("committee cannot be empty")
    domain_probabilities = domain_compromise_probability or {}
    grouped: dict[Hashable, list[ValidatorCandidate]] = defaultdict(list)
    for candidate in committee:
        grouped[candidate.domain].append(candidate)

    total_distribution = [1.0]
    for domain, members in grouped.items():
        compromise_probability = float(domain_probabilities.get(domain, 0.0))
        if not 0.0 <= compromise_probability <= 1.0:
            raise ValueError("domain compromise probability must be in [0, 1]")
        independent = _independent_distribution(
            [1.0 - member.honesty_lcb for member in members]
        )
        domain_distribution = [
            (1.0 - compromise_probability) * value for value in independent
        ]
        domain_distribution[-1] += compromise_probability
        total_distribution = _convolve(total_distribution, domain_distribution)

    max_byzantine = (len(committee) - 1) // 3
    return min(1.0, max(0.0, sum(total_distribution[max_byzantine + 1 :])))


def pbft_protocol_message_count(committee_size: int) -> int:
    if committee_size < 1:
        raise ValueError("committee_size must be positive")
    followers = committee_size - 1
    return followers + followers * max(0, followers - 1) + followers + followers


def _lottery_priority(
    candidate: ValidatorCandidate,
    *,
    seed: int,
    event_id: str,
    minimum_weight: float,
    maximum_weight: float,
) -> float:
    # Affinely map a probability in [0, 1] into the registered bounded weight
    # interval.  A direct hard clamp made every LCB above the upper cap equal
    # and accidentally reduced the reputation lottery to a uniform lottery.
    weight = minimum_weight + (
        maximum_weight - minimum_weight
    ) * candidate.honesty_lcb
    digest = sha256(
        f"{seed}|{event_id}|{candidate.validator_id}".encode("utf-8")
    ).digest()
    integer = int.from_bytes(digest, "big")
    uniform = (integer + 1) / (2 ** (8 * len(digest)) + 1)
    return -log(uniform) / weight


def _candidate_committee(
    ordered: Sequence[ValidatorCandidate],
    size: int,
    domain_seat_fraction: float,
) -> list[ValidatorCandidate] | None:
    seat_limit = ceil(domain_seat_fraction * size)
    selected: list[ValidatorCandidate] = []
    seats: Counter[Hashable] = Counter()
    for candidate in ordered:
        if seats[candidate.domain] >= seat_limit:
            continue
        selected.append(candidate)
        seats[candidate.domain] += 1
        if len(selected) == size:
            return selected
    return None


def select_risk_constrained_committee(
    candidates: Iterable[ValidatorCandidate],
    *,
    risk_level: RiskLevel | str,
    seed: int,
    event_id: str,
    domain_compromise_probability: Mapping[Hashable, float] | None = None,
    minimum_size: int = 4,
    domain_seat_fraction: float = 0.40,
    minimum_lottery_weight: float = 0.05,
    maximum_lottery_weight: float = 0.80,
) -> CommitteeSelection:
    risk_level = RiskLevel(risk_level)
    pool = list(candidates)
    if len({item.validator_id for item in pool}) != len(pool):
        raise ValueError("validator identifiers must be unique")
    if len(pool) < minimum_size:
        raise UnsafeCommitteeError("not enough candidates for minimum committee")
    if not 0.0 < domain_seat_fraction <= 1.0:
        raise ValueError("domain_seat_fraction must be in (0, 1]")
    if not 0.0 < minimum_lottery_weight <= maximum_lottery_weight <= 1.0:
        raise ValueError("invalid lottery weight caps")

    ordered = sorted(
        pool,
        key=lambda candidate: (
            _lottery_priority(
                candidate,
                seed=seed,
                event_id=event_id,
                minimum_weight=minimum_lottery_weight,
                maximum_weight=maximum_lottery_weight,
            ),
            candidate.validator_id,
        ),
    )
    budget = RISK_BUDGETS[risk_level]
    for size in range(minimum_size, len(pool) + 1):
        committee = _candidate_committee(ordered, size, domain_seat_fraction)
        if committee is None:
            continue
        failure = committee_failure_probability(
            committee, domain_compromise_probability
        )
        if failure <= budget:
            domains = {item.domain for item in committee}
            return CommitteeSelection(
                risk_level=risk_level.value,
                failure_budget=budget,
                estimated_failure_probability=failure,
                committee_size=size,
                max_byzantine=(size - 1) // 3,
                member_ids=tuple(item.validator_id for item in committee),
                represented_domains=len(domains),
                maximum_domain_seats=max(Counter(item.domain for item in committee).values()),
                protocol_message_count=pbft_protocol_message_count(size),
                mean_latency_ms=sum(item.latency_ms for item in committee) / size,
            )
    raise UnsafeCommitteeError(
        f"no committee satisfies {risk_level.value} budget {budget}"
    )
