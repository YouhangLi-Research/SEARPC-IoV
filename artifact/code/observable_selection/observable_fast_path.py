"""observable selection observable-only fast-hint controller and simulation adapter.

The controller in this module never receives Byzantine/ground-truth labels.
Fault labels may be used only by the simulation environment to generate an
observable transcript (which validators actually returned usable signatures,
collector availability, block availability, etc.) and by the offline evaluator
that computes latent committee fault-budget exceedance.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Iterable, Sequence

from durac.certified import CertifiedConsensusOutcome, CertifiedSelection, select_cross_domain_collectors
from durac.consensus import ValidatorCandidate, pbft_protocol_message_count
from durac.dual_path import select_diverse_random_committee
from durac.security import CommitteeMethod, select_committee_leader, select_size_matched_committee


@dataclass(frozen=True)
class FastPathPlan:
    selection: str
    committee_size: int
    member_ids: tuple[int, ...]
    leader_id: int
    registered_ids: FrozenSet[int]
    final_quorum: int
    fast_quorum: int
    primary_collector_id: int = -1
    backup_collector_id: int = -1


@dataclass(frozen=True)
class ObservableTranscript:
    """Everything the online controller may observe for one planned attempt."""

    fast_legal_signer_ids: FrozenSet[int]
    base_legal_signer_ids: FrozenSet[int]
    collector_available: bool = True
    collector_withholds: bool = False
    backup_collector_available: bool = True
    backup_collector_withholds: bool = False
    block_available: bool = True
    hint_structurally_valid: bool = True


@dataclass(frozen=True)
class ObservableDecision:
    path: str
    certificate_available: int
    collector_fault: int
    fallback_triggered: int
    direct_standard: int
    hint_assembly_timeout: int
    invalid_hint: int
    block_unavailable: int
    actual_handoff: int
    final_legal_eventual_commit: int
    final_illegal_block_accepted: int
    final_refusal: int
    protocol_message_count: int
    backup_collector_attempted: int = 0
    backup_collector_fault: int = 0
    backup_certificate_available: int = 0
    certificate_collector: str = "none"


@dataclass(frozen=True)
class OfflineFaultEvaluation:
    actual_byzantine: int
    max_byzantine: int
    fault_budget_exceedance: int
    latent_illegal_fast_capability: int


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
            candidates, size=size, seed=seed, event_id=event_id
        )
    method = {
        CertifiedSelection.UNIFORM: CommitteeMethod.UNIFORM_SIZE_MATCHED,
        CertifiedSelection.REPUTATION_TOP: CommitteeMethod.REPUTATION_TOP_SIZE_MATCHED,
        CertifiedSelection.POS_WEIGHTED: CommitteeMethod.POS_WEIGHTED_SIZE_MATCHED,
    }[selection]
    return select_size_matched_committee(
        candidates, size=size, method=method, seed=seed, event_id=event_id
    )


def plan_fast_path(
    candidates: Iterable[ValidatorCandidate],
    registered_candidates: Iterable[ValidatorCandidate],
    *,
    size: int,
    selection: CertifiedSelection | str,
    seed: int,
    event_id: str,
    leader_reputation_weighted: bool,
    backup_collector_enabled: bool = False,
) -> FastPathPlan:
    """Choose a committee using only public/observable candidate state."""

    selection = CertifiedSelection(selection)
    pool = list(candidates)
    registered = sorted(registered_candidates, key=lambda c: c.validator_id)
    registered_ids = frozenset(c.validator_id for c in registered)
    if not registered:
        raise ValueError("registered validator set cannot be empty")
    if len(registered_ids) != len(registered):
        raise ValueError("registered validator identifiers must be unique")
    if not {c.validator_id for c in pool} <= registered_ids:
        raise ValueError("candidates must belong to the registered set")
    if size < 1:
        raise ValueError("size must be positive")

    full_f = (len(registered) - 1) // 3
    final_quorum = 2 * full_f + 1
    fast_f = (size - 1) // 3
    fast_quorum = 2 * fast_f + 1

    if len(pool) < size:
        return FastPathPlan(
            selection=selection.value,
            committee_size=0,
            member_ids=(),
            leader_id=-1,
            registered_ids=registered_ids,
            final_quorum=final_quorum,
            fast_quorum=fast_quorum,
        )

    committee = _select(pool, size=size, selection=selection, seed=seed, event_id=event_id)
    leader = select_committee_leader(
        committee,
        seed=seed + 7,
        event_id=f"{event_id}|leader",
        reputation_weighted=leader_reputation_weighted,
    )
    collectors = (
        select_cross_domain_collectors(
            registered, seed=seed + 17, event_id=f"{event_id}|collectors"
        )
        if backup_collector_enabled
        else None
    )
    return FastPathPlan(
        selection=selection.value,
        committee_size=size,
        member_ids=tuple(c.validator_id for c in committee),
        leader_id=leader.validator_id,
        registered_ids=registered_ids,
        final_quorum=final_quorum,
        fast_quorum=fast_quorum,
        primary_collector_id=collectors.primary_id if collectors else -1,
        backup_collector_id=collectors.backup_id if collectors else -1,
    )


def decide_from_observation(
    plan: FastPathPlan,
    transcript: ObservableTranscript,
    *,
    use_full_certificate: bool = True,
    fallback_enabled: bool = True,
    backup_collector_enabled: bool = False,
) -> ObservableDecision:
    """Decide the path using observable outcomes only; never ground truth."""

    if not transcript.fast_legal_signer_ids <= set(plan.member_ids):
        raise ValueError("fast signer set contains a non-member")
    if not transcript.base_legal_signer_ids <= plan.registered_ids:
        raise ValueError("base signer set contains an unregistered validator")

    if plan.committee_size == 0:
        base_ok = len(transcript.base_legal_signer_ids) >= plan.final_quorum
        return ObservableDecision(
            path="direct_standard" if base_ok else "refused",
            certificate_available=0,
            collector_fault=0,
            fallback_triggered=1,
            direct_standard=1,
            hint_assembly_timeout=0,
            invalid_hint=0,
            block_unavailable=0,
            actual_handoff=0,
            final_legal_eventual_commit=int(base_ok and fallback_enabled),
            final_illegal_block_accepted=0,
            final_refusal=int(not (base_ok and fallback_enabled)),
            protocol_message_count=(
                pbft_protocol_message_count(len(plan.registered_ids))
                if fallback_enabled else 0
            ),
        )

    primary_collector_fault = int(
        not transcript.collector_available or transcript.collector_withholds
    )
    fast_quorum_reached = len(transcript.fast_legal_signer_ids) >= plan.fast_quorum
    base_quorum_reached = len(transcript.base_legal_signer_ids) >= plan.final_quorum
    hint_timeout = int(not fast_quorum_reached)
    invalid_hint = int(fast_quorum_reached and not transcript.hint_structurally_valid)
    block_unavailable = int(fast_quorum_reached and not transcript.block_available)

    primary_certificate_available = int(
        use_full_certificate
        and fast_quorum_reached
        and base_quorum_reached
        and transcript.collector_available
        and not transcript.collector_withholds
        and not invalid_hint
        and not block_unavailable
    )
    backup_collector_attempted = int(
        use_full_certificate
        and backup_collector_enabled
        and primary_collector_fault
        and fast_quorum_reached
        and not invalid_hint
        and not block_unavailable
    )
    backup_collector_fault = int(
        backup_collector_attempted
        and (
            not transcript.backup_collector_available
            or transcript.backup_collector_withholds
        )
    )
    backup_certificate_available = int(
        backup_collector_attempted
        and base_quorum_reached
        and transcript.backup_collector_available
        and not transcript.backup_collector_withholds
    )
    certificate_available = int(
        primary_certificate_available or backup_certificate_available
    )
    certificate_collector = (
        "primary" if primary_certificate_available else
        "backup" if backup_certificate_available else "none"
    )

    fast_messages = pbft_protocol_message_count(plan.committee_size)
    if use_full_certificate:
        fast_messages += 2 * len(plan.registered_ids)
        if backup_collector_attempted:
            fast_messages += 2 * len(plan.registered_ids)

    if certificate_available:
        return ObservableDecision(
            path="fast_certified_backup" if backup_certificate_available else "fast_certified",
            certificate_available=1,
            collector_fault=primary_collector_fault,
            fallback_triggered=0,
            direct_standard=0,
            hint_assembly_timeout=hint_timeout,
            invalid_hint=invalid_hint,
            block_unavailable=block_unavailable,
            actual_handoff=0,
            final_legal_eventual_commit=1,
            final_illegal_block_accepted=0,
            final_refusal=0,
            protocol_message_count=fast_messages,
            backup_collector_attempted=backup_collector_attempted,
            backup_collector_fault=backup_collector_fault,
            backup_certificate_available=backup_certificate_available,
            certificate_collector=certificate_collector,
        )

    if not fallback_enabled:
        return ObservableDecision(
            path="refused",
            certificate_available=0,
            collector_fault=primary_collector_fault,
            fallback_triggered=0,
            direct_standard=0,
            hint_assembly_timeout=hint_timeout,
            invalid_hint=invalid_hint,
            block_unavailable=block_unavailable,
            actual_handoff=0,
            final_legal_eventual_commit=0,
            final_illegal_block_accepted=0,
            final_refusal=1,
            protocol_message_count=fast_messages,
            backup_collector_attempted=backup_collector_attempted,
            backup_collector_fault=backup_collector_fault,
            backup_certificate_available=backup_certificate_available,
            certificate_collector=certificate_collector,
        )

    base_ok = base_quorum_reached
    return ObservableDecision(
        path="fast_then_standard" if base_ok else "refused",
        certificate_available=0,
        collector_fault=primary_collector_fault,
        fallback_triggered=1,
        direct_standard=0,
        hint_assembly_timeout=hint_timeout,
        invalid_hint=invalid_hint,
        block_unavailable=block_unavailable,
        actual_handoff=1,
        final_legal_eventual_commit=int(base_ok),
        final_illegal_block_accepted=0,
        final_refusal=int(not base_ok),
        protocol_message_count=(
            fast_messages + pbft_protocol_message_count(len(plan.registered_ids))
        ),
        backup_collector_attempted=backup_collector_attempted,
        backup_collector_fault=backup_collector_fault,
        backup_certificate_available=backup_certificate_available,
        certificate_collector=certificate_collector,
    )


def simulate_transcript_from_fault_labels(
    plan: FastPathPlan,
    *,
    byzantine_ids: Iterable[int],
    unavailable_ids: Iterable[int] = (),
    collector_available: bool = True,
    collector_withholds: bool = False,
    backup_collector_available: bool = True,
    backup_collector_withholds: bool = False,
    block_available: bool = True,
    hint_structurally_valid: bool = True,
) -> ObservableTranscript:
    """Simulation environment only: convert hidden labels into visible actions.

    This preserves the base simulation behavior model (honest online validators return a
    usable signature for the legal digest; Byzantine validators may withhold).
    The returned transcript, not the labels, is the online controller input.
    """

    byzantine = set(int(x) for x in byzantine_ids)
    unavailable = set(int(x) for x in unavailable_ids)
    online = set(plan.registered_ids) - unavailable
    base_signers = frozenset(online - byzantine)
    fast_signers = frozenset(set(plan.member_ids) & set(base_signers))
    return ObservableTranscript(
        fast_legal_signer_ids=fast_signers,
        base_legal_signer_ids=base_signers,
        collector_available=collector_available,
        collector_withholds=collector_withholds,
        backup_collector_available=backup_collector_available,
        backup_collector_withholds=backup_collector_withholds,
        block_available=block_available,
        hint_structurally_valid=hint_structurally_valid,
    )


def offline_fault_evaluation(
    plan: FastPathPlan, *, byzantine_ids: Iterable[int]
) -> OfflineFaultEvaluation:
    """Offline metric only; cannot influence an online decision."""
    byzantine = set(int(x) for x in byzantine_ids)
    actual = len(set(plan.member_ids) & byzantine)
    maximum = (plan.committee_size - 1) // 3 if plan.committee_size else 0
    latent_illegal = int(
        plan.committee_size > 0
        and plan.leader_id in byzantine
        and actual >= plan.fast_quorum
    )
    return OfflineFaultEvaluation(
        actual_byzantine=actual,
        max_byzantine=maximum,
        fault_budget_exceedance=int(actual > maximum),
        latent_illegal_fast_capability=latent_illegal,
    )


def simulate_observable_consensus(
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
    """Simulation shim returning the legacy outcome shape.

    Hidden fault labels are consumed only here to produce a transcript and
    offline metrics. ``plan_fast_path`` and ``decide_from_observation`` remain
    label-free and are the observable selection online control path.
    """
    plan = plan_fast_path(
        candidates,
        registered_candidates,
        size=size,
        selection=selection,
        seed=seed,
        event_id=event_id,
        leader_reputation_weighted=leader_reputation_weighted,
        backup_collector_enabled=backup_collector_enabled,
    )
    transcript = simulate_transcript_from_fault_labels(
        plan,
        byzantine_ids=byzantine_ids,
        unavailable_ids=unavailable_ids,
        collector_available=collector_available,
        collector_withholds=collector_withholds,
        backup_collector_available=backup_collector_available,
        backup_collector_withholds=backup_collector_withholds,
    )
    decision = decide_from_observation(
        plan,
        transcript,
        use_full_certificate=use_full_certificate,
        fallback_enabled=fallback_enabled,
        backup_collector_enabled=backup_collector_enabled,
    )
    offline = offline_fault_evaluation(plan, byzantine_ids=byzantine_ids)
    return CertifiedConsensusOutcome(
        selection=plan.selection,
        path=decision.path,
        committee_size=plan.committee_size,
        member_ids=plan.member_ids,
        leader_id=plan.leader_id,
        actual_byzantine=offline.actual_byzantine,
        max_byzantine=offline.max_byzantine,
        safety_budget_breach=offline.fault_budget_exceedance,
        fast_illegal_proposal=offline.latent_illegal_fast_capability,
        certificate_available=decision.certificate_available,
        collector_fault=decision.collector_fault,
        fallback_triggered=decision.fallback_triggered,
        final_legal_eventual_commit=decision.final_legal_eventual_commit,
        final_illegal_block_accepted=decision.final_illegal_block_accepted,
        final_refusal=decision.final_refusal,
        protocol_message_count=decision.protocol_message_count,
        primary_collector_id=plan.primary_collector_id,
        backup_collector_id=plan.backup_collector_id,
        backup_collector_attempted=decision.backup_collector_attempted,
        backup_collector_fault=decision.backup_collector_fault,
        backup_certificate_available=decision.backup_certificate_available,
        certificate_collector=decision.certificate_collector,
    )


__all__ = [
    "FastPathPlan", "ObservableTranscript", "ObservableDecision",
    "OfflineFaultEvaluation", "plan_fast_path", "decide_from_observation",
    "simulate_transcript_from_fault_labels", "offline_fault_evaluation",
    "simulate_observable_consensus",
]
