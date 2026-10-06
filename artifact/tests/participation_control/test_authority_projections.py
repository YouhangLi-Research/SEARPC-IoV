from __future__ import annotations

from dataclasses import replace
import inspect
import math

from authorized_selection import plan_authorized_fast_path
from canonical_evidence import *
from durac import CertifiedSelection, ValidatorCandidate
from generate_content_risk import online_levels, risk_from_components
from run_participation import run_repeat
from typed_authority import (
    AuthorityCapability,
    AuthorityTarget,
    EvidenceKind,
    allowed_targets,
    require_authority,
)


def rec(**kw):
    values = dict(
        evidence_id="e1",
        subject_id=1,
        evidence_kind="validator_audit",
        outcome=1.0,
        source_domain="d1",
        effective_height=4,
        delivery_height=5,
        source_height=3,
    )
    values.update(kw)
    return CanonicalEvidenceRecord(**values)


def snap(*, risk=None, registry=None):
    return build_snapshot(
        height=5,
        view=0,
        audit_root="a" * 64,
        risk=risk or neutral_risk_record(4),
        registry_root=registry or "b" * 64,
    )


def entries():
    return experiment_registry_entries(
        ["domain-a", "domain-b", "domain-c"],
        registry_epoch=7,
        configuration={"k": 2, "Q": 3},
    )


def test_01_exact_duplicate_collapses():
    item = rec()
    assert canonical_cut([item, item], decision_height=5) == (item,)


def test_02_conflicting_payloads_all_rejected():
    first = rec()
    second = replace(first, outcome=0.0)
    accepted, rejected = resolve_evidence(
        [first, second], decision_height=5
    )
    assert not accepted and len(rejected) == 2


def test_03_late_record_not_visible_early():
    assert not canonical_cut([rec(delivery_height=7)], decision_height=6)


def test_04_late_record_visible_after_delivery():
    assert len(canonical_cut([rec(delivery_height=7)], decision_height=7)) == 1


def test_05_effective_height_must_precede_decision():
    assert not canonical_cut([rec(effective_height=5)], decision_height=5)


def test_06_wrong_schema_rejected():
    accepted, rejected = resolve_evidence(
        [rec(schema_version="bad")], decision_height=5
    )
    assert not accepted and len(rejected) == 1


def test_07_arrival_order_does_not_change_cut():
    first = rec()
    second = rec(evidence_id="e2", subject_id=2)
    assert canonical_cut([first, second], decision_height=5) == canonical_cut(
        [second, first], decision_height=5
    )


def test_08_batch_order_does_not_change_root():
    first = rec()
    second = rec(evidence_id="e2", subject_id=2)
    left = RollingEvidenceRoot()
    right = RollingEvidenceRoot()
    left.append_batch([first, second])
    right.append_batch([second, first])
    assert left.root == right.root


def test_09_duplicate_does_not_change_root():
    item = rec()
    left = RollingEvidenceRoot()
    right = RollingEvidenceRoot()
    left.append_batch([item])
    right.append_batch([item, item])
    assert left.root == right.root


def test_10_new_envelope_id_cannot_create_new_challenge():
    first = rec(evidence_id="envelope-a")
    second = rec(evidence_id="envelope-b")
    cut = canonical_cut([first, second], decision_height=5)
    assert len(cut) == 1
    assert first.challenge_id == second.challenge_id


def test_11_cross_height_replay_is_idempotent():
    log = CanonicalEvidenceLog()
    item = rec()
    first = log.commit([item], decision_height=5)
    root = log.root
    second = log.commit([item], decision_height=6)
    assert len(first.accepted) == 1
    assert not second.accepted and len(second.replayed) == 1
    assert log.records == 1 and log.root == root


def test_12_different_id_same_challenge_is_replay():
    log = CanonicalEvidenceLog()
    log.commit([rec(evidence_id="a")], decision_height=5)
    result = log.commit([rec(evidence_id="b")], decision_height=6)
    assert len(result.replayed) == 1
    assert not result.accepted and log.records == 1


def test_13_post_finalization_conflict_does_not_update_log():
    log = CanonicalEvidenceLog()
    log.commit([rec(outcome=1.0)], decision_height=5)
    root = log.root
    result = log.commit(
        [rec(evidence_id="conflict", outcome=0.0)], decision_height=6
    )
    assert len(result.conflicts) == 1
    assert not result.accepted and log.records == 1 and log.root == root


def test_14_independent_audit_domains_are_distinct_challenges():
    log = CanonicalEvidenceLog()
    result = log.commit(
        [rec(source_domain="issuer-a"), rec(source_domain="issuer-b")],
        decision_height=5,
    )
    assert len(result.accepted) == 2 and log.records == 2


def test_15_risk_record_digest_is_stable():
    risk = CanonicalRiskRecord(4, 0.5, "medium", 0, "ev")
    assert risk.digest == replace(risk).digest


def test_16_wrong_slot_maps_to_neutral():
    risk = CanonicalRiskRecord(3, 0.7, "high", 1, "ev")
    snapshot = build_snapshot(
        height=5,
        view=0,
        audit_root="a" * 64,
        risk=risk,
        registry_root="b" * 64,
    )
    assert snapshot.risk_trigger == 0
    assert snapshot.risk_status == "not-authorized"


def test_17_risk_and_view_cannot_taint_seed_projection():
    low = CanonicalRiskRecord(4, 0.01, "low", 0, "event-a")
    high = CanonicalRiskRecord(4, 0.99, "high", 1, "event-b")
    first = snap(risk=low)
    second = replace(snap(risk=high), view=99)
    assert first.root != second.root and first.risk_root != second.risk_root
    assert first.seed_root == second.seed_root


def test_18_core_audit_projection_excludes_content():
    low = snap(risk=CanonicalRiskRecord(4, 0.01, "low", 0, "a"))
    high = snap(risk=CanonicalRiskRecord(4, 0.99, "high", 1, "b"))
    assert low.audit_plan_root(content_aware=False) == high.audit_plan_root(
        content_aware=False
    )
    assert low.audit_plan_root(content_aware=True) != high.audit_plan_root(
        content_aware=True
    )


def test_19_commitment_required_before_beacon_reveal():
    beacon = synthetic_frozen_beacon(experiment_seed=1, source_height=4)
    try:
        derive_committee_capability(
            beacon=beacon, seed_commitment=snap().seed_root, purpose="primary"
        )
    except TypeError:
        pass
    else:
        raise AssertionError("raw roots must not cross the seed sink")


def test_20_seed_binds_purpose():
    beacon = synthetic_frozen_beacon(experiment_seed=1, source_height=4)
    commitment = snap().commit_seed_projection()
    primary = derive_committee_capability(
        beacon=beacon, seed_commitment=commitment, purpose="primary"
    )
    resample = derive_committee_capability(
        beacon=beacon, seed_commitment=commitment, purpose="resample"
    )
    assert primary.seed != resample.seed


def test_21_late_evidence_cannot_mutate_frozen_seed_commitment():
    snapshot = snap()
    commitment = snapshot.commit_seed_projection()
    log = CanonicalEvidenceLog()
    log.commit([rec()], decision_height=5)
    beacon = synthetic_frozen_beacon(experiment_seed=2, source_height=4)
    capability = derive_committee_capability(
        beacon=beacon, seed_commitment=commitment, purpose="primary"
    )
    assert capability.seed_projection_root == commitment.root
    assert log.root != snapshot.audit_root


def test_22_selector_has_no_external_event_label_parameter():
    assert "event_id" not in inspect.signature(
        plan_authorized_fast_path
    ).parameters


def test_23_external_label_cannot_change_members_leader_or_collectors():
    candidates = [
        ValidatorCandidate(i, 0.5, f"d{i % 5}", float(i))
        for i in range(20)
    ]
    commitment = snap().commit_seed_projection()
    beacon = synthetic_frozen_beacon(experiment_seed=3, source_height=4)
    capability = derive_committee_capability(
        beacon=beacon, seed_commitment=commitment, purpose="primary"
    )
    first = plan_authorized_fast_path(
        candidates,
        candidates,
        size=13,
        selection=CertifiedSelection.DIVERSE_UNIFORM,
        capability=capability,
        leader_reputation_weighted=False,
        backup_collector_enabled=True,
    )
    arbitrary_external_label = "attacker-controlled-event-name"
    assert arbitrary_external_label
    second = plan_authorized_fast_path(
        candidates,
        candidates,
        size=13,
        selection=CertifiedSelection.DIVERSE_UNIFORM,
        capability=capability,
        leader_reputation_weighted=False,
        backup_collector_enabled=True,
    )
    assert (
        first.member_ids,
        first.leader_id,
        first.primary_collector_id,
        first.backup_collector_id,
    ) == (
        second.member_ids,
        second.leader_id,
        second.primary_collector_id,
        second.backup_collector_id,
    )


def test_24_registry_order_is_canonical():
    registry = entries()
    assert registry_root(registry) == registry_root(tuple(reversed(registry)))


def test_25_registry_commits_validator_identity_and_domain():
    registry = entries()
    changed_id = (replace(registry[0], validator_id=30), *registry[1:])
    changed_domain = (
        replace(registry[0], correlation_domain="new-domain"),
        *registry[1:],
    )
    assert registry_root(registry) != registry_root(changed_id)
    assert registry_root(registry) != registry_root(changed_domain)


def test_26_registry_commits_credential_eligibility_epoch_and_config():
    registry = entries()
    changes = [
        replace(registry[0], credential_digest="f" * 64),
        replace(registry[0], eligible=False),
        replace(registry[0], registry_epoch=8),
        replace(registry[0], configuration_digest="e" * 64),
    ]
    for changed in changes:
        assert registry_root(registry) != registry_root(
            (changed, *registry[1:])
        )


def test_27_runtime_capability_rejects_wrong_sink():
    capability = snap().audit_capability(content_aware=False)
    try:
        require_authority(
            capability.authority, AuthorityTarget.COMMITTEE_SEED
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("core audit authority reached committee seed")


def test_28_audit_output_is_bound_to_authorized_plan():
    capability = snap().audit_capability(content_aware=False)
    first = audit_plan_output_root(
        capability, targets=(1, 2, 3), coverage=0.5
    )
    second = audit_plan_output_root(
        capability, targets=(1, 2, 4), coverage=0.5
    )
    assert first != second


def test_29_hashing_does_not_escalate_authority():
    inherited = authority_meet(
        VALIDATOR_AUDIT_AUTHORITY,
        CONTENT_RISK_AUTHORITY,
        REGISTRY_AUTHORITY,
    )
    assert AuthorityTarget.COMMITTEE_SEED not in inherited
    assert inherited == frozenset()


def test_30_content_risk_has_no_core_authority():
    allowed = allowed_targets(EvidenceKind.CONTENT_RISK)
    assert AuthorityTarget.COMMITTEE_SEED not in allowed
    assert AuthorityTarget.CORE_AUDIT_PLAN not in allowed
    assert AuthorityTarget.CORE_PARTICIPATION_FSM not in allowed


def test_31_core_metamorphic_content_noninterference():
    base = [
        {
            "block": i,
            "source_index": i,
            "risk_score": 0.2,
            "risk_level": "low",
        }
        for i in range(1, 41)
    ]
    changed = [
        {
            "block": i,
            "source_index": 10000 - i,
            "risk_score": 0.99 if i % 2 else 0.01,
            "risk_level": "high" if i % 2 else "medium",
        }
        for i in range(1, 41)
    ]
    first = run_repeat(
        1, "metamorphic", 1, base, selected_methods=("validator_only",)
    )
    second = run_repeat(
        1, "metamorphic", 1, changed, selected_methods=("validator_only",)
    )
    fields = (
        "seed_projection_root",
        "primary_member_ids",
        "selected_member_ids",
        "resampled",
        "audit_target_ids",
        "audit_plan_output_root",
        "actual_handoff",
        "direct_standard",
    )
    assert [
        tuple(row[key] for key in fields) for row in first
    ] == [
        tuple(row[key] for key in fields) for row in second
    ]


def test_32_validator_beta_has_no_control_input():
    source = inspect.getsource(run_repeat)
    assert "beta.ppf" not in source
    assert "validator_beta" not in source
    assert "E_i_v" not in source


def test_33_runner_does_not_call_free_event_selector():
    source = inspect.getsource(run_repeat)
    assert "event_id=" not in source
    assert "plan_fast_path(" not in source
    assert "plan_authorized_fast_path(" in source


def test_34_risk_extremes_are_finite_and_bounded():
    for probability in (0, 1):
        value = risk_from_components(
            message_probability=probability,
            reliability=1,
            provider_mean=1 - probability,
            opinion_value=1 - probability,
            opinion_weight=1,
        )
        assert math.isfinite(value) and 0 <= value <= 1


def test_35_quantile_constant_window_is_medium():
    levels = online_levels([0.5] * 110)
    assert set(levels[100:]) == {"medium"}


def test_36_quantile_tie_is_deterministic():
    scores = [0.1] * 90 + [0.9] * 20
    assert online_levels(scores) == online_levels(list(scores))
