"""Unit checks for the external baseline external baseline adapters."""
import numpy as np
from canonical_evidence import CanonicalEvidenceRecord
from run_dual_role import _ArrayBook
from brbc_participation import (
    BRBC_INITIAL,
    BRBC_THRESHOLD,
    JUDGE_DOMAINS,
    K,
    N,
    Q,
    _eligible,
    _scores,
    _update_score,
)
from identity_multiplicity_external import (
    TWSL_COMMUNICATION_QUALITY,
    TWSL_GAMMA,
    local_opinion,
)


def _record(domain, outcome, index):
    return CanonicalEvidenceRecord(
        evidence_id=f"test:{domain}:{index}:{outcome}",
        subject_id=0,
        evidence_kind="validator_audit",
        outcome=float(outcome),
        source_domain=domain,
        effective_height=index,
        delivery_height=index + 1,
        source_height=index,
    )


def test_brs_starts_vacuous_and_pools_evidence():
    book = _ArrayBook(2, 1)
    assert float(book.mean(0, 0)) == 0.5
    book.update(0, np.asarray([0]), np.asarray([1.0]))
    book.update(0, np.asarray([0]), np.asarray([0.0]))
    assert float(book.mean(0, 0)) == 0.5


def test_twsl_local_opinion_vacuous_expectation_is_neutral():
    opinion = local_opinion(0.0, 0.0, TWSL_COMMUNICATION_QUALITY, TWSL_GAMMA)
    assert opinion.expectation == 0.5


def test_brbc_requires_strict_judge_majority_for_ineligibility():
    scores = _scores()
    assert BRBC_INITIAL == BRBC_THRESHOLD == 7.0
    assert _eligible(scores, 0)
    for index, domain in enumerate(JUDGE_DOMAINS[:2]):
        _update_score(scores, _record(domain, 0.0, index))
    assert _eligible(scores, 0)
    _update_score(scores, _record(JUDGE_DOMAINS[2], 0.0, 2))
    assert not _eligible(scores, 0)
    _update_score(scores, _record(JUDGE_DOMAINS[0], 1.0, 3))
    assert _eligible(scores, 0)


def test_external_adapter_preserves_fixed_finality_constants():
    assert (N, K, Q) == (40, 13, 27)
