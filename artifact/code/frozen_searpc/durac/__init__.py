"""DURAC-IoV role-separated trust primitives.

The package is intentionally independent from the frozen CBTDS trust package.
"""

from .fusion import FusionResult, Opinion, robust_opinion_fusion
from .datasets import (
    CONTEXTUAL_FEATURE_NAMES,
    CsvSchemaAudit,
    TEMPORAL_FEATURE_NAMES,
    VeReMiRecord,
    VeReMiSplitAudit,
    VeReMiContextualExample,
    VeReMiTemporalExample,
    audit_trust_iov_csv,
    audit_veremi_directory,
    iter_veremi_directory,
    iter_veremi_contextual_directory,
    iter_veremi_json,
    iter_veremi_temporal_directory,
)
from .consensus import (
    CommitteeSelection,
    RiskLevel,
    UnsafeCommitteeError,
    ValidatorCandidate,
    committee_failure_probability,
    pbft_protocol_message_count,
    select_risk_constrained_committee,
)
from .feasibility import (
    ClassificationMetrics,
    FeasibilityConfig,
    FeasibilityResult,
    FeasibilitySimulator,
)
from .reputation import BetaRolePosterior, Role, RoleReputationBook
from .risk import EventAssessment, assess_event
from .admission import AdmissionState, AdmissionUpdate, ValidatorAdmissionTracker
from .dual_path import (
    ConsensusPath,
    DualPathOutcome,
    FAST_COMMITTEE_SIZES,
    execute_dual_path_consensus,
    select_diverse_random_committee,
)
from .security import (
    CommitteeMethod,
    CommitteeSecurityOutcome,
    evaluate_committee_security,
    sample_byzantine_ids,
    select_committee_leader,
    select_size_matched_committee,
)
from .validator_reputation import ValidatorReputationTracker, ValidatorUpdate
from .timing import FinalityCertificateCost, full_set_finality_cost
from .certified import (
    CertifiedConsensusOutcome,
    CertifiedSelection,
    CollectorPair,
    basic_hotstuff_message_count,
    execute_certified_committee_consensus,
    select_cross_domain_collectors,
)
from .hotstuff_timing import BasicHotStuffCost, basic_hotstuff_cost
from .finality_adapter import (
    FastProposalHint,
    FinalizerInvocation,
    FinalizerBoundary,
)
from .message_evidence import (
    IsotonicProbabilityCalibrator,
    MessageEvidenceMetrics,
    PlattProbabilityCalibrator,
    expected_calibration_error,
    message_evidence_metrics,
    select_fpr_constrained_threshold,
    uncertainty_diagnostics,
)

__all__ = [
    "BetaRolePosterior",
    "ClassificationMetrics",
    "CommitteeSelection",
    "CommitteeMethod",
    "CommitteeSecurityOutcome",
    "CsvSchemaAudit",
    "CONTEXTUAL_FEATURE_NAMES",
    "TEMPORAL_FEATURE_NAMES",
    "EventAssessment",
    "FusionResult",
    "FeasibilityConfig",
    "FeasibilityResult",
    "FeasibilitySimulator",
    "Opinion",
    "Role",
    "RoleReputationBook",
    "RiskLevel",
    "UnsafeCommitteeError",
    "ValidatorCandidate",
    "AdmissionState",
    "AdmissionUpdate",
    "ValidatorAdmissionTracker",
    "ConsensusPath",
    "DualPathOutcome",
    "FAST_COMMITTEE_SIZES",
    "FinalityCertificateCost",
    "CertifiedConsensusOutcome",
    "CertifiedSelection",
    "CollectorPair",
    "BasicHotStuffCost",
    "IsotonicProbabilityCalibrator",
    "MessageEvidenceMetrics",
    "PlattProbabilityCalibrator",
    "ValidatorReputationTracker",
    "ValidatorUpdate",
    "VeReMiRecord",
    "VeReMiContextualExample",
    "VeReMiSplitAudit",
    "VeReMiTemporalExample",
    "assess_event",
    "audit_trust_iov_csv",
    "audit_veremi_directory",
    "committee_failure_probability",
    "evaluate_committee_security",
    "iter_veremi_json",
    "iter_veremi_contextual_directory",
    "iter_veremi_directory",
    "iter_veremi_temporal_directory",
    "pbft_protocol_message_count",
    "sample_byzantine_ids",
    "select_committee_leader",
    "select_risk_constrained_committee",
    "select_size_matched_committee",
    "execute_dual_path_consensus",
    "select_diverse_random_committee",
    "full_set_finality_cost",
    "basic_hotstuff_message_count",
    "execute_certified_committee_consensus",
    "select_cross_domain_collectors",
    "basic_hotstuff_cost",
    "expected_calibration_error",
    "message_evidence_metrics",
    "robust_opinion_fusion",
    "select_fpr_constrained_threshold",
    "uncertainty_diagnostics",
    "FastProposalHint",
    "FinalizerInvocation",
    "FinalizerBoundary",
]
