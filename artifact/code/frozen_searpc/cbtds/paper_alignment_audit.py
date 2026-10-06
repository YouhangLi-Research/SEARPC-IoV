"""Audited experiment orchestration around the frozen trust implementation.

This module deliberately lives beside, rather than replacing, ``population``.
It fixes a decision-threshold coupling in the Figure-8 runner and exposes the
previously implicit availability of requester-specific direct evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from typing import Dict, List

from .config import CBTDSConfig
from .model import PairwiseEvidence, Recommendation
from .population import PopulationConfig, PopulationSimulator, _clip01


@dataclass(frozen=True)
class AuditedPopulationResult:
    method: str
    decision_mode: str
    decision_threshold: float
    direct_evidence_probability: float
    malicious_fraction: float
    seed: int
    num_vehicles: int
    num_malicious: int
    true_positive: int
    false_negative: int
    false_positive: int
    true_negative: int
    detection_rate: float
    false_negative_rate: float
    paper_literal_false_negative_fraction: float
    false_positive_rate: float
    precision: float
    accuracy: float
    f1: float
    mean_benign_trust: float
    mean_malicious_trust: float


class AuditedPopulationSimulator(PopulationSimulator):
    """Population simulator with calculation and decision controls separated.

    ``trust_config.trust_threshold`` remains the internal equation/filtering
    threshold. ``decision_threshold`` is used only after trust values have been
    calculated. ``direct_evidence_probability`` models whether the current
    evaluator has prior direct evidence for equation (11); its RNG is separate
    from the event generator so sensitivity cases use identical events.
    """

    _AVAILABILITY_SEED_MASK = 0x5EED_D1EC7

    def __init__(
        self,
        trust_config: CBTDSConfig,
        population_config: PopulationConfig = PopulationConfig(),
        direct_evidence_probability: float = 1.0,
    ) -> None:
        super().__init__(trust_config, population_config)
        if not 0.0 <= direct_evidence_probability <= 1.0:
            raise ValueError("direct_evidence_probability must be in [0, 1]")
        self.direct_evidence_probability = direct_evidence_probability

    def run(
        self,
        malicious_fraction: float,
        seed: int,
        method: str = "cbtds",
        decision_mode: str = "final",
        decision_threshold: float | None = None,
    ) -> AuditedPopulationResult:
        if not 0.0 < malicious_fraction < 1.0:
            raise ValueError("malicious_fraction must be in (0, 1)")
        if method not in self.METHODS:
            raise ValueError(f"method must be one of {self.METHODS}")
        if decision_mode not in ("final", "ever"):
            raise ValueError("decision_mode must be 'final' or 'ever'")
        threshold = (
            self.trust_config.trust_threshold
            if decision_threshold is None
            else float(decision_threshold)
        )
        if not 0.0 < threshold < 1.0:
            raise ValueError("decision_threshold must be in (0, 1)")

        cfg = self.population_config
        rng = random.Random(seed)
        availability_rng = random.Random(seed ^ self._AVAILABILITY_SEED_MASK)
        vehicle_ids = list(range(cfg.num_vehicles))
        pretrusted = set(vehicle_ids[: cfg.num_pretrusted])
        eligible_attackers = vehicle_ids[cfg.num_pretrusted :]
        requested_malicious = round(cfg.num_vehicles * malicious_fraction)
        num_malicious = min(len(eligible_attackers), requested_malicious)
        malicious = set(rng.sample(eligible_attackers, num_malicious))

        trust: Dict[int, float] = {vehicle_id: 0.5 for vehicle_id in vehicle_ids}
        for vehicle_id in pretrusted:
            trust[vehicle_id] = 0.95
        evidence = {vehicle_id: PairwiseEvidence() for vehicle_id in vehicle_ids}
        background_interactions = {vehicle_id: 0 for vehicle_id in vehicle_ids}
        ever_predicted_malicious = set()

        for _round in range(cfg.num_rounds):
            next_trust: Dict[int, float] = {}
            for target in vehicle_ids:
                is_malicious_target = target in malicious
                bad_event_probability = (
                    cfg.malicious_event_probability
                    if is_malicious_target
                    else cfg.benign_fault_probability
                )
                is_bad_event = rng.random() < bad_event_probability
                quality_mean = (
                    cfg.malicious_quality_mean
                    if is_bad_event
                    else cfg.benign_quality_mean
                )
                quality = _clip01(rng.gauss(quality_mean, cfg.quality_std))
                evidence[target].observe(quality, self.trust_config.trust_threshold)
                background_interactions[target] += rng.randint(1, 3)
                direct = self.model.direct_trust(
                    evidence[target],
                    evidence[target].interactions + background_interactions[target],
                )
                direct_is_available = (
                    availability_rng.random() < self.direct_evidence_probability
                )
                direct_for_evaluation = direct if direct_is_available else None

                candidates = [item for item in vehicle_ids if item != target]
                selected = rng.sample(candidates, cfg.recommenders_per_target)
                recommendations: List[Recommendation] = []
                for recommender in selected:
                    honest_report = _clip01(rng.gauss(quality_mean, cfg.report_std))
                    if recommender in malicious:
                        collusive_mean = 0.95 if is_malicious_target else 0.05
                        report = _clip01(rng.gauss(collusive_mean, cfg.report_std))
                    else:
                        report = honest_report
                    recommendations.append(
                        Recommendation(
                            value=report,
                            recommender_global_trust=trust[recommender],
                            requester_recommender_trust=trust[recommender],
                            is_pretrusted=recommender in pretrusted,
                        )
                    )

                if method.startswith("cbtds"):
                    indirect = self._cbtds_indirect(recommendations, method)
                    current = self.model.final_trust(
                        data_quality=quality,
                        direct_trust=direct_for_evaluation,
                        indirect_trust=indirect,
                        recommendation_count=len(recommendations),
                        neighbor_count=cfg.recommenders_per_target,
                    )
                    next_trust[target] = self.model.update_global_trust(
                        current=current,
                        previous=trust[target],
                    )
                elif method == "twsl_aligned":
                    local_evidence = (
                        evidence[target]
                        if direct_is_available
                        else PairwiseEvidence()
                    )
                    next_trust[target] = self._twsl_trust(
                        local_evidence, recommendations
                    )
                else:
                    if direct_is_available:
                        next_trust[target] = self._recommendation_trust(
                            evidence[target], recommendations
                        )
                    else:
                        values = [item.value for item in recommendations]
                        weights = [
                            0.25 + 0.75 * item.recommender_global_trust
                            for item in recommendations
                        ]
                        next_trust[target] = _clip01(
                            self._weighted_mean(values, weights)
                        )
            trust = next_trust
            ever_predicted_malicious.update(
                vehicle_id
                for vehicle_id, value in trust.items()
                if value < threshold
            )

        predicted_malicious = (
            ever_predicted_malicious
            if decision_mode == "ever"
            else {
                vehicle_id
                for vehicle_id, value in trust.items()
                if value < threshold
            }
        )
        benign = set(vehicle_ids) - malicious
        tp = len(predicted_malicious & malicious)
        fn = len(malicious - predicted_malicious)
        fp = len(predicted_malicious & benign)
        tn = len(benign - predicted_malicious)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )

        return AuditedPopulationResult(
            method=method,
            decision_mode=decision_mode,
            decision_threshold=threshold,
            direct_evidence_probability=self.direct_evidence_probability,
            malicious_fraction=malicious_fraction,
            seed=seed,
            num_vehicles=cfg.num_vehicles,
            num_malicious=len(malicious),
            true_positive=tp,
            false_negative=fn,
            false_positive=fp,
            true_negative=tn,
            detection_rate=recall,
            false_negative_rate=fn / len(malicious),
            paper_literal_false_negative_fraction=fn / cfg.num_vehicles,
            false_positive_rate=fp / len(benign),
            precision=precision,
            accuracy=(tp + tn) / cfg.num_vehicles,
            f1=f1,
            mean_benign_trust=sum(trust[item] for item in benign) / len(benign),
            mean_malicious_trust=(
                sum(trust[item] for item in malicious) / len(malicious)
            ),
        )
