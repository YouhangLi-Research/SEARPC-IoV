"""Population-scale synthetic evaluation for the CBTDS trust core.

The uploaded manuscript reports simulations rather than a public dataset. This
module therefore keeps the experiment generator explicit and deterministic.
It does not claim to reproduce the authors' unpublished simulator bit for bit.
"""

from __future__ import annotations

from dataclasses import dataclass
import random
from statistics import median
from typing import Dict, List

from .config import CBTDSConfig
from .model import PairwiseEvidence, Recommendation, TrustModel


@dataclass(frozen=True)
class PopulationConfig:
    num_vehicles: int = 200
    num_pretrusted: int = 20
    num_rounds: int = 60
    recommenders_per_target: int = 20
    malicious_quality_mean: float = 0.22
    benign_quality_mean: float = 0.82
    quality_std: float = 0.12
    report_std: float = 0.08
    malicious_event_probability: float = 0.35
    benign_fault_probability: float = 0.01

    def __post_init__(self) -> None:
        if not 0 < self.num_pretrusted < self.num_vehicles:
            raise ValueError("num_pretrusted must be between 0 and num_vehicles")
        if not 1 <= self.recommenders_per_target < self.num_vehicles:
            raise ValueError("invalid recommenders_per_target")
        if self.num_rounds <= 0:
            raise ValueError("num_rounds must be positive")
        for name in ("malicious_event_probability", "benign_fault_probability"):
            if not 0.0 <= getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")


@dataclass(frozen=True)
class PopulationResult:
    method: str
    decision_mode: str
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
    false_positive_rate: float
    precision: float
    accuracy: float
    f1: float
    mean_benign_trust: float
    mean_malicious_trust: float


def _clip01(value: float) -> float:
    return min(1.0, max(0.0, value))


class PopulationSimulator:
    """Evaluate trust classification in a 200-vehicle synthetic network."""

    def __init__(
        self,
        trust_config: CBTDSConfig,
        population_config: PopulationConfig = PopulationConfig(),
    ) -> None:
        self.trust_config = trust_config
        self.population_config = population_config
        self.model = TrustModel(trust_config)

    METHODS = (
        "cbtds",
        "twsl_aligned",
        "recommendation_aligned",
        "cbtds_no_filter",
        "cbtds_no_pretrusted",
    )

    @staticmethod
    def _weighted_mean(values: List[float], weights: List[float]) -> float:
        total = sum(weights)
        if total <= 0.0:
            return sum(values) / len(values)
        return sum(value * weight for value, weight in zip(values, weights)) / total

    def _cbtds_indirect(
        self,
        recommendations: List[Recommendation],
        method: str,
    ) -> float | None:
        if method == "cbtds":
            return self.model.indirect_trust(recommendations)

        filtered = recommendations
        if method == "cbtds_no_pretrusted":
            filtered = [
                item
                for item in recommendations
                if item.recommender_global_trust
                >= self.trust_config.trust_threshold
            ]
        if not filtered:
            return None
        values = [item.value for item in filtered]
        weights = [
            max(
                1e-12,
                item.recommender_global_trust
                + item.requester_recommender_trust,
            )
            for item in filtered
        ]
        return _clip01(self._weighted_mean(values, weights))

    def _twsl_trust(
        self,
        evidence: PairwiseEvidence,
        recommendations: List[Recommendation],
    ) -> float:
        """Paper-aligned TWSL surrogate on the shared synthetic evidence.

        The source paper defines subjective opinions, interaction/event weights,
        trajectory similarity and opinion fusion. The CBTDS manuscript does not
        publish the trajectories or pairwise histories used for its baseline.
        We therefore retain the published opinion/fusion structure and use
        recommender trust as the common-scene evidence-quality weight.
        """

        positive = max(0.0, evidence.alpha - 1.0)
        negative = max(0.0, evidence.beta - 1.0)
        # The TWSL source states that negative events carry greater influence.
        # A fixed 3:1 negative-to-positive evidence ratio is preregistered for
        # this aligned surrogate because CBTDS does not report the baseline's
        # exact per-event stream.
        weighted_negative = 3.0 * negative
        total = positive + weighted_negative
        direct_probability = positive / total if total else 0.5
        local_uncertainty = 2.0 / (total + 2.0)
        local_belief = (1.0 - local_uncertainty) * direct_probability
        local_disbelief = (1.0 - local_uncertainty) * (1.0 - direct_probability)

        rec_values = [item.value for item in recommendations]
        # Interaction/trajectory information is unavailable in the CBTDS
        # manuscript's simulator. Global recommender trust is the preregistered
        # shared-scene quality proxy; no hard filtering is applied.
        rec_weights = [0.5 + 0.5 * item.recommender_global_trust for item in recommendations]
        rec_probability = self._weighted_mean(rec_values, rec_weights)
        rec_uncertainty = 2.0 / (len(recommendations) + 2.0)
        rec_belief = (1.0 - rec_uncertainty) * rec_probability
        rec_disbelief = (1.0 - rec_uncertainty) * (1.0 - rec_probability)

        denominator = (
            local_uncertainty
            + rec_uncertainty
            - local_uncertainty * rec_uncertainty
        )
        if denominator <= 1e-12:
            return direct_probability
        final_belief = (
            local_belief * rec_uncertainty
            + rec_belief * local_uncertainty
        ) / denominator
        final_uncertainty = (
            local_uncertainty * rec_uncertainty / denominator
        )
        # gamma=0.5 is the default used in the TWSL source.
        _ = local_disbelief, rec_disbelief
        return _clip01(final_belief + 0.5 * final_uncertainty)

    def _recommendation_trust(
        self,
        evidence: PairwiseEvidence,
        recommendations: List[Recommendation],
    ) -> float:
        """Paper-aligned Shabut recommendation-model surrogate.

        It retains Beta direct trust, decay-compatible accumulated evidence,
        a robust recommendation cluster and dynamic direct/indirect weights.
        Location and pair-specific history are not available in CBTDS, so this
        is explicitly not labelled an exact implementation of Shabut et al.
        """

        positive = max(0.0, evidence.alpha - 1.0)
        negative = max(0.0, evidence.beta - 1.0)
        # Shabut et al. use decayed Beta evidence. The common generator has no
        # inactivity gaps, so we use a milder 2.0x negative-event weight as the
        # declared aligned surrogate.
        direct = (positive + 1.0) / (
            positive + 2.0 * negative + 2.0
        )
        values = [item.value for item in recommendations]
        centre = median(values)
        deviations = [abs(value - centre) for value in values]
        mad = median(deviations)
        tolerance = max(0.10, 2.5 * mad)
        kept = [
            item
            for item in recommendations
            if abs(item.value - centre) <= tolerance
        ]
        if not kept:
            kept = recommendations
        confidence_weights = [
            0.25 + 0.75 * item.recommender_global_trust for item in kept
        ]
        indirect = self._weighted_mean(
            [item.value for item in kept], confidence_weights
        )
        observations = max(0.0, evidence.alpha + evidence.beta - 2.0)
        direct_weight = min(0.80, max(0.20, observations / (observations + 10.0)))
        return _clip01(
            direct_weight * direct + (1.0 - direct_weight) * indirect
        )

    def run(
        self,
        malicious_fraction: float,
        seed: int,
        method: str = "cbtds",
        decision_mode: str = "final",
    ) -> PopulationResult:
        if not 0.0 < malicious_fraction < 1.0:
            raise ValueError("malicious_fraction must be in (0, 1)")
        if method not in self.METHODS:
            raise ValueError(f"method must be one of {self.METHODS}")
        if decision_mode not in ("final", "ever"):
            raise ValueError("decision_mode must be 'final' or 'ever'")

        cfg = self.population_config
        rng = random.Random(seed)
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
                # Attackers are not assumed to emit a bad message in every
                # round. Intermittent good behavior makes the experiment test
                # trust memory rather than trivially separating two Gaussians.
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

                candidates = [item for item in vehicle_ids if item != target]
                selected = rng.sample(candidates, cfg.recommenders_per_target)
                recommendations: List[Recommendation] = []
                for recommender in selected:
                    honest_report = _clip01(rng.gauss(quality_mean, cfg.report_std))
                    # Colluding attackers bad-mouth benign vehicles and
                    # ballot-stuff malicious vehicles.
                    if recommender in malicious:
                        # Colluders bad-mouth benign identities and
                        # ballot-stuff malicious identities, irrespective of
                        # the target's current on/off behavior.
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
                        direct_trust=direct,
                        indirect_trust=indirect,
                        recommendation_count=len(recommendations),
                        neighbor_count=cfg.recommenders_per_target,
                    )
                    next_trust[target] = self.model.update_global_trust(
                        current=current,
                        previous=trust[target],
                    )
                elif method == "twsl_aligned":
                    next_trust[target] = self._twsl_trust(
                        evidence[target], recommendations
                    )
                else:
                    next_trust[target] = self._recommendation_trust(
                        evidence[target], recommendations
                    )
            trust = next_trust
            ever_predicted_malicious.update(
                vehicle_id
                for vehicle_id, value in trust.items()
                if self.model.is_malicious(value)
            )

        if decision_mode == "ever":
            predicted_malicious = ever_predicted_malicious
        else:
            predicted_malicious = {
                vehicle_id
                for vehicle_id, value in trust.items()
                if self.model.is_malicious(value)
            }
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

        return PopulationResult(
            method=method,
            decision_mode=decision_mode,
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
            false_positive_rate=fp / len(benign),
            precision=precision,
            accuracy=(tp + tn) / cfg.num_vehicles,
            f1=f1,
            mean_benign_trust=sum(trust[item] for item in benign) / len(benign),
            mean_malicious_trust=(
                sum(trust[item] for item in malicious) / len(malicious)
            ),
        )
