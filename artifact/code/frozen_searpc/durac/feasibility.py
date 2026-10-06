"""Trace-driven minimum feasibility comparison for DURAC and frozen CBTDS."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import isfinite
import random
from typing import DefaultDict, Dict, Iterable, List, Sequence, Tuple

from cbtds import CBTDSConfig
from cbtds.model import PairwiseEvidence, Recommendation, TrustModel

from .fusion import Opinion, robust_opinion_fusion
from .reputation import Role, RoleReputationBook
from .risk import assess_event


def _clip01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


@dataclass(frozen=True)
class FeasibilityConfig:
    num_vehicles: int = 96
    num_pretrusted: int = 10
    num_domains: int = 8
    num_rounds: int = 60
    events_per_round: int = 48
    opinions_per_event: int = 9
    provider_malicious_fraction: float = 0.30
    opinion_malicious_fraction: float = 0.30
    role_overlap_fraction: float = 0.50
    honest_false_probability: float = 0.02
    attacker_false_probability: float = 0.80
    attack_windows: Tuple[Tuple[int, int], ...] = ((15, 29), (45, 59))
    credible_message_mean: float = 0.82
    false_message_mean: float = 0.18
    message_probability_std: float = 0.12
    epistemic_uncertainty: float = 0.10
    honest_credible_opinion_mean: float = 0.85
    honest_false_opinion_mean: float = 0.15
    ballot_stuffing_mean: float = 0.95
    bad_mouthing_mean: float = 0.05
    opinion_std: float = 0.10
    adjudication_delay: int = 3
    criticality: float = 1.0
    lcb_quantile: float = 0.05
    decision_threshold: float = 0.50

    def __post_init__(self) -> None:
        if self.num_vehicles < 10:
            raise ValueError("num_vehicles must be at least 10")
        if not 0 <= self.num_pretrusted < self.num_vehicles:
            raise ValueError("invalid num_pretrusted")
        if not 1 <= self.num_domains <= self.num_vehicles:
            raise ValueError("invalid num_domains")
        if self.num_rounds <= 0 or self.events_per_round <= 0:
            raise ValueError("round and event counts must be positive")
        if not 1 <= self.opinions_per_event <= self.num_vehicles - 2:
            raise ValueError("invalid opinions_per_event")
        for name in (
            "provider_malicious_fraction",
            "opinion_malicious_fraction",
            "role_overlap_fraction",
            "honest_false_probability",
            "attacker_false_probability",
            "epistemic_uncertainty",
        ):
            value = getattr(self, name)
            if not isfinite(value) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if self.adjudication_delay < 0:
            raise ValueError("adjudication_delay must be non-negative")


@dataclass(frozen=True)
class ClassificationMetrics:
    true_positive: int
    false_negative: int
    false_positive: int
    true_negative: int
    recall: float
    false_negative_rate: float
    false_positive_rate: float
    precision: float
    f1: float
    accuracy: float


@dataclass(frozen=True)
class FeasibilityResult:
    seed: int
    provider_attackers: Tuple[int, ...]
    opinion_attackers: Tuple[int, ...]
    cbtds_provider: ClassificationMetrics
    durac_provider: ClassificationMetrics
    cbtds_opinion: ClassificationMetrics
    durac_opinion: ClassificationMetrics
    cbtds_event: ClassificationMetrics
    durac_event: ClassificationMetrics
    mean_durac_provider_lcb_honest: float
    mean_durac_provider_lcb_malicious: float
    mean_durac_opinion_lcb_honest: float
    mean_durac_opinion_lcb_malicious: float
    cbtds_honesty_scores: Tuple[float, ...]
    durac_provider_honesty_scores: Tuple[float, ...]
    durac_opinion_honesty_scores: Tuple[float, ...]


@dataclass(frozen=True)
class _PendingAdjudication:
    due_round: int
    provider_id: int
    credible: bool
    message_reliability: float
    opinions: Tuple[Opinion, ...]


def _classification(
    actual_positive: Iterable[int],
    predicted_positive: Iterable[int],
    universe: Iterable[int],
) -> ClassificationMetrics:
    actual = set(actual_positive)
    predicted = set(predicted_positive)
    all_items = set(universe)
    if not actual <= all_items or not predicted <= all_items:
        raise ValueError("actual and predicted sets must be inside universe")
    negative = all_items - actual
    tp = len(actual & predicted)
    fn = len(actual - predicted)
    fp = len(negative & predicted)
    tn = len(negative - predicted)
    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2.0 * precision * recall / (precision + recall) if precision + recall else 0.0
    return ClassificationMetrics(
        true_positive=tp,
        false_negative=fn,
        false_positive=fp,
        true_negative=tn,
        recall=recall,
        false_negative_rate=1.0 - recall,
        false_positive_rate=fpr,
        precision=precision,
        f1=f1,
        accuracy=(tp + tn) / len(all_items) if all_items else 0.0,
    )


class FeasibilitySimulator:
    """Generate one common trace and feed both trust systems."""

    def __init__(self, config: FeasibilityConfig | None = None) -> None:
        self.config = config or FeasibilityConfig()
        self.cbtds_config = CBTDSConfig()
        self.cbtds_model = TrustModel(self.cbtds_config)

    def _attack_active(self, round_index: int) -> bool:
        return any(start <= round_index <= end for start, end in self.config.attack_windows)

    def _select_attackers(
        self, rng: random.Random, vehicle_ids: Sequence[int]
    ) -> tuple[set[int], set[int]]:
        eligible = list(vehicle_ids[self.config.num_pretrusted :])
        provider_count = round(
            self.config.num_vehicles * self.config.provider_malicious_fraction
        )
        opinion_count = round(
            self.config.num_vehicles * self.config.opinion_malicious_fraction
        )
        provider_attackers = set(rng.sample(eligible, provider_count))
        overlap_count = min(
            provider_count,
            opinion_count,
            round(opinion_count * self.config.role_overlap_fraction),
        )
        overlap = set(rng.sample(sorted(provider_attackers), overlap_count))
        opinion_only_pool = sorted(set(eligible) - provider_attackers)
        opinion_only_count = opinion_count - overlap_count
        opinion_attackers = overlap | set(
            rng.sample(opinion_only_pool, opinion_only_count)
        )
        return provider_attackers, opinion_attackers

    def _apply_adjudication(
        self,
        item: _PendingAdjudication,
        book: RoleReputationBook,
    ) -> None:
        truth = 1.0 if item.credible else 0.0
        book.update(
            item.provider_id,
            Role.DATA_PROVIDER,
            truth,
            weight=item.message_reliability,
        )
        for opinion in item.opinions:
            honesty = 1.0 - abs(opinion.value - truth)
            book.update(
                opinion.recommender_id,
                Role.OPINION_PROVIDER,
                honesty,
            )

    def run(self, seed: int) -> FeasibilityResult:
        cfg = self.config
        rng = random.Random(seed)
        vehicle_ids = list(range(cfg.num_vehicles))
        pretrusted = set(vehicle_ids[: cfg.num_pretrusted])
        provider_attackers, opinion_attackers = self._select_attackers(
            rng, vehicle_ids
        )

        book = RoleReputationBook()
        cbtds_global: Dict[int, float] = {item: 0.5 for item in vehicle_ids}
        for item in pretrusted:
            cbtds_global[item] = 0.95
        cbtds_pair: DefaultDict[Tuple[int, int], PairwiseEvidence] = defaultdict(
            PairwiseEvidence
        )
        requester_total: DefaultDict[int, int] = defaultdict(int)
        pending: List[_PendingAdjudication] = []

        actual_false_events: set[int] = set()
        cbtds_false_events: set[int] = set()
        durac_false_events: set[int] = set()
        event_index = 0

        for round_index in range(cfg.num_rounds):
            due_now = [item for item in pending if item.due_round <= round_index]
            pending = [item for item in pending if item.due_round > round_index]
            for item in due_now:
                self._apply_adjudication(item, book)

            for _ in range(cfg.events_per_round):
                requester = rng.choice(vehicle_ids)
                provider = rng.choice([item for item in vehicle_ids if item != requester])
                is_attacker = provider in provider_attackers
                false_probability = (
                    cfg.attacker_false_probability
                    if is_attacker and self._attack_active(round_index)
                    else cfg.honest_false_probability
                )
                credible = rng.random() >= false_probability
                if not credible:
                    actual_false_events.add(event_index)

                probability_mean = (
                    cfg.credible_message_mean
                    if credible
                    else cfg.false_message_mean
                )
                message_probability = _clip01(
                    rng.gauss(probability_mean, cfg.message_probability_std)
                )
                message_reliability = 1.0 - cfg.epistemic_uncertainty

                recommender_pool = [
                    item for item in vehicle_ids
                    if item not in (requester, provider)
                ]
                recommender_ids = rng.sample(
                    recommender_pool, cfg.opinions_per_event
                )
                opinions: list[Opinion] = []
                cbtds_recommendations: list[Recommendation] = []
                for recommender in recommender_ids:
                    if recommender in opinion_attackers:
                        opinion_mean = (
                            cfg.ballot_stuffing_mean
                            if provider in provider_attackers
                            else cfg.bad_mouthing_mean
                        )
                    else:
                        opinion_mean = (
                            cfg.honest_credible_opinion_mean
                            if credible
                            else cfg.honest_false_opinion_mean
                        )
                    opinion_value = _clip01(
                        rng.gauss(opinion_mean, cfg.opinion_std)
                    )
                    opinion = Opinion(
                        recommender_id=recommender,
                        value=opinion_value,
                        domain=recommender % cfg.num_domains,
                    )
                    opinions.append(opinion)

                    requester_recommender_evidence = cbtds_pair.get(
                        (requester, recommender)
                    )
                    requester_recommender_trust = None
                    if requester_recommender_evidence is not None:
                        requester_recommender_trust = self.cbtds_model.direct_trust(
                            requester_recommender_evidence,
                            requester_total[requester],
                        )
                    cbtds_recommendations.append(
                        Recommendation(
                            value=opinion_value,
                            recommender_global_trust=cbtds_global[recommender],
                            requester_recommender_trust=(
                                requester_recommender_trust
                                if requester_recommender_trust is not None
                                else cbtds_global[recommender]
                            ),
                            is_pretrusted=recommender in pretrusted,
                        )
                    )

                pair_evidence = cbtds_pair[(requester, provider)]
                pair_evidence.observe(
                    message_probability, self.cbtds_config.trust_threshold
                )
                requester_total[requester] += 1
                direct = self.cbtds_model.direct_trust(
                    pair_evidence, requester_total[requester]
                )
                indirect = self.cbtds_model.indirect_trust(
                    cbtds_recommendations
                )
                current_cbtds = self.cbtds_model.final_trust(
                    data_quality=message_probability,
                    direct_trust=direct,
                    indirect_trust=indirect,
                    recommendation_count=len(cbtds_recommendations),
                    neighbor_count=len(recommender_pool),
                )
                cbtds_global[provider] = self.cbtds_model.update_global_trust(
                    current=current_cbtds,
                    previous=cbtds_global[provider],
                )
                if cbtds_global[provider] < cfg.decision_threshold:
                    cbtds_false_events.add(event_index)

                fusion = robust_opinion_fusion(
                    opinions,
                    book,
                    lcb_quantile=cfg.lcb_quantile,
                    evidence_reliability=message_reliability,
                )
                assessment = assess_event(
                    message_probability=message_probability,
                    epistemic_uncertainty=cfg.epistemic_uncertainty,
                    provider_lcb=book.lower_bound(
                        provider, Role.DATA_PROVIDER, cfg.lcb_quantile
                    ),
                    opinion=fusion,
                    criticality=cfg.criticality,
                    decision_threshold=cfg.decision_threshold,
                    bound_quantile=cfg.lcb_quantile,
                )
                if not assessment.credible_decision:
                    durac_false_events.add(event_index)

                pending.append(
                    _PendingAdjudication(
                        due_round=round_index + cfg.adjudication_delay,
                        provider_id=provider,
                        credible=credible,
                        message_reliability=message_reliability,
                        opinions=tuple(opinions),
                    )
                )
                event_index += 1

        for item in pending:
            self._apply_adjudication(item, book)

        durac_provider_predicted = {
            item
            for item in vehicle_ids
            if book.lower_bound(item, Role.DATA_PROVIDER, cfg.lcb_quantile)
            < cfg.decision_threshold
        }
        durac_opinion_predicted = {
            item
            for item in vehicle_ids
            if book.lower_bound(item, Role.OPINION_PROVIDER, cfg.lcb_quantile)
            < cfg.decision_threshold
        }
        cbtds_predicted = {
            item for item in vehicle_ids
            if cbtds_global[item] < cfg.decision_threshold
        }
        universe = set(vehicle_ids)
        event_universe = set(range(event_index))

        honest_providers = universe - provider_attackers
        honest_opinion = universe - opinion_attackers
        provider_lcbs = {
            item: book.lower_bound(item, Role.DATA_PROVIDER, cfg.lcb_quantile)
            for item in vehicle_ids
        }
        opinion_lcbs = {
            item: book.lower_bound(item, Role.OPINION_PROVIDER, cfg.lcb_quantile)
            for item in vehicle_ids
        }

        return FeasibilityResult(
            seed=seed,
            provider_attackers=tuple(sorted(provider_attackers)),
            opinion_attackers=tuple(sorted(opinion_attackers)),
            cbtds_provider=_classification(
                provider_attackers, cbtds_predicted, universe
            ),
            durac_provider=_classification(
                provider_attackers, durac_provider_predicted, universe
            ),
            cbtds_opinion=_classification(
                opinion_attackers, cbtds_predicted, universe
            ),
            durac_opinion=_classification(
                opinion_attackers, durac_opinion_predicted, universe
            ),
            cbtds_event=_classification(
                actual_false_events, cbtds_false_events, event_universe
            ),
            durac_event=_classification(
                actual_false_events, durac_false_events, event_universe
            ),
            mean_durac_provider_lcb_honest=sum(
                provider_lcbs[item] for item in honest_providers
            ) / len(honest_providers),
            mean_durac_provider_lcb_malicious=sum(
                provider_lcbs[item] for item in provider_attackers
            ) / len(provider_attackers),
            mean_durac_opinion_lcb_honest=sum(
                opinion_lcbs[item] for item in honest_opinion
            ) / len(honest_opinion),
            mean_durac_opinion_lcb_malicious=sum(
                opinion_lcbs[item] for item in opinion_attackers
            ) / len(opinion_attackers),
            cbtds_honesty_scores=tuple(cbtds_global[item] for item in vehicle_ids),
            durac_provider_honesty_scores=tuple(
                provider_lcbs[item] for item in vehicle_ids
            ),
            durac_opinion_honesty_scores=tuple(
                opinion_lcbs[item] for item in vehicle_ids
            ),
        )
