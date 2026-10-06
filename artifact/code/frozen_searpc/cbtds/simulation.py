"""Deterministic first-stage simulation for CBTDS trust trajectories."""

from __future__ import annotations

from dataclasses import dataclass, field
import random
from typing import Dict, Iterable, List

from .config import CBTDSConfig
from .model import PairwiseEvidence, Recommendation, TrustModel


@dataclass
class ObserverState:
    observer_id: str
    global_trust: float
    is_pretrusted: bool
    is_dishonest: bool = False
    evidence: PairwiseEvidence = field(default_factory=PairwiseEvidence)
    background_interactions: int = 0


@dataclass(frozen=True)
class TrajectoryPoint:
    minute: int
    profile: str
    active_behavior: str
    global_trust: float
    malicious_decision: bool


class TrustTrajectorySimulator:
    """Simulate one provider observed by a small vehicular neighborhood."""

    PROFILES = ("normal", "persistent_malicious", "swing")

    def __init__(self, config: CBTDSConfig) -> None:
        self.config = config
        self.model = TrustModel(config)

    def _observers(self) -> List[ObserverState]:
        observers: List[ObserverState] = []
        for index in range(self.config.num_observers):
            is_pretrusted = index < self.config.num_pretrusted_observers
            # The last two ordinary observers model dishonest recommenders.
            is_dishonest = index >= self.config.num_observers - 2
            if is_pretrusted:
                global_trust = 0.95
            elif is_dishonest:
                global_trust = 0.35
            else:
                global_trust = 0.78 + 0.02 * (index % 4)
            observers.append(
                ObserverState(
                    observer_id=f"observer_{index:02d}",
                    global_trust=global_trust,
                    is_pretrusted=is_pretrusted,
                    is_dishonest=is_dishonest,
                )
            )
        return observers

    @staticmethod
    def active_behavior(profile: str, minute: int) -> str:
        if profile == "normal":
            return "normal"
        if profile == "persistent_malicious":
            return "malicious"
        if profile == "swing":
            if minute <= 40:
                return "normal"
            if minute <= 80:
                return "malicious"
            return "normal"
        raise ValueError(f"unknown profile: {profile}")

    @staticmethod
    def _honest_quality(behavior: str, rng: random.Random) -> float:
        if behavior == "normal":
            return min(1.0, max(0.0, rng.gauss(0.88, 0.055)))
        return min(1.0, max(0.0, rng.gauss(0.12, 0.055)))

    def run_profile(self, profile: str) -> List[TrajectoryPoint]:
        if profile not in self.PROFILES:
            raise ValueError(f"profile must be one of {self.PROFILES}")

        # Give every profile an independent but reproducible stream.
        profile_offset = self.PROFILES.index(profile) * 10_000
        rng = random.Random(self.config.random_seed + profile_offset)
        observers = self._observers()
        previous_global_trust = 0.5
        points = [
            TrajectoryPoint(
                minute=0,
                profile=profile,
                active_behavior=self.active_behavior(profile, 0),
                global_trust=previous_global_trust,
                malicious_decision=self.model.is_malicious(previous_global_trust),
            )
        ]

        for step in range(1, self.config.num_steps + 1):
            minute = step * self.config.update_interval_minutes
            behavior = self.active_behavior(profile, minute)

            # Algorithm 1 / equation (13): once an attacker has fallen below
            # the trust threshold, honest vehicles keep it on their local
            # blacklist and do not provide fresh positive interactions merely
            # because it switches back to normal behavior.  This is essential
            # to the paper's claimed swing-attack resistance.
            if (
                profile != "normal"
                and behavior == "normal"
                and self.model.is_malicious(previous_global_trust)
            ):
                points.append(
                    TrajectoryPoint(
                        minute=minute,
                        profile=profile,
                        active_behavior=behavior,
                        global_trust=previous_global_trust,
                        malicious_decision=True,
                    )
                )
                continue

            observed_quality: Dict[str, float] = {}
            direct_values: Dict[str, float] = {}

            for observer in observers:
                honest_quality = self._honest_quality(behavior, rng)
                if observer.is_dishonest:
                    # Bad-mouthing a normal provider and ballot-stuffing a
                    # malicious provider. Their low global trust should remove
                    # these values from indirect recommendations.
                    quality = 1.0 - honest_quality
                else:
                    quality = honest_quality
                observed_quality[observer.observer_id] = quality
                observer.evidence.observe(quality, self.config.trust_threshold)
                observer.background_interactions += rng.randint(1, 3)
                total_interactions = (
                    observer.evidence.interactions
                    + observer.background_interactions
                )
                direct = self.model.direct_trust(
                    observer.evidence, total_interactions
                )
                if direct is None:
                    raise RuntimeError("direct trust must exist after observation")
                direct_values[observer.observer_id] = direct

            final_reports: Dict[str, float] = {}
            for observer in observers:
                recommendations = []
                for recommender in observers:
                    if recommender.observer_id == observer.observer_id:
                        continue
                    recommendations.append(
                        Recommendation(
                            value=direct_values[recommender.observer_id],
                            recommender_global_trust=recommender.global_trust,
                            requester_recommender_trust=(
                                0.35 if recommender.is_dishonest else 0.82
                            ),
                            is_pretrusted=recommender.is_pretrusted,
                        )
                    )
                indirect = self.model.indirect_trust(recommendations)
                final_reports[observer.observer_id] = self.model.final_trust(
                    data_quality=observed_quality[observer.observer_id],
                    direct_trust=direct_values[observer.observer_id],
                    indirect_trust=indirect,
                    recommendation_count=len(recommendations),
                    neighbor_count=len(observers) - 1,
                )

            pretrusted_reports = [
                final_reports[observer.observer_id]
                for observer in observers
                if observer.is_pretrusted
            ]
            common_reports = [
                final_reports[observer.observer_id]
                for observer in observers
                if not observer.is_pretrusted
            ]
            current_trust = self.model.aggregate_current_trust(
                common_reports=common_reports,
                pretrusted_reports=pretrusted_reports,
            )
            previous_global_trust = self.model.update_global_trust(
                current=current_trust, previous=previous_global_trust
            )
            points.append(
                TrajectoryPoint(
                    minute=minute,
                    profile=profile,
                    active_behavior=behavior,
                    global_trust=previous_global_trust,
                    malicious_decision=self.model.is_malicious(
                        previous_global_trust
                    ),
                )
            )
        return points

    def run_all(self) -> Dict[str, List[TrajectoryPoint]]:
        return {profile: self.run_profile(profile) for profile in self.PROFILES}


def flatten_trajectories(
    trajectories: Dict[str, Iterable[TrajectoryPoint]],
) -> List[TrajectoryPoint]:
    return [point for profile in TrustTrajectorySimulator.PROFILES for point in trajectories[profile]]
