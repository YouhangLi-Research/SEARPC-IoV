"""Missing Figure 6-7 experiment structures without changing frozen trust code."""

from __future__ import annotations

from dataclasses import dataclass
import random
from statistics import mean
from typing import Dict, List

from .config import CBTDSConfig
from .model import Recommendation, TrustModel
from .population import PopulationSimulator
from .simulation import ObserverState, TrustTrajectorySimulator


@dataclass(frozen=True)
class CommonStepEvent:
    minute: int
    active_behavior: str
    observed_qualities: tuple[float, ...]
    background_increments: tuple[int, ...]


@dataclass(frozen=True)
class PaperTrajectoryPoint:
    minute: int
    scenario: str
    method: str
    active_behavior: str
    global_trust: float
    malicious_decision: bool
    blacklisted: bool


class PaperTrajectorySimulator:
    """Paired trajectory simulator for manuscript Figures 6 and 7."""

    METHODS = ("cbtds", "twsl_aligned", "recommendation_aligned")
    FIGURE7_SCENARIOS = ("figure7a", "figure7b", "figure7c")
    ALL_SCENARIOS = ("persistent_malicious",) + FIGURE7_SCENARIOS
    SCENARIO_OFFSETS = {
        "persistent_malicious": 10_000,
        "figure7a": 70_000,
        "figure7b": 80_000,
        "figure7c": 90_000,
    }

    def __init__(self, config: CBTDSConfig) -> None:
        self.config = config
        self.model = TrustModel(config)
        self.frozen_simulator = TrustTrajectorySimulator(config)
        self.aligned_baselines = PopulationSimulator(config)

    @staticmethod
    def active_behavior(scenario: str, minute: int) -> str:
        if scenario == "persistent_malicious":
            return "malicious"
        if scenario == "figure7a":
            return "normal" if minute <= 40 else "malicious"
        if scenario == "figure7b":
            if minute <= 40:
                return "malicious"
            return "normal" if minute <= 80 else "malicious"
        if scenario == "figure7c":
            return "malicious" if minute <= 80 else "normal"
        raise ValueError(f"unknown scenario: {scenario}")

    def _common_events(self, scenario: str) -> List[CommonStepEvent]:
        if scenario not in self.ALL_SCENARIOS:
            raise ValueError(f"scenario must be one of {self.ALL_SCENARIOS}")
        rng = random.Random(
            self.config.random_seed + self.SCENARIO_OFFSETS[scenario]
        )
        observer_templates = self.frozen_simulator._observers()
        events = []
        for step in range(1, self.config.num_steps + 1):
            minute = step * self.config.update_interval_minutes
            behavior = self.active_behavior(scenario, minute)
            qualities = []
            background = []
            for observer in observer_templates:
                honest_quality = self.frozen_simulator._honest_quality(
                    behavior, rng
                )
                qualities.append(
                    1.0 - honest_quality
                    if observer.is_dishonest
                    else honest_quality
                )
                background.append(rng.randint(1, 3))
            events.append(
                CommonStepEvent(
                    minute=minute,
                    active_behavior=behavior,
                    observed_qualities=tuple(qualities),
                    background_increments=tuple(background),
                )
            )
        return events

    def _recommendations(
        self,
        observer: ObserverState,
        observers: List[ObserverState],
        direct_values: Dict[str, float],
    ) -> List[Recommendation]:
        output = []
        for recommender in observers:
            if recommender.observer_id == observer.observer_id:
                continue
            output.append(
                Recommendation(
                    value=direct_values[recommender.observer_id],
                    recommender_global_trust=recommender.global_trust,
                    requester_recommender_trust=(
                        0.35 if recommender.is_dishonest else 0.82
                    ),
                    is_pretrusted=recommender.is_pretrusted,
                )
            )
        return output

    def _run_method(
        self,
        scenario: str,
        method: str,
        events: List[CommonStepEvent],
    ) -> List[PaperTrajectoryPoint]:
        if method not in self.METHODS:
            raise ValueError(f"method must be one of {self.METHODS}")
        observers = self.frozen_simulator._observers()
        previous_global_trust = 0.5
        blacklisted = False
        points = [
            PaperTrajectoryPoint(
                minute=0,
                scenario=scenario,
                method=method,
                active_behavior=self.active_behavior(scenario, 0),
                global_trust=previous_global_trust,
                malicious_decision=self.model.is_malicious(
                    previous_global_trust
                ),
                blacklisted=False,
            )
        ]

        for event in events:
            if method == "cbtds" and blacklisted and event.active_behavior == "normal":
                points.append(
                    PaperTrajectoryPoint(
                        minute=event.minute,
                        scenario=scenario,
                        method=method,
                        active_behavior=event.active_behavior,
                        global_trust=previous_global_trust,
                        malicious_decision=True,
                        blacklisted=True,
                    )
                )
                continue

            direct_values: Dict[str, float] = {}
            for index, observer in enumerate(observers):
                quality = event.observed_qualities[index]
                observer.evidence.observe(
                    quality, self.config.trust_threshold
                )
                observer.background_interactions += (
                    event.background_increments[index]
                )
                direct = self.model.direct_trust(
                    observer.evidence,
                    observer.evidence.interactions
                    + observer.background_interactions,
                )
                if direct is None:
                    raise RuntimeError("direct trust missing after observation")
                direct_values[observer.observer_id] = direct

            reports: Dict[str, float] = {}
            for index, observer in enumerate(observers):
                recommendations = self._recommendations(
                    observer, observers, direct_values
                )
                if method == "cbtds":
                    indirect = self.model.indirect_trust(recommendations)
                    reports[observer.observer_id] = self.model.final_trust(
                        data_quality=event.observed_qualities[index],
                        direct_trust=direct_values[observer.observer_id],
                        indirect_trust=indirect,
                        recommendation_count=len(recommendations),
                        neighbor_count=len(observers) - 1,
                    )
                elif method == "twsl_aligned":
                    reports[observer.observer_id] = (
                        self.aligned_baselines._twsl_trust(
                            observer.evidence, recommendations
                        )
                    )
                else:
                    reports[observer.observer_id] = (
                        self.aligned_baselines._recommendation_trust(
                            observer.evidence, recommendations
                        )
                    )

            if method == "cbtds":
                pretrusted_reports = [
                    reports[observer.observer_id]
                    for observer in observers
                    if observer.is_pretrusted
                ]
                common_reports = [
                    reports[observer.observer_id]
                    for observer in observers
                    if not observer.is_pretrusted
                ]
                current_trust = self.model.aggregate_current_trust(
                    common_reports=common_reports,
                    pretrusted_reports=pretrusted_reports,
                )
                previous_global_trust = self.model.update_global_trust(
                    current=current_trust,
                    previous=previous_global_trust,
                )
                blacklisted = blacklisted or self.model.is_malicious(
                    previous_global_trust
                )
            else:
                previous_global_trust = mean(reports.values())

            points.append(
                PaperTrajectoryPoint(
                    minute=event.minute,
                    scenario=scenario,
                    method=method,
                    active_behavior=event.active_behavior,
                    global_trust=previous_global_trust,
                    malicious_decision=self.model.is_malicious(
                        previous_global_trust
                    ),
                    blacklisted=blacklisted if method == "cbtds" else False,
                )
            )
        return points

    def run_scenario(
        self, scenario: str
    ) -> Dict[str, List[PaperTrajectoryPoint]]:
        events = self._common_events(scenario)
        return {
            method: self._run_method(scenario, method, events)
            for method in self.METHODS
        }
