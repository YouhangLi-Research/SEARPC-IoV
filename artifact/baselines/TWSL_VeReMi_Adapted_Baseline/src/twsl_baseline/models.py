from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


_TOL = 1e-9


def _unit_interval(name: str, value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} must lie in [0, 1], got {value}")


@dataclass(frozen=True)
class Opinion:
    """A binomial subjective-logic opinion (b, d, u) and base rate."""

    belief: float
    distrust: float
    uncertainty: float
    base_rate: float = 0.5

    def __post_init__(self) -> None:
        for name in ("belief", "distrust", "uncertainty", "base_rate"):
            _unit_interval(name, float(getattr(self, name)))
        total = self.belief + self.distrust + self.uncertainty
        if abs(total - 1.0) > _TOL:
            raise ValueError(f"opinion components must sum to one, got {total}")

    @property
    def expectation(self) -> float:
        return self.belief + self.base_rate * self.uncertainty

    def as_dict(self, prefix: str = "") -> dict[str, float]:
        return {
            f"{prefix}belief": self.belief,
            f"{prefix}distrust": self.distrust,
            f"{prefix}uncertainty": self.uncertainty,
            f"{prefix}reputation": self.expectation,
        }


@dataclass(frozen=True)
class Interaction:
    timestamp: float
    requestor_id: str
    provider_id: str
    positive: bool
    communication_quality: float

    def __post_init__(self) -> None:
        _unit_interval("communication_quality", self.communication_quality)
        if self.requestor_id == self.provider_id:
            raise ValueError("self-interactions are not supported")


@dataclass(frozen=True)
class TrajectoryPoint:
    timestamp: float
    vehicle_id: str
    x: float
    y: float
    speed: float | None = None
    direction: float | None = None

    def __post_init__(self) -> None:
        if self.speed is not None and self.speed < 0.0:
            raise ValueError("speed must be non-negative")


@dataclass(frozen=True)
class LocalOpinionRecord:
    requestor_id: str
    provider_id: str
    opinion: Opinion
    interaction_frequency: float
    trajectory_similarity: float
    weight: float
    positive_events: int = 0
    negative_events: int = 0
    communication_quality: float = 0.0

    def __post_init__(self) -> None:
        if self.interaction_frequency < 0.0:
            raise ValueError("interaction_frequency must be non-negative")
        _unit_interval("trajectory_similarity", self.trajectory_similarity)
        if self.weight < 0.0:
            raise ValueError("weight must be non-negative")


@dataclass(frozen=True)
class ReputationRecord:
    requestor_id: str
    provider_id: str
    local_opinion: Opinion
    recommended_opinion: Opinion | None
    final_opinion: Opinion
    recommendation_count: int
    local_weight: float
    local_interaction_frequency: float
    local_trajectory_similarity: float


@dataclass(frozen=True)
class TWSLConfig:
    """Algorithm configuration.

    Defaults reproduce the numeric values in Table II of Kang et al. The paper
    text says theta < tau, but Table II reports theta=0.6 and tau=0.4. The
    default therefore preserves the table literally and records the conflict in
    the run manifest. Set enforce_text_inequalities=True only for a declared
    sensitivity run using a constraint-consistent configuration.
    """

    gamma: float = 0.5
    theta_positive: float = 0.6
    tau_negative: float = 0.4
    zeta_recent: float = 0.6
    sigma_past: float = 0.4
    psi_speed: float = 0.3
    psi_location: float = 0.4
    psi_direction: float = 0.3
    rho_frequency: float = 0.5
    rho_similarity: float = 0.5
    recent_horizon_seconds: float = 7.0 * 24.0 * 60.0 * 60.0
    history_window_seconds: float | None = None
    update_period_seconds: float = 15.0 * 60.0
    lcs_position_tolerance: float = 0.0
    missing_trajectory_policy: str = "error"
    communication_quality_default: float | None = None
    enforce_text_inequalities: bool = False
    profile_name: str = "paper_table_ii_literal"
    evaluation_protocol: str = "paper_aligned"

    def __post_init__(self) -> None:
        for name in (
            "gamma",
            "theta_positive",
            "tau_negative",
            "zeta_recent",
            "sigma_past",
            "psi_speed",
            "psi_location",
            "psi_direction",
            "rho_frequency",
            "rho_similarity",
        ):
            _unit_interval(name, float(getattr(self, name)))
        for names in (
            ("theta_positive", "tau_negative"),
            ("zeta_recent", "sigma_past"),
            ("psi_speed", "psi_location", "psi_direction"),
            ("rho_frequency", "rho_similarity"),
        ):
            total = sum(float(getattr(self, name)) for name in names)
            if abs(total - 1.0) > _TOL:
                raise ValueError(f"{names} must sum to one, got {total}")
        if self.enforce_text_inequalities:
            if not self.theta_positive < self.tau_negative:
                raise ValueError("paper text requires theta_positive < tau_negative")
            if not self.zeta_recent > self.sigma_past:
                raise ValueError("paper text requires zeta_recent > sigma_past")
        if self.recent_horizon_seconds <= 0.0:
            raise ValueError("recent_horizon_seconds must be positive")
        if self.history_window_seconds is not None and self.history_window_seconds <= 0.0:
            raise ValueError("history_window_seconds must be positive or null")
        if self.update_period_seconds <= 0.0:
            raise ValueError("update_period_seconds must be positive")
        if self.lcs_position_tolerance < 0.0:
            raise ValueError("lcs_position_tolerance must be non-negative")
        if self.missing_trajectory_policy not in {"error", "zero", "neutral", "identical"}:
            raise ValueError("invalid missing_trajectory_policy")
        if self.communication_quality_default is not None:
            _unit_interval("communication_quality_default", self.communication_quality_default)
        if self.evaluation_protocol not in {"paper_aligned", "veremi_adapted"}:
            raise ValueError("evaluation_protocol must be paper_aligned or veremi_adapted")
        if self.evaluation_protocol == "veremi_adapted" and self.history_window_seconds is None:
            raise ValueError(
                "VeReMi adaptation requires a finite synchronized history_window_seconds"
            )

    @property
    def paper_text_weight_conflict(self) -> bool:
        return not self.theta_positive < self.tau_negative

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> "TWSLConfig":
        known = {field.name for field in cls.__dataclass_fields__.values()}
        unexpected = sorted(set(values) - known)
        if unexpected:
            raise ValueError(f"unknown configuration keys: {unexpected}")
        return cls(**values)
