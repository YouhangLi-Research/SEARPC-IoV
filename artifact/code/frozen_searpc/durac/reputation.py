"""Role-separated Bayesian reputation state for DURAC-IoV."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
from typing import Dict, Hashable, Tuple

from scipy.stats import beta as beta_distribution


class Role(str, Enum):
    DATA_PROVIDER = "data_provider"
    OPINION_PROVIDER = "opinion_provider"
    VALIDATOR = "validator"


@dataclass
class BetaRolePosterior:
    """Fractional-count Beta posterior for one entity in one role."""

    alpha: float = 1.0
    beta: float = 1.0
    prior_alpha: float = 1.0
    prior_beta: float = 1.0

    def __post_init__(self) -> None:
        for name, value in (
            ("alpha", self.alpha),
            ("beta", self.beta),
            ("prior_alpha", self.prior_alpha),
            ("prior_beta", self.prior_beta),
        ):
            if not isfinite(value) or value <= 0.0:
                raise ValueError(f"{name} must be finite and positive")
        if self.alpha < self.prior_alpha or self.beta < self.prior_beta:
            raise ValueError("posterior counts cannot be below prior counts")

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def evidence_count(self) -> float:
        return (
            self.alpha
            + self.beta
            - self.prior_alpha
            - self.prior_beta
        )

    def lower_credible_bound(self, quantile: float = 0.05) -> float:
        if not 0.0 < quantile < 0.5:
            raise ValueError("quantile must be in (0, 0.5)")
        return float(beta_distribution.ppf(quantile, self.alpha, self.beta))

    def upper_credible_bound(self, quantile: float = 0.95) -> float:
        if not 0.5 < quantile < 1.0:
            raise ValueError("quantile must be in (0.5, 1)")
        return float(beta_distribution.ppf(quantile, self.alpha, self.beta))

    def update(
        self,
        success: float,
        *,
        weight: float = 1.0,
        decay: float = 1.0,
    ) -> None:
        if not isfinite(success) or not 0.0 <= success <= 1.0:
            raise ValueError("success must be finite and in [0, 1]")
        if not isfinite(weight) or weight < 0.0:
            raise ValueError("weight must be finite and non-negative")
        if not isfinite(decay) or not 0.0 < decay <= 1.0:
            raise ValueError("decay must be finite and in (0, 1]")
        self.alpha = (
            self.prior_alpha
            + decay * (self.alpha - self.prior_alpha)
            + weight * success
        )
        self.beta = (
            self.prior_beta
            + decay * (self.beta - self.prior_beta)
            + weight * (1.0 - success)
        )


@dataclass
class RoleReputationBook:
    """Independent posterior state for every entity-role pair."""

    prior_alpha: float = 1.0
    prior_beta: float = 1.0
    _posteriors: Dict[Tuple[Hashable, Role], BetaRolePosterior] = field(
        default_factory=dict
    )

    def posterior(self, entity_id: Hashable, role: Role) -> BetaRolePosterior:
        key = (entity_id, Role(role))
        if key not in self._posteriors:
            self._posteriors[key] = BetaRolePosterior(
                alpha=self.prior_alpha,
                beta=self.prior_beta,
                prior_alpha=self.prior_alpha,
                prior_beta=self.prior_beta,
            )
        return self._posteriors[key]

    def update(
        self,
        entity_id: Hashable,
        role: Role,
        success: float,
        *,
        weight: float = 1.0,
        decay: float = 1.0,
    ) -> None:
        self.posterior(entity_id, role).update(
            success, weight=weight, decay=decay
        )

    def lower_bound(
        self, entity_id: Hashable, role: Role, quantile: float = 0.05
    ) -> float:
        return self.posterior(entity_id, role).lower_credible_bound(quantile)

