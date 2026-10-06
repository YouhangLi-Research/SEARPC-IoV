"""Configuration values for the CBTDS trust-model reproduction.

Values explicitly reported by the paper are separated from simulation choices
that the paper leaves unspecified.  The latter are documented in
``IMPLEMENTATION_ASSUMPTIONS.md``.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CBTDSConfig:
    """Parameters used by the trust model and the first smoke simulation."""

    # Reported in Table II / Section VII.
    trust_threshold: float = 0.5
    direct_weight: float = 0.6
    data_quality_weight: float = 0.35
    direct_final_weight: float = 0.30
    indirect_final_weight: float = 0.35
    history_floor: float = 0.2

    # The paper introduces xi but does not provide an unambiguous Table-II
    # value in the uploaded manuscript.  We pre-register 0.6 for the pilot.
    pretrusted_weight: float = 0.6

    # Simulation choices needed to instantiate equations (6), (15)-(17).
    penalty_gamma: float = 0.2
    recovery_regulator: float = 4.0
    update_interval_minutes: int = 2
    total_minutes: int = 120

    # First milestone: ten observers, including two pre-trusted observers.
    num_observers: int = 10
    num_pretrusted_observers: int = 2
    ratings_per_step: int = 10
    random_seed: int = 3407

    def __post_init__(self) -> None:
        if not 0.0 < self.trust_threshold < 1.0:
            raise ValueError("trust_threshold must be in (0, 1)")
        final_weight_sum = (
            self.data_quality_weight
            + self.direct_final_weight
            + self.indirect_final_weight
        )
        if abs(final_weight_sum - 1.0) > 1e-12:
            raise ValueError("the three final-trust weights must sum to one")
        for name in ("direct_weight", "history_floor", "pretrusted_weight"):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be in [0, 1]")
        if self.total_minutes % self.update_interval_minutes != 0:
            raise ValueError("total_minutes must be divisible by the update interval")

    @property
    def num_steps(self) -> int:
        return self.total_minutes // self.update_interval_minutes
