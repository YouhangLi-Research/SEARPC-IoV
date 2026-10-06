"""Paper-aligned Three-Weight Subjective Logic (TWSL) baseline."""

from .core import (
    combine_local_and_recommended,
    interaction_frequency,
    local_opinion,
    recommended_opinion,
)
from .models import (
    Interaction,
    LocalOpinionRecord,
    Opinion,
    TrajectoryPoint,
    TWSLConfig,
)
from .pipeline import build_local_opinions, compute_reputations

__all__ = [
    "Interaction",
    "LocalOpinionRecord",
    "Opinion",
    "TrajectoryPoint",
    "TWSLConfig",
    "build_local_opinions",
    "combine_local_and_recommended",
    "compute_reputations",
    "interaction_frequency",
    "local_opinion",
    "recommended_opinion",
]

__version__ = "2.0.0"
