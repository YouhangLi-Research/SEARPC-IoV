"""Executable scoped evidence evidence-authority helpers."""
from __future__ import annotations

import numpy as np


def apply_malicious_authority_gate(weights, malicious_state):
    """Zero opinion-fusion authority for entities in the malicious state.

    `uncertain` and `trusted` are not hard separated here: their continuous
    influence remains encoded in the supplied LCB/mean weight.  No new tuning
    threshold is introduced.
    """
    w = np.asarray(weights, dtype=float)
    blocked = np.asarray(malicious_state, dtype=bool)
    if w.shape != blocked.shape:
        raise ValueError("weights and malicious_state must have identical shape")
    out = w.copy()
    out[blocked] = 0.0
    return out
