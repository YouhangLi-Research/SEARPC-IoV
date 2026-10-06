#!/usr/bin/env python3
"""Shared deterministic helpers for the frozen DURAC dual-path experiments.

The historical release omitted this small helper module even though closed loop--16
import it.  It contains no learned parameters and does not inspect current
compromise identities.  The audit provenance label is derived only from public
experiment coordinates so recovery certificates can require more than one
independent audit domain.
"""

from __future__ import annotations

from hashlib import sha256


AUDIT_DOMAIN_COUNT = 4


def _audit_domain(repeat: int, block: int, validator_id: int) -> str:
    """Return a deterministic audit-provenance class.

    The mapping is deliberately independent of audit success and compromise
    state.  SHA-256 avoids Python hash randomization and keeps the mapping
    reproducible across interpreters.
    """

    if repeat < 1 or block < 1 or validator_id < 0:
        raise ValueError("repeat/block must be positive and validator_id non-negative")
    digest = sha256(
        f"audit-domain|{repeat}|{block}|{validator_id}".encode("utf-8")
    ).digest()
    return f"audit-{int.from_bytes(digest[:4], 'big') % AUDIT_DOMAIN_COUNT}"


__all__ = ["AUDIT_DOMAIN_COUNT", "_audit_domain"]
