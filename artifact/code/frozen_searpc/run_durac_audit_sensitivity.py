#!/usr/bin/env python3
"""Shared audit-cost constants for legacy stress experiments.

These constants affect only the optional audit-cost accounting runner; they are
not used by the paper's RQ4 canonical results.
"""

AUDIT_BYTES = 512
AUDIT_CPU_MS = 0.05

__all__ = ["AUDIT_BYTES", "AUDIT_CPU_MS"]
