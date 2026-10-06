"""SEARPC-owned committee selector boundary.

The frozen consensus library retains its generic event_id API for historical
experiments. SEARPC participation control never exposes that argument: all height and purpose
variation is already committed inside the typed seed capability, while the
lower-level domain-separation label is a fixed internal constant.
"""
from __future__ import annotations

from typing import Iterable

from canonical_evidence import SelectionCapability
from durac import CertifiedSelection, ValidatorCandidate
from observable_fast_path import FastPathPlan, plan_fast_path
from typed_authority import AuthorityTarget, require_authority


_INTERNAL_SELECTION_DOMAIN = bytes.fromhex("72656361702d617574686f72697a65642d73656c656374696f6e2d7631").decode("ascii")


def plan_authorized_fast_path(
    candidates: Iterable[ValidatorCandidate],
    registered_candidates: Iterable[ValidatorCandidate],
    *,
    size: int,
    selection: CertifiedSelection | str,
    capability: SelectionCapability,
    leader_reputation_weighted: bool,
    backup_collector_enabled: bool = False,
) -> FastPathPlan:
    if not isinstance(capability, SelectionCapability):
        raise TypeError("a SelectionCapability is required")
    require_authority(
        capability.authority, AuthorityTarget.COMMITTEE_SEED
    )
    return plan_fast_path(
        candidates,
        registered_candidates,
        size=size,
        selection=selection,
        seed=capability.seed,
        event_id=_INTERNAL_SELECTION_DOMAIN,
        leader_reputation_weighted=leader_reputation_weighted,
        backup_collector_enabled=backup_collector_enabled,
    )
