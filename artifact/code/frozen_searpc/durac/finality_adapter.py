"""Non-interference boundary between SEARPC and a base BFT finalizer.

SEARPC may rank candidates and attach a fast-path certificate as an advisory
proposal hint.  It does not implement cross-view locking.  A production
integration delegates validation, safe lock transfer, view change, and final
certificate construction to a base BFT finalizer whose quorum is fixed by the
registered validator set.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import FrozenSet, Iterable


@dataclass(frozen=True)
class FastProposalHint:
    """Advisory fast-path evidence with no finality or lock semantics."""

    height: int
    view: int
    digest: str
    signer_ids: FrozenSet[int]

    @classmethod
    def build(
        cls,
        *,
        height: int,
        view: int,
        block: bytes,
        signer_ids: Iterable[int],
    ) -> "FastProposalHint":
        if height < 0 or view < 0:
            raise ValueError("height and view must be non-negative")
        signers = frozenset(int(item) for item in signer_ids)
        if not signers:
            raise ValueError("a fast proposal hint needs at least one signer")
        return cls(
            height=height,
            view=view,
            digest=sha256(block).hexdigest(),
            signer_ids=signers,
        )


@dataclass(frozen=True)
class FinalizerInvocation:
    """Inputs that SEARPC is allowed to pass to the base finalizer."""

    height: int
    mode: str
    registered_ids: FrozenSet[int]
    final_quorum: int
    block_digest: str | None
    fast_hint: FastProposalHint | None
    reason: str


class FinalizerBoundary:
    """Stateless adapter that enforces SEARPC/finalizer separation.

    The adapter deliberately stores no lock, highest certificate, or view-change
    state.  Those variables belong to the base finalizer.  Consequently, two
    conflicting fast hints cannot create a split lock inside SEARPC.
    """

    def __init__(self, registered_ids: Iterable[int], final_quorum: int) -> None:
        ids = frozenset(int(item) for item in registered_ids)
        if not ids:
            raise ValueError("registered validator set cannot be empty")
        if not 1 <= final_quorum <= len(ids):
            raise ValueError("final quorum must be within the registered set")
        self._registered_ids = ids
        self._final_quorum = int(final_quorum)

    @property
    def registered_ids(self) -> FrozenSet[int]:
        return self._registered_ids

    @property
    def final_quorum(self) -> int:
        return self._final_quorum

    @property
    def searpc_lock_state(self) -> None:
        """SEARPC owns no finalizer lock state by construction."""

        return None

    def propose(
        self,
        *,
        height: int,
        block: bytes,
        fast_hint: FastProposalHint | None,
    ) -> FinalizerInvocation:
        digest = sha256(block).hexdigest()
        if fast_hint is not None:
            if fast_hint.height != height:
                raise ValueError("fast hint height does not match proposal height")
            if fast_hint.digest != digest:
                raise ValueError("fast hint digest does not match complete block")
            if not fast_hint.signer_ids <= self._registered_ids:
                raise ValueError("fast hint contains an unregistered signer")
        return FinalizerInvocation(
            height=height,
            mode="base_finalize",
            registered_ids=self._registered_ids,
            final_quorum=self._final_quorum,
            block_digest=digest,
            fast_hint=fast_hint,
            reason="validated complete block submitted to base finalizer",
        )

    def fail_open_propose(
        self,
        *,
        height: int,
        block: bytes,
        fast_hint: FastProposalHint | None,
        hint_status: str = "delivered",
    ) -> FinalizerInvocation:
        """Submit the complete block even when the advisory hint is unusable.

        ``missing``, ``timeout``, and any structurally invalid delivered hint are
        mapped to the bottom value (no hint).  The base finalizer therefore sees
        its normal proposal input at the same fixed quorum.  This adapter has no
        proposer timer, lock, or view-change state that a hint can block.

        ``propose`` remains the strict validation primitive so callers can audit
        malformed hints explicitly; production composition should call this
        fail-open wrapper at the SEARPC/base-finalizer boundary.
        """

        if hint_status not in {"delivered", "missing", "timeout"}:
            raise ValueError("unknown hint status")
        if hint_status in {"missing", "timeout"}:
            invocation = self.propose(height=height, block=block, fast_hint=None)
            return FinalizerInvocation(
                **{
                    **invocation.__dict__,
                    "reason": f"{hint_status} hint treated as bottom; base proposer path",
                }
            )
        try:
            return self.propose(height=height, block=block, fast_hint=fast_hint)
        except ValueError:
            invocation = self.propose(height=height, block=block, fast_hint=None)
            return FinalizerInvocation(
                **{
                    **invocation.__dict__,
                    "reason": "invalid hint treated as bottom; base proposer path",
                }
            )

    def fallback(self, *, height: int, reason: str) -> FinalizerInvocation:
        """Invoke the base finalizer's normal path/view change at fixed Q."""

        if height < 0:
            raise ValueError("height must be non-negative")
        if not reason:
            raise ValueError("fallback reason cannot be empty")
        return FinalizerInvocation(
            height=height,
            mode="base_fallback",
            registered_ids=self._registered_ids,
            final_quorum=self._final_quorum,
            block_digest=None,
            fast_hint=None,
            reason=reason,
        )


__all__ = ["FastProposalHint", "FinalizerInvocation", "FinalizerBoundary"]
