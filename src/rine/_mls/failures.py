"""What a failure from the MLS core *means*, decided in one place.

Every failure the core raises is a typed class carrying a stable
``RINE_MLS_*`` code — a value to branch on, never a message to parse. The two
predicates here are the only places rine decides what a given failure means, so
no surface has to know the vocabulary itself. They are the Python side of
``rine-core``'s ``crypto/mls-errors.ts``; both stacks classify identically
because both classify off the same core.
"""

from __future__ import annotations

from rine._mls.binding import (
    MlsCoreError,
    MlsPanicError,
    MlsPoisonedError,
    MlsStoreError,
    SelfMessageNotCachedError,
)
from rine.errors import NoMlsGroupStateError

#: Failures of THIS process, never of the artifact it was handed. A commit is
#: not at fault because our own disk was unwritable.
_LOCAL_FAILURES = (MlsStoreError, MlsPanicError, MlsPoisonedError)


def is_unprocessable_commit(err: BaseException) -> bool:
    """True when a failure means "this commit cannot be applied".

    Only that earns a NACK. NACKing because our own store failed would roll back
    a commit every other member applied cleanly.
    """
    return isinstance(err, MlsCoreError) and not isinstance(err, _LOCAL_FAILURES)


def is_recoverable_mls_failure(err: BaseException) -> bool:
    """True when installing pending Welcomes and syncing commits might fix it.

    Two failures are deliberately NOT recoverable. A message this member sent
    whose plaintext has aged out of the self-read cache will never decrypt —
    forward secrecy consumed the sender's ratchet step and no peer can re-send
    it, so retrying is two pointless round trips before the same answer. And a
    local store failure is not something a sync can fix.
    """
    if isinstance(err, NoMlsGroupStateError):
        return True
    return is_unprocessable_commit(err) and not isinstance(err, SelfMessageNotCachedError)


__all__ = ["is_recoverable_mls_failure", "is_unprocessable_commit"]
