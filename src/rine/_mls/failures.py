"""What a failure from the MLS core *means*, decided in one place.

Every failure the core raises is a typed class carrying a stable
``RINE_MLS_*`` code — a value to branch on, never a message to parse. The two
predicates here are the only places rine decides what a given failure means, so
no surface has to know the vocabulary itself. They are the Python side of
``rine-core``'s ``crypto/mls-errors.ts``; both stacks classify identically
because both classify off the same core.

:func:`mls_boundary` is where that vocabulary stops. Inside this package a
failure keeps its core class, because the predicates below branch on it; on the
way out it becomes an :class:`~rine.errors.MlsError`, so no caller ever holds a
type from the compiled wheel this package exists to be the only importer of.
"""

from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
from typing import TYPE_CHECKING, ParamSpec, TypeVar

from rine._mls.binding import (
    EpochConflictError,
    GroupInactiveError,
    MlsCoreError,
    MlsPanicError,
    MlsPoisonedError,
    MlsStoreError,
    SelfMessageNotCachedError,
)
from rine._mls.wire import api_error_code
from rine.errors import GroupEvictedError, MlsError, NoMlsGroupStateError

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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


#: The server's ``error`` key when its epoch compare-and-set refused a commit.
EPOCH_CONFLICT = "epoch_conflict"


def is_epoch_conflict(err: BaseException) -> bool:
    """True when the group moved on before this commit landed, from either side.

    The core raises it when a local commit is built against a superseded epoch;
    the server answers ``409 epoch_conflict`` when a peer's commit won the CAS
    first. Both mean the same thing to a caller — catch up and rebuild once —
    so both are one predicate rather than two half-checks per call site.
    """
    return isinstance(err, EpochConflictError) or api_error_code(err) == EPOCH_CONFLICT


@contextmanager
def group_failures(group_id: str) -> Iterator[None]:
    """Re-word the one core failure that is really a membership fact.

    ``RINE_MLS_GROUP_INACTIVE`` is raised for exactly one reason — a Remove
    commit evicted this member's leaf — and the core's own message names no
    group and no remedy. Wrapping the operations an evicted agent can still
    reach (reading, sending, admitting, removing) turns it into
    :class:`~rine.errors.GroupEvictedError`, which says what happened and how to
    come back.

    Only that one failure is translated. A store failure and an epoch conflict
    are this process's problems and must never be reported to an agent as an
    eviction it can do nothing about. The TypeScript twin is ``asGroupFailure``
    (``rine-ts-sdk/src/resources/groups-mls-context.ts``).

    It is a context manager rather than a decorator because the group id is a
    *value* every one of these functions already holds, and a decorator would
    have to go looking for it in the call's arguments.

    Args:
        group_id: The rine group the wrapped operation is about.

    Yields:
        Nothing; the block runs unchanged unless the core reports an eviction.
    """
    try:
        yield
    except GroupInactiveError as err:
        raise GroupEvictedError(group_id) from err


_P = ParamSpec("_P")
_T = TypeVar("_T")


def mls_boundary(fn: Callable[_P, _T]) -> Callable[_P, _T]:
    """Normalize every core failure escaping ``fn`` into an SDK error.

    Applied to the functions this package is entered through, and to no others:
    a wrapped failure would defeat the predicates above, which are what decide
    whether a commit earns a NACK and whether a read is worth recovering.
    """

    @wraps(fn)
    def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _T:
        try:
            return fn(*args, **kwargs)
        except MlsCoreError as err:
            raise MlsError(getattr(err, "code", None), str(err)) from err

    return wrapper


__all__ = [
    "EPOCH_CONFLICT",
    "group_failures",
    "is_epoch_conflict",
    "is_recoverable_mls_failure",
    "is_unprocessable_commit",
    "mls_boundary",
]
