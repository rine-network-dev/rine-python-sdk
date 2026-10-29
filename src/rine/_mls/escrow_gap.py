"""The record of an installed epoch that has no escrow.

The native group reports an epoch it cannot escrow once, and the drain's
``group.save()`` makes that report durable, so the drain files a marker here
before saving: nothing else remembers the epoch afterwards. A marker is a file
beside the group's pending escrows, holding the reason::

    escrow-pending/<group_id>/<epoch>.gap                an epoch with no known fork
    escrow-pending/<group_id>/<epoch>-<fp hex>.gap       one fork of an epoch

The first is what the native core reports and what an unreadable parked state leaves: neither
names a fork. The second is a pending escrow given up on, or a parked export lost with its
state: the fork is known, so the marker is its own and never speaks for another fork of the
same epoch. A marker is only ever written once: a later loss of the same fork does not replace
the first reason. It is removed when the fork's escrow is stored.

:func:`rine._mls.escrow_store.list_pending` reads only ``<epoch>-<fp hex>.bin``,
so a marker never reaches an upload.

A marker also records an epoch whose escrow was given up on for good (an
:class:`EscrowLoss`): the server refused it for good, the parked state holding it
could not be read, or its branch was revoked. The marker is filed first and the file
that held the escrow is deleted after, so a crash between the two leaves both and the
next pass finishes the job. No marker holds secret material.

The TypeScript twin is ``rine-core/src/mls-escrow-gap.ts`` — same names, same keys.
"""

from __future__ import annotations

import contextlib
import os
import re
import stat
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, NamedTuple

from pydantic import InstanceOf, PlainSerializer

from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_atomic import create_exclusive
from rine._mls.escrow_head import EscrowHead, clear_head
from rine._mls.escrow_store import EPOCH_NAME_PATTERN, FP_HEX_LENGTH, delete_pending, pending_dir

if TYPE_CHECKING:
    from collections.abc import Iterable

    from rine._mls.escrow_store import PendingEscrow

GAP_SUFFIX = ".gap"

#: ``<epoch>.gap`` or ``<epoch>-<32 hex>.gap`` — the only names :func:`read_gap` will read.
GAP_NAME_RE = re.compile(
    rf"^{EPOCH_NAME_PATTERN}(?:-([0-9a-f]{{{FP_HEX_LENGTH}}}))?{re.escape(GAP_SUFFIX)}$"
)

#: A marker holds one reason, shorter than this, so a longer file names none and is never
#: read past it.
MAX_MARKER_BYTES = 32


class EscrowLoss(StrEnum):
    """Why an epoch's escrow was given up on for good."""

    REFUSED = "refused"
    """The server refused it for good, or kept refusing it until the attempts ran out."""

    UNREADABLE = "unreadable"
    """The parked state that held it could not be read."""

    BRANCH_REVOKED = "branch_revoked"
    """The branch it would be sealed to is revoked, so nobody could ever read it."""

    AGENT_REVOKED = "agent_revoked"
    """The agent that would upload it is revoked, so the server takes nothing from it."""


#: ``reason.value`` -> member, for the native reasons and the losses. The native enum is
#: not iterable, but its members are class attributes, so a new variant is picked up
#: without a list here.
_REASONS: dict[str, EscrowGapReason | EscrowLoss] = {
    **{
        member.value: member
        for member in vars(EscrowGapReason).values()
        if isinstance(member, EscrowGapReason)
    },
    **{loss.value: loss for loss in EscrowLoss},
}


#: A gap reason as a pydantic field: the native enum has no schema of its own, and a
#: result model holding a :class:`DrainGap` must still validate and dump to JSON.
GapReason = Annotated[
    InstanceOf[EscrowGapReason] | EscrowLoss,
    PlainSerializer(lambda reason: reason.value, return_type=str),
]


#: A fork fingerprint as a result field: raw bytes do not dump to JSON, and a hash is public.
Fork = Annotated[
    bytes | None,
    PlainSerializer(lambda fp: None if fp is None else fp.hex(), return_type=str | None),
]


@dataclass(frozen=True, slots=True)
class DrainGap:
    """An installed epoch with no escrow, and why."""

    epoch: int
    reason: GapReason
    fp: Fork = None
    """The fork the epoch is lost for, when the core could name it."""


class LocatedGap(NamedTuple):
    """A gap and the group it belongs to, for a loss no group's result has told anyone yet."""

    group_id: str
    gap: DrainGap


def _gap_path(config_dir: str, agent_id: str, group_id: str, epoch: int, fp: bytes | None) -> str:
    fork = "" if fp is None else f"-{fp.hex()}"
    return os.path.join(pending_dir(config_dir, agent_id, group_id), f"{epoch}{fork}{GAP_SUFFIX}")


def parse_gap_name(name: str) -> tuple[int, str | None] | None:
    """The epoch and fork (32 hex, when the name has one) a marker's file name stands for."""
    match = GAP_NAME_RE.fullmatch(name)
    return None if match is None else (int(match.group(1)), match.group(2))


def marker_reason(path: str) -> EscrowGapReason | EscrowLoss | None:
    """The reason a marker file holds; ``None`` when it is unreadable or names no known one.

    Only a regular file is read, and at most :data:`MAX_MARKER_BYTES` of it: a link, a pipe or
    a huge file planted under a marker's name is skipped, never followed, waited on or loaded.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return _REASONS.get(os.read(fd, MAX_MARKER_BYTES).decode("ascii"))
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def write_gap(
    config_dir: str, agent_id: str, group_id: str, gap: DrainGap, fp: bytes | None = None
) -> GapReason:
    """Record that ``gap.epoch`` has no escrow, for the fork ``fp`` or for no known fork.

    The first reason recorded for a marker is kept: a later loss of the same fork
    leaves it as it is.

    Returns:
        The reason the marker holds on disk, which is the first one recorded, so a
        caller reports the loss the disk will keep naming.

    Raises:
        CryptoError: ``group_id`` is not a canonical UUID.
    """
    path = _gap_path(config_dir, agent_id, group_id, gap.epoch, fp)
    create_exclusive(path, gap.reason.value.encode("ascii"))
    return marker_reason(path) or gap.reason


def clear_gap(config_dir: str, agent_id: str, group_id: str, epoch: int, fp: bytes) -> None:
    """Remove the marker of a fork whose escrow the server now holds; missing is success."""
    with contextlib.suppress(FileNotFoundError):
        os.unlink(_gap_path(config_dir, agent_id, group_id, epoch, fp))


def file_gaps(config_dir: str, agent_id: str, group_id: str, gaps: Iterable[DrainGap]) -> None:
    """Record every gap under its own fork before the drain saves the group.

    Nothing else remembers them.
    """
    for gap in gaps:
        write_gap(config_dir, agent_id, group_id, gap, gap.fp)


def lost_gaps(epochs: Iterable[int], loss: EscrowLoss) -> tuple[DrainGap, ...]:
    """One gap per epoch, all for the same loss."""
    return tuple(DrainGap(epoch, loss) for epoch in epochs)


def give_up_pending(
    config_dir: str, agent_id: str, pending: PendingEscrow, loss: EscrowLoss
) -> DrainGap:
    """Record that a pending escrow will never be uploaded, then delete it.

    The marker is durable before the file goes, so the epoch is never forgotten. When the
    file is the one the group's head points at, the head is forgotten too, so the send gate
    reads the marker and names the loss instead of sending to an escrow that is not there.

    Raises:
        OSError: The marker could not be written. The file is kept for the next pass.
    """
    reason = write_gap(
        config_dir, agent_id, pending.group_id, DrainGap(pending.epoch, loss), pending.fp
    )
    gap = DrainGap(pending.epoch, reason)
    clear_head(config_dir, agent_id, pending.group_id, EscrowHead(pending.epoch, pending.fp))
    delete_pending(config_dir, agent_id, pending)
    return gap
