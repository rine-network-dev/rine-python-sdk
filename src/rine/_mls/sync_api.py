"""The handshake endpoints — commits in, and the ACK/NACK that confirm them.

Split from :mod:`rine._mls.api` (which carries the founding and joining half)
purely so neither file outgrows what one screen holds. Same encoding rules:
every blob is standard base64, via :mod:`rine._mls.wire`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from rine._mls.api import fetch_group_info
from rine._mls.wire import PENDING_CONFIRMATION, api_error_code, mls_from_base64
from rine.errors import ConflictError


@dataclass(frozen=True)
class MlsHandshake:
    """One commit the server is holding for a group, and its delivery id.

    ``epoch`` is the epoch the commit advances the group *to*. It is nullable on
    the wire — an open-enrollment commit is recorded before the server knows the
    epoch it will confirm at — and a NACK carries ``0`` in that case.
    """

    id: str
    epoch: int | None
    blob: bytes


class OwnCommitStanding(StrEnum):
    """Where the server holds the caller's own pending commit, as the handshakes read says."""

    TENTATIVE = "tentative"
    """Accepted, and no member has acknowledged it yet."""

    CONFIRMED = "confirmed"
    """A member acknowledged it: it is the group's commit at its epoch."""

    ROLLED_BACK = "rolled_back"
    """The server quarantined it, or the latch fell back below its epoch."""

    SUPERSEDED = "superseded"
    """Another agent's commit holds its epoch."""

    ABSENT = "absent"
    """The server holds no commit of the caller's at that epoch."""


@dataclass(frozen=True)
class MlsHandshakeFeed:
    """The commits served since an epoch, and where the caller's own commit stands."""

    handshakes: list[MlsHandshake] = field(default_factory=list)
    pending_commit: OwnCommitStanding | None = None
    """Present only when the request named a ``pending_epoch``."""


def fetch_handshake_feed(
    client: Any,
    group_id: str,
    since_epoch: int,
    extra_headers: dict[str, str],
    pending_epoch: int | None = None,
) -> MlsHandshakeFeed:
    """Every commit posted to the group since the caller's current epoch.

    With ``pending_epoch`` (which must be ``since_epoch + 1``) the server also says
    where the caller's own commit at that epoch stands, and measures replay
    reachability from it only when it is confirmed, so a holder of a confirmed
    commit is not sent to a resync.

    Args:
        client: Sync HTTP client.
        group_id: The rine group UUID.
        since_epoch: The caller's local epoch; the server returns what comes after.
        extra_headers: Acting-agent headers.
        pending_epoch: The epoch of the commit the caller holds pending, if any.

    Returns:
        The commits, oldest first — the order they must be applied in — and the
        standing when ``pending_epoch`` was named and the server answered it.
    """
    params: dict[str, int] = {"since_epoch": since_epoch}
    if pending_epoch is not None:
        params["pending_epoch"] = pending_epoch
    data = client.get(
        f"/groups/{group_id}/mls/handshakes", params=params, extra_headers=extra_headers
    )
    standing = data.get("pending_commit")
    return MlsHandshakeFeed(
        handshakes=[
            MlsHandshake(
                id=str(h["id"]),
                epoch=None if h.get("epoch") is None else int(h["epoch"]),
                blob=mls_from_base64(h["blob"]),
            )
            for h in data.get("handshakes", [])
        ],
        pending_commit=None if standing is None else OwnCommitStanding(standing),
    )


def fetch_handshakes(
    client: Any, group_id: str, since_epoch: int, extra_headers: dict[str, str]
) -> list[MlsHandshake]:
    """Every commit posted to the group since ``since_epoch``, oldest first."""
    return fetch_handshake_feed(client, group_id, since_epoch, extra_headers).handshakes


def mls_ack(client: Any, group_id: str, object_id: str, extra_headers: dict[str, str]) -> bool:
    """Confirm a commit this member applied cleanly.

    Returns:
        Whether the commit is now confirmed for the group.
    """
    data = client.post(
        f"/groups/{group_id}/mls/ack",
        json_body={"object_id": object_id},
        extra_headers=extra_headers,
    )
    return bool(data.get("confirmed", False))


def mls_nack(
    client: Any,
    group_id: str,
    handshake: MlsHandshake,
    reason: str,
    extra_headers: dict[str, str],
) -> bool:
    """Report a commit this member could not process.

    The server quarantines the delivery and lazily rolls the tentative commit
    back. It is non-destructive: only unconfirmed, never-served state is ever
    un-advanced.

    Returns:
        Whether the server quarantined the commit.
    """
    data = client.post(
        f"/groups/{group_id}/mls/nack",
        json_body={
            "object_id": handshake.id,
            "epoch": handshake.epoch or 0,
            "reason": reason[:256],
        },
        extra_headers=extra_headers,
    )
    return bool(data.get("quarantined", False))


@dataclass(frozen=True)
class GroupEpochs:
    """The group row's confirmed epoch, as the server reports it.

    ``confirmed`` is the newest epoch a member ACK (or a closed-regime commit)
    confirmed. ``None`` when the group has no confirmed GroupInfo to read, or the
    server predates the field.
    """

    confirmed: int | None


def fetch_group_epochs(client: Any, group_id: str, extra_headers: dict[str, str]) -> GroupEpochs:
    """Read the group's confirmed epoch.

    The same route as :func:`rine._mls.api.fetch_group_info`, projected to the
    confirmed epoch. Running it also settles a tentative commit that is past its ACK
    deadline, so the answer is current.

    A group whose newest GroupInfo is still awaiting an ACK serves no confirmed
    one (409 ``pending_confirmation``); that reads as unknown rather than as a
    failure, because a held commit must keep holding.

    Raises:
        RineApiError: Any other refusal, or a transport failure.
    """
    try:
        info = fetch_group_info(client, group_id, extra_headers)
    except ConflictError as err:
        if api_error_code(err) == PENDING_CONFIRMATION:
            return GroupEpochs(confirmed=None)
        raise
    return GroupEpochs(confirmed=info.confirmed_epoch)
