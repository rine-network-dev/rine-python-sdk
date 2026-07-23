"""The handshake endpoints — commits in, and the ACK/NACK that confirm them.

Split from :mod:`rine._mls.api` (which carries the founding and joining half)
purely so neither file outgrows what one screen holds. Same encoding rules:
every blob is standard base64, via :mod:`rine._mls.wire`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._mls.wire import mls_from_base64


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


def fetch_handshakes(
    client: Any, group_id: str, since_epoch: int, extra_headers: dict[str, str]
) -> list[MlsHandshake]:
    """Every commit posted to the group since the caller's current epoch.

    Args:
        client: Sync HTTP client.
        group_id: The rine group UUID.
        since_epoch: The caller's local epoch; the server returns what comes after.
        extra_headers: Acting-agent headers.

    Returns:
        The commits, oldest first — the order they must be applied in.
    """
    data = client.get(
        f"/groups/{group_id}/mls/handshakes",
        params={"since_epoch": since_epoch},
        extra_headers=extra_headers,
    )
    return [
        MlsHandshake(
            id=str(h["id"]),
            epoch=None if h.get("epoch") is None else int(h["epoch"]),
            blob=mls_from_base64(h["blob"]),
        )
        for h in data.get("handshakes", [])
    ]


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
