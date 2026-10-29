"""The two MLS read-escrow HTTP calls.

Kept out of :mod:`rine._mls.api` because that module belongs to the MLS
group-state owner; these two are the escrow read's own routes.

Both paths are f-strings with the variable spliced in, like the rest of
:mod:`rine._mls.api` does, so the client⇄server contract gate can extract them
and resolve them against the server's routes. The TypeScript twin is
``rine-core/src/mls-escrow-api.ts``.
"""

from __future__ import annotations

from typing import Any, TypedDict
from urllib.parse import quote

from rine._actor import AGENT_HEADER


class EscrowUploadBody(TypedDict):
    """The ``PUT /groups/{group_id}/mls/escrow/{epoch}`` body.

    Every field is a base64url string except ``key_gen``, which is the
    uploader's key generation at the moment it signed.
    """

    fp: str
    sealed: str
    key_gen: int
    sig: str


def upload_escrow(
    client: Any, agent_id: str, group_id: str, epoch: int, body: EscrowUploadBody
) -> None:
    """Store one sealed escrow for a group epoch.

    Every 2xx is success: 201 is the first upload of the slot and 200 is the
    server recognising a byte-identical retry, and both mean the escrow is
    stored, so the two statuses need no branch here.

    Args:
        client: Sync HTTP client.
        agent_id: The acting agent's UUID.
        group_id: The group the escrow belongs to.
        epoch: The epoch the escrow was drained from.
        body: The sealed bytes, fork fingerprint, key generation and signature.
    """
    client.put(
        f"/groups/{group_id}/mls/escrow/{epoch}",
        json_body=body,
        extra_headers={AGENT_HEADER: agent_id},
    )


def fetch_branch_escrow_key(client: Any, agent_id: str, branch: str) -> dict[str, Any]:
    """Fetch the acting agent's own branch escrow key.

    Args:
        client: Sync HTTP client.
        agent_id: The acting agent's UUID.
        branch: The branch name, percent-encoded into the path.

    Returns:
        The decoded ``/orgs/me/branches/{branch}/escrow-key`` response.
    """
    response: dict[str, Any] = client.get(
        f"/orgs/me/branches/{quote(branch, safe='')}/escrow-key",
        extra_headers={AGENT_HEADER: agent_id},
    )
    return response
