"""SPIFFE identity verification.

Proves control of a SPIFFE identity for an agent and elevates the org to trust
tier 2. Ports rine-core's ``verifyIdentitySpiffe`` (sync + async peers, matching
the dual-SDK convention). Three ordered steps:

1. ``POST /agents/{id}/verify-svid/challenge`` → a single-use ``audience``.
2. Obtain a JWT-SVID whose ``aud`` is that audience (caller-supplied ``svid``).
3. ``POST /agents/{id}/verify-svid`` with the SVID → typed result.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import TYPE_CHECKING

from rine.errors import RineError, SpiffeVerificationError
from rine.types import AgentRead, VerifyIdentityResult

if TYPE_CHECKING:
    from rine._http import AsyncHttpClient, SyncHttpClient

_SPIFFE_ENDPOINT_SOCKET_ENV = "SPIFFE_ENDPOINT_SOCKET"

_Log = Callable[[str], None]


def _has_spiffe_endpoint() -> bool:
    """True when a SPIFFE Workload API socket is advertised in the environment."""
    return bool(os.environ.get(_SPIFFE_ENDPOINT_SOCKET_ENV))


def _acquire_svid(svid: str | None, log: _Log | None) -> str:
    """Resolve the JWT-SVID to present, or fail fast before any request.

    Mirrors core's ``autoFetchSvid`` stub: a caller-supplied ``svid`` is the
    primary path. No first-party Workload-API client is bundled (the JWT-SVID
    fetch is gRPC-only, so a dependency-free auto-fetch is not possible), so when
    no ``svid`` is given this raises :class:`SpiffeVerificationError` — never a
    silent no-op. Called before the challenge is minted so an unobtainable SVID
    never burns a request against the server's verify rate limit.
    """
    if svid:
        return svid
    socket = os.environ.get(_SPIFFE_ENDPOINT_SOCKET_ENV)
    if socket:
        if log:
            log(
                f"SPIFFE Workload API detected at {socket}, but automatic JWT-SVID "
                f"fetch is not available in this build. Provide a JWT-SVID via svid=."
            )
        raise SpiffeVerificationError(
            "SPIFFE Workload API auto-fetch is unavailable; supply a JWT-SVID via svid=.",
            reason="autofetch-unavailable",
        )
    raise SpiffeVerificationError(
        "No JWT-SVID provided and no SPIFFE Workload API endpoint detected; supply one via svid=.",
        reason="no-svid",
    )


def verify_identity(
    client: SyncHttpClient,
    agent_id: str,
    *,
    svid: str | None = None,
    log: _Log | None = None,
) -> VerifyIdentityResult:
    """Prove control of a SPIFFE identity for ``agent_id`` (sync).

    Args:
        client: Authenticated HTTP client.
        agent_id: Agent UUID to verify.
        svid: A SPIFFE JWT-SVID (compact JWS) minted for the challenge audience.
        log: Optional sink for human-readable diagnostics.

    Returns:
        VerifyIdentityResult with the recorded spiffe_id and elevated trust tier.

    Raises:
        SpiffeVerificationError: If no SVID can be obtained.
        RineApiError: On challenge/verify HTTP failures (404/409/422/429/...).
    """
    resolved = _acquire_svid(svid, log)
    client.post(f"/agents/{agent_id}/verify-svid/challenge")
    data = client.post(f"/agents/{agent_id}/verify-svid", json_body={"svid": resolved})
    return VerifyIdentityResult.model_validate(data)


async def async_verify_identity(
    client: AsyncHttpClient,
    agent_id: str,
    *,
    svid: str | None = None,
    log: _Log | None = None,
) -> VerifyIdentityResult:
    """Prove control of a SPIFFE identity for ``agent_id`` (async variant)."""
    resolved = _acquire_svid(svid, log)
    await client.post(f"/agents/{agent_id}/verify-svid/challenge")
    data = await client.post(f"/agents/{agent_id}/verify-svid", json_body={"svid": resolved})
    return VerifyIdentityResult.model_validate(data)


def apply_identity_verification(
    client: SyncHttpClient,
    agent: AgentRead,
    *,
    verify: bool,
    svid: str | None,
    log: _Log | None,
) -> None:
    """Run the ``create_agent`` auto-verify hook, mutating ``agent`` in place.

    Verification runs when explicitly requested, when a SPIFFE Workload API
    endpoint is present, or when the caller supplied an ``svid`` (an SVID passed
    without ``verify_identity`` must not be silently discarded). The agent
    already exists, so a FAILURE is captured in ``agent.identity_error`` and
    never re-raised — it must never undo creation.
    """
    if not (verify or svid or _has_spiffe_endpoint()):
        return
    try:
        agent.identity = verify_identity(client, str(agent.id), svid=svid, log=log)
    except RineError as err:
        agent.identity_error = str(err)
