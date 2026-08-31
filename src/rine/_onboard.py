"""Registration + agent creation flow.

PoW-protected org registration and agent creation with key generation.
Ports rine-core's ``onboard.ts``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    # Imported for annotations only — the runtime import stays inside the functions
    # that actually open a client, which is where it has always been. CredentialEntry
    # is annotation-only too: the one `cast` naming it passes a string.
    import httpx

    from rine._types import CredentialEntry

from rine._config import cache_token, load_credentials, save_credentials
from rine._crypto.keys import generate_agent_keys, public_keys_body, save_agent_keys
from rine._http import _USER_AGENT, SyncHttpClient, _parse_error_detail, _parse_retry_after
from rine._logging import logger
from rine._timelock import solve_timelock
from rine._verify import apply_identity_verification
from rine.errors import RateLimitError, RineError, raise_for_status
from rine.types import AgentRead, RegistrationResult

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$")


def validate_slug(slug: str) -> bool:
    """Validate an org slug.

    Args:
        slug: Slug string (2-32 chars, lowercase alphanumeric + interior hyphens).

    Returns:
        True if valid.
    """
    return bool(_SLUG_RE.match(slug))


def _raise_registration_error(resp: httpx.Response) -> None:
    """Raise the appropriate SDK error from a failed registration response.

    Uses the same error parsing as the main HTTP layer so that server-provided
    detail messages (e.g. "Email already in use") are surfaced accurately.
    """
    detail = _parse_error_detail(resp)
    if resp.status_code == 429:
        retry_val = _parse_retry_after(resp)
        raise RateLimitError(detail=detail, retry_after=retry_val, raw=resp.text)
    raise_for_status(resp.status_code, detail, raw=resp.text)


def register(
    api_url: str,
    config_dir: str,
    email: str,
    org_slug: str,
    org_name: str,
    on_progress: Callable[[int], None] | None = None,
    profile: str = "default",
) -> RegistrationResult:
    """Register a new org via PoW challenge.

    Exported from the package root under two names: ``rine.register``, which is
    what the TypeScript SDK and the CLI call it, and ``rine.onboard``, which is
    what this SDK has always called it. They are the same object.

    Args:
        api_url: API base URL.
        config_dir: Config directory for saving credentials.
        email: Contact email.
        org_slug: URL-safe org identifier.
        org_name: Human-readable org name.
        on_progress: Optional callback for PoW progress (0-100).
        profile: Credential profile name.

    Returns:
        RegistrationResult with org_id and client_id.

    Raises:
        RineError: If slug is invalid.
        ConflictError: If slug or email already in use.
        RateLimitError: If rate limited.
        RineApiError: If registration fails.
    """
    import httpx

    if not validate_slug(org_slug):
        raise RineError(
            f"Invalid slug '{org_slug}'. Must match: [a-z0-9][a-z0-9-]{{0,30}}[a-z0-9]"
        )

    with httpx.Client(timeout=60) as http:
        # Step 1: Request challenge
        resp = http.post(
            f"{api_url}/auth/register",
            json={"email": email, "org_slug": org_slug},
            headers={"User-Agent": _USER_AGENT},
        )
        if not resp.is_success:
            _raise_registration_error(resp)

        challenge = resp.json()
        algorithm = challenge.get("algorithm")
        if algorithm != "rsa-timelock-v1":
            raise RineError(f"Unsupported PoW algorithm: {algorithm}")

        # Step 2: Solve PoW
        solution = solve_timelock(
            challenge["prefix"], challenge["modulus"], challenge["difficulty"]
        )
        if on_progress:
            on_progress(100)

        # Step 3: Submit solution
        resp = http.post(
            f"{api_url}/auth/register/solve",
            json={
                "challenge_id": challenge["challenge_id"],
                "nonce": solution,
                "org_name": org_name,
                "org_slug": org_slug,
                "consent": True,
            },
            headers={"User-Agent": _USER_AGENT},
        )
        if not resp.is_success:
            _raise_registration_error(resp)

        result = resp.json()

    # Save credentials
    creds = load_credentials(config_dir)
    creds[profile] = {
        "client_id": result["client_id"],
        "client_secret": result["client_secret"],
    }
    save_credentials(config_dir, creds)

    # Cache token (non-fatal)
    try:
        if "access_token" in result:
            cache_token(config_dir, profile, result["access_token"], result.get("expires_in", 900))
    except Exception:
        logger.warning("Failed to cache token after registration", exc_info=True)

    return RegistrationResult(org_id=result["org_id"], client_id=result["client_id"])


async def async_register(
    api_url: str,
    config_dir: str,
    email: str,
    org_slug: str,
    org_name: str,
    on_progress: Callable[[int], None] | None = None,
    profile: str = "default",
) -> RegistrationResult:
    """Register a new org via PoW challenge (async variant).

    Exported from the package root as both ``rine.async_register`` and
    ``rine.async_onboard`` — the same object under the two spellings the product
    uses, exactly as its sync twin is.

    Args:
        api_url: API base URL.
        config_dir: Config directory for saving credentials.
        email: Contact email.
        org_slug: URL-safe org identifier.
        org_name: Human-readable org name.
        on_progress: Optional callback for PoW progress (0-100).
        profile: Credential profile name.

    Returns:
        RegistrationResult with org_id and client_id.

    Raises:
        RineError: If slug is invalid.
        ConflictError: If slug or email already in use.
        RateLimitError: If rate limited.
        RineApiError: If registration fails.
    """
    import asyncio

    import httpx

    if not validate_slug(org_slug):
        raise RineError(
            f"Invalid slug '{org_slug}'. Must match: [a-z0-9][a-z0-9-]{{0,30}}[a-z0-9]"
        )

    async with httpx.AsyncClient(timeout=60) as http:
        # Step 1: Request challenge
        resp = await http.post(
            f"{api_url}/auth/register",
            json={"email": email, "org_slug": org_slug},
            headers={"User-Agent": _USER_AGENT},
        )
        if not resp.is_success:
            _raise_registration_error(resp)

        challenge = resp.json()
        algorithm = challenge.get("algorithm")
        if algorithm != "rsa-timelock-v1":
            raise RineError(f"Unsupported PoW algorithm: {algorithm}")

        # Step 2: Solve PoW in thread (CPU-bound)
        solution = await asyncio.to_thread(
            solve_timelock,
            challenge["prefix"],
            challenge["modulus"],
            challenge["difficulty"],
        )
        if on_progress:
            on_progress(100)

        # Step 3: Submit solution
        resp = await http.post(
            f"{api_url}/auth/register/solve",
            json={
                "challenge_id": challenge["challenge_id"],
                "nonce": solution,
                "org_name": org_name,
                "org_slug": org_slug,
                "consent": True,
            },
            headers={"User-Agent": _USER_AGENT},
        )
        if not resp.is_success:
            _raise_registration_error(resp)

        result = resp.json()

    # Save credentials
    creds = load_credentials(config_dir)
    creds[profile] = {
        "client_id": result["client_id"],
        "client_secret": result["client_secret"],
    }
    save_credentials(config_dir, creds)

    # Cache token (non-fatal)
    try:
        if "access_token" in result:
            cache_token(config_dir, profile, result["access_token"], result.get("expires_in", 900))
    except Exception:
        logger.warning("Failed to cache token after registration", exc_info=True)

    return RegistrationResult(org_id=result["org_id"], client_id=result["client_id"])


def create_agent(
    client: SyncHttpClient,
    config_dir: str,
    name: str,
    human_oversight: bool = True,
    unlisted: bool = False,
    *,
    verify_identity: bool = False,
    svid: str | None = None,
    log: Callable[[str], None] | None = None,
) -> AgentRead:
    """Create an agent with generated keypairs.

    Args:
        client: Authenticated HTTP client.
        config_dir: Config directory for saving keys.
        name: Agent name.
        human_oversight: Whether agent requires human oversight.
        unlisted: Whether agent is unlisted.
        verify_identity: Run SPIFFE identity verification after creation.
        svid: Caller-supplied JWT-SVID for the verification step. Supplying it
            implies verification even when ``verify_identity`` is False.
        log: Optional sink for verification diagnostics.

    Returns:
        Created AgentRead. When verification runs, ``identity`` (success) or
        ``identity_error`` (failure) is populated — a verify failure never undoes
        creation.
    """
    keys = generate_agent_keys()

    body: dict[str, Any] = {
        "name": name,
        "human_oversight": human_oversight,
        "unlisted": unlisted,
        **public_keys_body(keys),
    }
    data = client.post("/agents", json_body=body)
    agent = AgentRead.model_validate(data)

    # Save private keys
    save_agent_keys(config_dir, str(agent.id), keys)

    # Publish an initial batch of MLS KeyPackages so the agent can be added to
    # groups from birth — without them, the first invite fails with "No key
    # packages available". Best-effort: a failure here must never undo agent
    # creation, and the next MLS operation replenishes.
    from rine._mls import replenish_mls_key_packages

    replenish_mls_key_packages(client, config_dir, str(agent.id))

    # Save poll_url to credentials if present
    if agent.poll_url:
        creds = load_credentials(config_dir)
        # A profile with no entry yet starts as an empty mapping that this block fills
        # in. The cast names that one unsound step explicitly, which is what the pair of
        # blanket ignores here used to hide; `poll_url` itself is a declared NotRequired
        # key of CredentialEntry, so the write below needs no exemption at all.
        entry: CredentialEntry = creds.get(client._profile) or cast("CredentialEntry", {})
        entry["poll_url"] = agent.poll_url
        creds[client._profile] = entry
        save_credentials(config_dir, creds)

    apply_identity_verification(client, agent, verify=verify_identity, svid=svid, log=log)

    return agent
