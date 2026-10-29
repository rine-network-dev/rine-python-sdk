"""Org registration: the client mints the root, the server sees public keys.

``register`` mints the 32-byte org root, derives every key from it, solves the
PoW, writes ``root.key`` and the recovery phrase to the owner dir, and sends the
org and ``main`` branch public keys with a proof of possession. Ports rine-core's
``onboard.ts``; agents are created afterwards by :mod:`rine._agent_provision`.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import httpx

from rine._config import _ensure_dir, cache_token
from rine._constants import MAIN_BRANCH
from rine._crypto.derive_nodes import BranchNode, OrgNode, derive_branch, derive_org
from rine._crypto.org_words import org_words
from rine._custody import Signer
from rine._http import (
    _USER_AGENT,
    _fetch_oauth_token,
    _fetch_oauth_token_async,
    _parse_error_detail,
    _parse_retry_after,
)
from rine._logging import logger
from rine._org_certs import branch_key_body, issue_branch_cert, register_proof
from rine._owner import (
    PHRASE_FILE,
    ROOT_SIZE,
    assert_fresh_owner_dir,
    remove_root,
    resolve_owner_dir,
    save_root,
)
from rine._principal import org_principal
from rine._profiles import DEFAULT_PROFILE, add_profile_if_absent
from rine._timelock import solve_timelock
from rine._types import Profile
from rine._utils import to_base64url
from rine.errors import RateLimitError, RineError, raise_for_status
from rine.types import RegistrationResult

if TYPE_CHECKING:
    from collections.abc import Callable

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$")
_HEADERS = {"User-Agent": _USER_AGENT}


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


@dataclass(frozen=True, slots=True)
class _Mint:
    """A freshly minted org root, with the nodes registration needs."""

    root: bytes
    org: OrgNode
    main: BranchNode

    @classmethod
    def new(cls) -> _Mint:
        """Mint a fresh root and derive the nodes from it."""
        return cls.from_root(os.urandom(ROOT_SIZE))

    @classmethod
    def from_root(cls, root: bytes) -> _Mint:
        """Derive the nodes from a root the caller already holds.

        The fleet enrols from a root it holds rather than minting one, and it
        must derive the org and the main branch exactly as :meth:`new` does.

        Raises:
            CryptoError: If the root is not ``ROOT_SIZE`` bytes.
        """
        org = derive_org(root)
        return cls(root, org, derive_branch(org.r_read, org.r_sign, MAIN_BRANCH))

    def begin_body(self, email: str, org_slug: str) -> dict[str, str]:
        """``POST /auth/register``: the org id and public keys, before any PoW."""
        return {
            "email": email,
            "org_slug": org_slug,
            "org_id": self.org.org_id,
            "org_signing_public_key": to_base64url(self.org.ed_pk),
            "org_pq_signing_public_key": to_base64url(self.org.dsa_pk),
        }

    def solve_body(
        self, api_url: str, challenge: dict[str, Any], nonce: str, org_slug: str, org_name: str
    ) -> dict[str, Any]:
        """``POST /auth/register/solve``: the PoW answer, the main branch and the proof."""
        cert = issue_branch_cert(self.org.org_id, self.org.ed_seed, self.main, int(time.time()))
        return {
            "challenge_id": challenge["challenge_id"],
            "nonce": nonce,
            "org_name": org_name,
            "org_slug": org_slug,
            "consent": True,
            "main_branch": branch_key_body(self.main, cert),
            "reader_public_key": to_base64url(self.org.reader_pk),
            "proof": register_proof(api_url, self.org, challenge["challenge_id"]),
        }

    def signer(self) -> Signer:
        return Signer(org_principal(self.org.org_id), self.org.ed_seed)


def _prepare(owner_dir: str | None, config_dir: str, org_slug: str) -> str:
    """Validate the slug and the owner dir, and make the runtime dir the agents will use."""
    if not validate_slug(org_slug):
        raise RineError(
            f"Invalid slug '{org_slug}'. Must match: [a-z0-9][a-z0-9-]{{0,30}}[a-z0-9]"
        )
    resolved = owner_dir or resolve_owner_dir()
    assert_fresh_owner_dir(resolved, config_dir)
    _ensure_dir(config_dir)
    return resolved


def _check_algorithm(challenge: dict[str, Any]) -> None:
    algorithm = challenge.get("algorithm")
    if algorithm != "rsa-timelock-v1":
        raise RineError(f"Unsupported PoW algorithm: {algorithm}")


def _refuse_solve(resp: httpx.Response, owner_dir: str) -> None:
    """Drop the root on a definitive refusal; keep it when the org may exist (a 5xx)."""
    if resp.status_code < 500:
        remove_root(owner_dir)
    _raise_registration_error(resp)


def _finish(mint: _Mint, owner_dir: str, profile: str, served_org_id: str) -> RegistrationResult:
    """Record the org the root derives; refuse a server that names another.

    The org id is a hash of the keys this client minted, so the only id worth
    pinning, printing as words or sealing escrow under is the local one. A
    different answer means the server did not register this root; ``root.key``
    stays because the org may still exist.
    """
    org_id = mint.org.org_id
    if served_org_id != org_id:
        raise RineError(
            "The server answered with an org id that does not match your root: refusing."
        )
    add_profile_if_absent(
        owner_dir,
        profile,
        Profile(org_id=org_id, principal=str(mint.signer().principal)),
    )
    return RegistrationResult(
        org_id=org_id,
        org_words=org_words(org_id),
        phrase_path=os.path.join(owner_dir, PHRASE_FILE),
    )


def register(
    api_url: str,
    config_dir: str,
    email: str,
    org_slug: str,
    org_name: str,
    on_progress: Callable[[int], None] | None = None,
    profile: str = DEFAULT_PROFILE,
    owner_dir: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> RegistrationResult:
    """Register a new org: mint its root, solve the PoW, send public keys only.

    Exported from the package root under two names: ``rine.register``, which is
    what the TypeScript SDK and the CLI call it, and ``rine.onboard``, which is
    what this SDK has always called it. They are the same object.

    ``root.key`` and the recovery phrase are written BEFORE the final request, so
    a process that dies after the server commits can still recover. They are
    removed again only when the server definitively refuses (a 4xx); a network
    failure or a 5xx keeps them, because the org may exist.

    Args:
        api_url: API base URL.
        config_dir: Runtime config directory the org's agents will use (created if absent).
        email: Contact email.
        org_slug: URL-safe org identifier.
        org_name: Human-readable org name.
        on_progress: Optional callback for PoW progress (0-100).
        profile: Name of the org profile written to the owner dir.
        owner_dir: Owner directory receiving ``root.key`` and the phrase;
            ``RINE_OWNER_DIR`` or ``~/.config/rine-owner`` when omitted.
        extra_headers: Headers sent with every request of the registration, the token
            fetch included; a load test sends a per-org ``X-Forwarded-For`` this way.

    Returns:
        RegistrationResult with the org id, its 8 verification words and the
        path of the written phrase. The phrase itself is never returned.

    Raises:
        RineError: If slug is invalid.
        ConfigError: If the owner dir is unsafe or already holds an org.
        ConflictError: If slug or email already in use.
        RateLimitError: If rate limited.
        RineApiError: If registration fails.
    """
    import httpx

    owner = _prepare(owner_dir, config_dir, org_slug)
    mint = _Mint.new()
    with httpx.Client(timeout=60, headers=extra_headers) as http:
        resp = http.post(
            f"{api_url}/auth/register", json=mint.begin_body(email, org_slug), headers=_HEADERS
        )
        if not resp.is_success:
            _raise_registration_error(resp)
        challenge = resp.json()
        _check_algorithm(challenge)

        nonce = solve_timelock(challenge["prefix"], challenge["modulus"], challenge["difficulty"])
        if on_progress:
            on_progress(100)

        save_root(owner, mint.root)
        resp = http.post(
            f"{api_url}/auth/register/solve",
            json=mint.solve_body(api_url, challenge, nonce, org_slug, org_name),
            headers=_HEADERS,
        )
        if not resp.is_success:
            _refuse_solve(resp, owner)
        result = _finish(mint, owner, profile, resp.json()["org_id"])
        try:
            token, expires_in = _fetch_oauth_token(http, api_url, mint.signer())
            cache_token(owner, str(mint.signer().principal), token, expires_in)
        except Exception:
            logger.warning("Failed to cache token after registration", exc_info=True)
    return result


async def async_register(
    api_url: str,
    config_dir: str,
    email: str,
    org_slug: str,
    org_name: str,
    on_progress: Callable[[int], None] | None = None,
    profile: str = DEFAULT_PROFILE,
    owner_dir: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> RegistrationResult:
    """Register a new org (async variant of :func:`register`).

    Exported from the package root as both ``rine.async_register`` and
    ``rine.async_onboard`` — the same object under the two spellings the product
    uses, exactly as its sync twin is. Arguments, results and errors are those of
    :func:`register`.
    """
    import asyncio

    import httpx

    owner = _prepare(owner_dir, config_dir, org_slug)
    mint = _Mint.new()
    async with httpx.AsyncClient(timeout=60, headers=extra_headers) as http:
        resp = await http.post(
            f"{api_url}/auth/register", json=mint.begin_body(email, org_slug), headers=_HEADERS
        )
        if not resp.is_success:
            _raise_registration_error(resp)
        challenge = resp.json()
        _check_algorithm(challenge)

        nonce = await asyncio.to_thread(
            solve_timelock, challenge["prefix"], challenge["modulus"], challenge["difficulty"]
        )
        if on_progress:
            on_progress(100)

        save_root(owner, mint.root)
        resp = await http.post(
            f"{api_url}/auth/register/solve",
            json=mint.solve_body(api_url, challenge, nonce, org_slug, org_name),
            headers=_HEADERS,
        )
        if not resp.is_success:
            _refuse_solve(resp, owner)
        result = _finish(mint, owner, profile, resp.json()["org_id"])
        try:
            token, expires_in = await _fetch_oauth_token_async(http, api_url, mint.signer())
            cache_token(owner, str(mint.signer().principal), token, expires_in)
        except Exception:
            logger.warning("Failed to cache token after registration", exc_info=True)
    return result
