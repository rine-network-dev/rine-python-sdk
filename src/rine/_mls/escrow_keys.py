"""The verified branch escrow key, cached per (org id, agent id).

The read is the only place a 410 ``branch revoked`` is handled, and the only
place the key is verified against the caller's own org and its own agent
certificate. The TypeScript twin is ``rine-core/src/mls-escrow-key.ts``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from threading import Lock
from typing import TYPE_CHECKING

from rine._constants import KEY_CACHE_TTL
from rine._crypto.escrow_key import EscrowKeyError, OwnIdentity, verify_branch_escrow_key
from rine._crypto.keys import load_agent_keys
from rine._mls.escrow_api import fetch_branch_escrow_key
from rine.errors import CryptoError, RineApiError

if TYPE_CHECKING:
    from typing import Any

    from rine._crypto.escrow_key import VerifiedEscrowKey
    from rine._mls.heartbeat import MlsActor

#: The server's answer when a branch has been revoked: ``GET …/escrow-key`` 410s.
ESCROW_KEY_REVOKED = "branch revoked"

#: The status the server answers a revoked branch's escrow key with.
_ESCROW_KEY_REVOKED_STATUS = 410


@dataclass(frozen=True, slots=True)
class _Entry:
    """A verified key and the monotonic instant it was stored at."""

    key: VerifiedEscrowKey
    stored_at: float


#: Verified branch escrow keys per ``(org id, agent id)``, process-wide.
#:
#: Keyed by agent rather than by branch because the branch is only known from
#: the ``GET /agents/{id}/keys`` response, and a cache hit must not pay for that
#: read. The verified key carries its own ``branch``, which is what
#: :func:`drop_escrow_keys` filters on. An entry older than
#: :data:`rine._constants.KEY_CACHE_TTL` is a miss and is dropped when seen.
_cache: dict[tuple[str, str], _Entry] = {}
_cache_lock = Lock()


class BranchRevokedError(CryptoError):
    """A branch whose escrow key the server refuses to serve any more.

    Never a fallback: an escrow sealed to a revoked branch's key is readable by
    nobody, so the read stops rather than sealing to a key the org has retired.
    """

    def __init__(self) -> None:
        super().__init__(ESCROW_KEY_REVOKED)


def _own_org(actor: MlsActor) -> str | None:
    """The acting agent's own org id, read locally from the client's key pins."""
    org_id: str | None = actor.client.key_pins.own_org_of(actor.agent_id)
    return org_id


def _fresh(entry: _Entry, now: float) -> bool:
    """Whether a cached entry is still within the key-cache window."""
    return now - entry.stored_at <= KEY_CACHE_TTL


def drop_escrow_keys(org_id: str | None = None, branch: str | None = None) -> None:
    """Forget cached escrow keys, for one org and optionally one branch.

    Args:
        org_id: The org to forget; ``None`` clears every cached key.
        branch: When given, only entries whose verified key names that branch.
    """
    with _cache_lock:
        if org_id is None:
            _cache.clear()
            return
        for key in [k for k in _cache if k[0] == org_id]:
            if branch is None or _cache[key].key.branch == branch:
                del _cache[key]


def cached_escrow_key(actor: MlsActor, *, now: float | None = None) -> VerifiedEscrowKey | None:
    """The acting agent's verified escrow key when cached and fresh, else ``None``.

    No network: the org id is read from the client's own key pins, and an
    unknown org is a miss. An entry older than the key-cache window is dropped
    here and reported as a miss.

    Args:
        actor: Who is acting, and through which sync client.
        now: The monotonic instant to age entries against; defaults to now.
    """
    org_id = _own_org(actor)
    if org_id is None:
        return None
    key = (org_id, actor.agent_id)
    instant = time.monotonic() if now is None else now
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        if not _fresh(entry, instant):
            del _cache[key]
            return None
        return entry.key


def drop_cached_escrow_key(actor: MlsActor) -> None:
    """Forget the acting agent's own cached escrow key.

    Does nothing when no own org id is pinned for the agent, since no entry
    could have been stored under an unknown org.
    """
    org_id = _own_org(actor)
    if org_id is None:
        return
    with _cache_lock:
        _cache.pop((org_id, actor.agent_id), None)


def _agent_key_fields(response: dict[str, Any]) -> tuple[str, str]:
    """The branch name and agent certificate a ``GET /agents/{id}/keys`` answer carries."""
    try:
        return str(response["branch"]), str(response["agent_certificate"])
    except (KeyError, TypeError) as exc:
        raise EscrowKeyError(f"malformed agent keys response: {exc}") from exc


def resolve_escrow_key(actor: MlsActor) -> VerifiedEscrowKey:
    """The acting agent's own branch escrow key, verified and then cached.

    The verified entry lives for the existing key-cache window
    (:data:`rine._constants.KEY_CACHE_TTL`) and is dropped on a
    ``branch_revoked`` answer, so a key the server stops serving is not trusted
    past that window.

    The agent certificate is read raw off ``GET /agents/{id}/keys`` on purpose:
    the chain-verifying key cache enforces the key-chain pins on a different
    path, and the verification here IS :func:`verify_branch_escrow_key`, which
    checks the agent certificate chains to the branch certificate, that the org
    is the locally pinned one, and that the certificate names the signing key
    this device holds.

    Args:
        actor: Who is acting, and through which sync client.

    Returns:
        The verified branch escrow key, safe to seal MLS read escrow to.

    Raises:
        CryptoError: No own org id is pinned for the acting agent.
        BranchRevokedError: The server 410s the branch's escrow key.
        EscrowKeyError: The key is not provably the agent's own branch's.
        RineApiError: Any other HTTP failure.
    """
    cached = cached_escrow_key(actor)
    if cached is not None:
        return cached

    org_id = _own_org(actor)
    if org_id is None:
        raise CryptoError(
            f"no own org id for agent {actor.agent_id}: cannot verify the branch escrow key"
        )
    branch, agent_certificate = _agent_key_fields(
        actor.client.get(f"/agents/{actor.agent_id}/keys")
    )
    signing_public_key = load_agent_keys(actor.config_dir, actor.agent_id).signing.public_key
    try:
        body = fetch_branch_escrow_key(actor.client, actor.agent_id, branch)
    except RineApiError as exc:
        if exc.status == _ESCROW_KEY_REVOKED_STATUS:
            drop_escrow_keys(org_id, branch)
            raise BranchRevokedError() from exc
        raise
    verified = verify_branch_escrow_key(
        body,
        OwnIdentity(
            org_id=org_id,
            agent_id=actor.agent_id,
            agent_signing_public_key=signing_public_key,
            agent_certificate=agent_certificate,
        ),
    )
    with _cache_lock:
        _cache[(org_id, actor.agent_id)] = _Entry(verified, time.monotonic())
    return verified
