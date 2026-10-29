"""The org-signed key chain, checked at every key consumer.

A published agent key is trusted only through this chain::

    org keys --UUIDv8--> org_id
    org Ed25519 key  --signs-->  branch cert  (carries the branch Ed25519 key)
    branch Ed25519 key  --signs-->  agent cert  (commits to every agent key)

:func:`verify_agent_chain` runs the whole chain over one ``/agents/{id}/keys``
response and returns :class:`VerifiedAgentKeys`, the only form of a peer's keys
the rest of the SDK accepts. The escrow key a member seals MLS read escrow to is
checked by :mod:`rine._crypto.escrow_key`. Any failure raises; there is no
fallback to unchecked keys.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rine._crypto import _mldsa
from rine._crypto.derive import UUID_RE, org_id_from_keys
from rine._crypto.ed25519_strict import is_valid_public_key
from rine._crypto.jws import JwsError, JwsTyp, verify_jws
from rine._crypto.keys import jwk_to_public_key
from rine._crypto.pq_keys import jwk_to_pq_public_key, jwk_to_pq_signing_public_key
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

CHAIN_INVALID = "recipient key chain invalid"

CERT_VERSION = 1
_BRANCH_FIELDS = frozenset({"branch", "dsa", "esck", "escx", "iat", "org", "rdr", "sig", "v"})
AGENT_FIELDS = frozenset(
    {"agent", "branch", "dsa", "enc", "gen", "iat", "kem", "mls", "org", "sig", "v"}
)
_ED25519_SIZE = 32


class ChainError(CryptoError):
    """A published key does not chain to the org that claims it."""

    def __init__(self, reason: str, *, label: str = CHAIN_INVALID) -> None:
        super().__init__(f"{label}: {reason}")


@dataclass(frozen=True, slots=True)
class VerifiedAgentKeys:
    """An agent's published keys after the whole chain checked out."""

    agent_id: str
    org_id: str
    branch: str
    key_gen: int
    signing_public_key: bytes
    encryption_public_key: bytes
    pq_encryption_public_key: bytes
    mls_public_key: bytes
    superseded_at: datetime | None = None
    """When the generation stopped being valid; ``None`` for the current one."""
    revoked_at: datetime | None = None
    """When the agent, or its branch, was revoked; ``None`` while neither is."""


def signed_within_validity(
    keys: VerifiedAgentKeys, created_at: datetime | None, *, historical: bool
) -> bool:
    """Whether a row the server stamped at ``created_at`` falls inside ``keys``' validity.

    A generation below the sender's current one (``historical``) signs only for an object
    stamped at or before its ``superseded_at``. A revoked agent's generation signs only
    for an object stamped at or before ``revoked_at``. The earlier bound wins when both are
    set. A missing stamp on either side refuses, so a history read that omits
    ``superseded_at`` or a caller that never passed the row's ``created_at`` cannot reopen
    a rotated-away or revoked key.
    """
    if historical and keys.superseded_at is None:
        return False
    bounds = [bound for bound in (keys.superseded_at, keys.revoked_at) if bound is not None]
    if not bounds:
        return True
    if created_at is None or created_at.tzinfo is None:
        return False
    return created_at <= min(bounds)


@dataclass(frozen=True, slots=True)
class Branch:
    org_id: str
    name: str
    claims: dict[str, str | int]
    signing_public_key: bytes


def key_digest(public_key: bytes) -> str:
    return to_base64url(hashlib.sha256(public_key).digest())


def b64_field(value: Any, label: str, size: int, error: type[ChainError]) -> bytes:
    """Decode a base64url field that must be exactly ``size`` bytes."""
    if not isinstance(value, str):
        raise error(f"{label} is missing")
    try:
        raw = from_base64url(value)
    except (CryptoError, ValueError) as exc:
        raise error(f"{label} is not base64url") from exc
    if len(raw) != size:
        raise error(f"{label} has the wrong length")
    return raw


def verified_claims(
    compact: Any, public_key: bytes, typ: JwsTyp, fields: frozenset[str], error: type[ChainError]
) -> dict[str, str | int]:
    """Verify a cert JWS and require exactly the expected claim names."""
    if not isinstance(compact, str):
        raise error(f"{typ.value} is missing")
    try:
        claims = verify_jws(compact, public_key, typ)
    except JwsError as exc:
        raise error(f"{typ.value}: {exc}") from exc
    if set(claims) != fields or claims["v"] != CERT_VERSION:
        raise error(f"{typ.value} has unexpected claims")
    return claims


def _verified_org(response: dict[str, Any], error: type[ChainError]) -> tuple[str, bytes]:
    """Check ``org_id`` against the org keys the response carries."""
    ed_pk = b64_field(response.get("org_signing_public_key"), "org key", _ED25519_SIZE, error)
    dsa_pk = b64_field(
        response.get("org_pq_signing_public_key"), "org PQ key", _mldsa.PUBLIC_KEY_SIZE, error
    )
    org_id = response.get("org_id")
    if not isinstance(org_id, str) or org_id != org_id_from_keys(ed_pk, dsa_pk):
        raise error("org_id does not commit to the org keys")
    return org_id, ed_pk


def verified_branch(response: dict[str, Any], error: type[ChainError]) -> Branch:
    org_id, org_pk = _verified_org(response, error)
    claims = verified_claims(
        response.get("branch_certificate"), org_pk, JwsTyp.BRANCH_CERT, _BRANCH_FIELDS, error
    )
    if claims["org"] != org_id or claims["branch"] != response.get("branch"):
        raise error("branch certificate names another org or branch")
    sig_pk = b64_field(claims["sig"], "branch certificate sig", _ED25519_SIZE, error)
    return Branch(org_id, str(claims["branch"]), claims, sig_pk)


def verify_agent_chain(response: dict[str, Any], agent_id: str) -> VerifiedAgentKeys:
    """Verify one ``/agents/{id}/keys`` response down to the agent's keys.

    Args:
        response: The decoded key response.
        agent_id: The agent the caller asked about.

    Returns:
        The agent's keys, each one committed to by the agent certificate.

    Raises:
        ChainError: Any link of the chain is missing, mislabelled or broken.
    """
    try:
        return _verify_agent_chain(response, agent_id)
    except ChainError:
        raise
    except (CryptoError, KeyError, TypeError, ValueError) as exc:
        raise ChainError(f"malformed key response: {exc}") from exc


def _verify_agent_chain(response: dict[str, Any], agent_id: str) -> VerifiedAgentKeys:
    error = ChainError
    if not UUID_RE.fullmatch(agent_id):
        raise error("agent id is not canonical")
    branch = verified_branch(response, error)
    agent = verified_claims(
        response.get("agent_certificate"),
        branch.signing_public_key,
        JwsTyp.AGENT_CERT,
        AGENT_FIELDS,
        error,
    )
    signing = jwk_to_public_key(response["signing_public_key"], expected_crv="Ed25519")
    encryption = jwk_to_public_key(response["encryption_public_key"], expected_crv="X25519")
    mls = jwk_to_public_key(response["mls_signing_public_key"], expected_crv="Ed25519")
    if not (is_valid_public_key(signing) and is_valid_public_key(mls)):
        raise error("an agent Ed25519 key is not a strict public key")
    kem = jwk_to_pq_public_key(response["pq_encryption_public_key"])
    dsa = jwk_to_pq_signing_public_key(response["pq_signing_public_key"])
    key_gen = response["key_gen"]
    committed = {
        "agent": agent_id,
        "branch": branch.name,
        "org": branch.org_id,
        "gen": key_gen,
        "sig": to_base64url(signing),
        "enc": to_base64url(encryption),
        "mls": to_base64url(mls),
        "kem": key_digest(kem),
        "dsa": key_digest(dsa),
    }
    if isinstance(key_gen, bool) or any(agent[name] != value for name, value in committed.items()):
        raise error("agent certificate does not match the returned keys")
    return VerifiedAgentKeys(
        agent_id,
        branch.org_id,
        branch.name,
        key_gen,
        signing,
        encryption,
        kem,
        mls,
        _timestamp(response, "superseded_at"),
        _timestamp(response, "revoked_at"),
    )


def _timestamp(response: dict[str, Any], name: str) -> datetime | None:
    """A validity bound a key read carries, required to be timezone-aware."""
    raw = response.get(name)
    if raw is None:
        return None
    stamp = datetime.fromisoformat(raw)
    if stamp.tzinfo is None:
        raise ValueError(f"{name} has no timezone")
    return stamp
