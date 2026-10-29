"""The branch escrow key check.

Split out of :mod:`rine._crypto.certs`, which owns the shared chain links. The
escrow key a member seals MLS read escrow to is trusted only when it chains to
the org this client holds locally and the agent certificate it holds locally
names the signing key it actually has: nothing the server answers with can
choose either side of that comparison.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from rine._crypto import _mlkem
from rine._crypto.certs import (
    AGENT_FIELDS,
    ChainError,
    b64_field,
    key_digest,
    verified_branch,
    verified_claims,
)
from rine._crypto.jws import JwsTyp
from rine._utils import to_base64url
from rine.errors import CryptoError

ESCROW_KEY_INVALID = "branch escrow key invalid"

_X25519_SIZE = 32


class EscrowKeyError(ChainError):
    """A branch escrow key does not chain to the agent's own org and branch."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, label=ESCROW_KEY_INVALID)


@dataclass(frozen=True, slots=True)
class OwnIdentity:
    """What this client itself holds: never a value read from a key response."""

    org_id: str
    agent_id: str
    agent_signing_public_key: bytes
    agent_certificate: str


@dataclass(frozen=True, slots=True)
class VerifiedEscrowKey:
    """A branch escrow key verified under the agent's own org and branch."""

    org_id: str
    branch: str
    x25519_public_key: bytes
    ml_kem_public_key: bytes


def verify_branch_escrow_key(response: dict[str, Any], own: OwnIdentity) -> VerifiedEscrowKey:
    """Verify the branch escrow key an agent is about to seal MLS escrow to.

    The key must belong to the agent's own org and its own branch, and the
    agent's own certificate must name the Ed25519 key the agent actually holds,
    so a server cannot hand a member a key it can read.

    Args:
        response: The decoded ``/orgs/me/branches/{name}/escrow-key`` response.
        own: The org id, signing public key and agent certificate held locally.

    Returns:
        The escrow key pair, safe to seal to.

    Raises:
        EscrowKeyError: The key is not provably the agent's own branch's.
    """
    try:
        return _verify_escrow_key(response, own)
    except EscrowKeyError:
        raise
    except (CryptoError, KeyError, TypeError, ValueError) as exc:
        raise EscrowKeyError(f"malformed escrow key response: {exc}") from exc


def _verify_escrow_key(response: dict[str, Any], own: OwnIdentity) -> VerifiedEscrowKey:
    error = EscrowKeyError
    branch = verified_branch(response, error)
    if branch.org_id != own.org_id:
        raise error("the escrow key belongs to another org")
    agent = verified_claims(
        own.agent_certificate,
        branch.signing_public_key,
        JwsTyp.AGENT_CERT,
        AGENT_FIELDS,
        error,
    )
    held = to_base64url(own.agent_signing_public_key)
    names_us = (agent["sig"], agent["org"], agent["agent"]) == (held, own.org_id, own.agent_id)
    if not names_us or agent["branch"] != branch.name:
        raise error("the agent certificate does not name this agent's key, id, org and branch")
    x25519 = b64_field(response.get("escrow_public_key"), "escrow key", _X25519_SIZE, error)
    ml_kem = b64_field(
        response.get("escrow_pq_public_key"), "escrow PQ key", _mlkem.PUBLIC_KEY_SIZE, error
    )
    claims = branch.claims
    if claims["escx"] != to_base64url(x25519) or claims["esck"] != key_digest(ml_kem):
        raise error("the escrow keys are not the ones the branch certificate commits to")
    return VerifiedEscrowKey(branch.org_id, branch.name, x25519, ml_kem)
