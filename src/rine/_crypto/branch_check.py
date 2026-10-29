"""Check that the branch certificate commits to the secrets a bundle carried.

A fleet is handed a delegated branch's ``(b_read, b_sign)`` in a sealed bundle.
The branch certificate the server serves is the only thing that ties those
secrets to the branch: :func:`verify_held_branch` checks the certificate chains
to the org the caller holds and that every claim it makes is the key the held
secrets derive. A read half that is not the branch's, or a signing half that is
not, is refused before either is used.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._crypto.certs import (
    Branch,
    ChainError,
    key_digest,
    verified_branch,
)
from rine._utils import to_base64url
from rine.errors import CryptoError

if TYPE_CHECKING:
    from rine._crypto.derive_nodes import BranchNode

HELD_BRANCH_INVALID = "held branch secrets invalid"


class HeldBranchError(ChainError):
    """The secrets a bundle carried are not the branch the certificate names."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason, label=HELD_BRANCH_INVALID)


def verify_held_branch(response: dict[str, Any], node: BranchNode, org_id: str) -> Branch:
    """Check a branch certificate commits to the secrets the caller holds.

    Args:
        response: The decoded ``/orgs/me/branches/{name}/escrow-key`` response.
        node: The branch node built locally from the held ``(b_read, b_sign)``.
        org_id: The org the caller holds locally.

    Returns:
        The verified branch, whose claims name the held secrets' keys.

    Raises:
        HeldBranchError: The certificate does not chain to ``org_id``, names
            another branch, or commits to keys the held secrets do not derive.
    """
    try:
        return _verify_held_branch(response, node, org_id)
    except HeldBranchError:
        raise
    except (CryptoError, KeyError, TypeError, ValueError) as exc:
        raise HeldBranchError(f"malformed branch response: {exc}") from exc


def _verify_held_branch(response: dict[str, Any], node: BranchNode, org_id: str) -> Branch:
    error = HeldBranchError
    verified = verified_branch(response, error)
    if verified.org_id != org_id:
        raise error("the branch belongs to another org")
    if verified.name != node.name:
        raise error("the branch certificate names another branch")
    claims = verified.claims
    read = {
        "rdr": to_base64url(node.reader_pk),
        "escx": to_base64url(node.escrow_x_pk),
        "esck": key_digest(node.escrow_kem_pk),
    }
    signing = {
        "sig": to_base64url(node.ed_pk),
        "dsa": key_digest(node.dsa_pk),
    }
    if any(claims[name] != value for name, value in read.items()):
        raise error("the read half is not the branch the certificate names")
    if any(claims[name] != value for name, value in signing.items()):
        raise error("the signing half is not the branch the certificate names")
    return verified
