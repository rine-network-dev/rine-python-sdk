"""Certificates, the registration proof and the key bodies that carry them.

The org key signs a branch's cert and the branch key signs each agent's, so a
server that holds only public keys can check the whole chain. Verification lives
in :mod:`rine._crypto.certs`; this is the issuing half, which only a holder of the
org root or a delegated branch ever runs.

Create and rotate share one body builder: create is generation 0 plus an id, a
name and flags, and rotate is the next generation and nothing else.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from rine._crypto.certs import CERT_VERSION, key_digest
from rine._crypto.derive_nodes import AgentNode, BranchNode, OrgNode, derive_agent
from rine._crypto.jws import JwsTyp, sign_jws
from rine._crypto.keys import AgentKeys, agent_keys_from_node, public_keys_body
from rine._utils import to_base64url

if TYPE_CHECKING:
    from rine._branch_custody import BranchSecrets
    from rine._custody import Custody

_REGISTER_SOLVE_PATH = "/auth/register/solve"


def issue_branch_cert(org_id: str, org_ed_seed: bytes, branch: BranchNode, iat: int) -> str:
    """The org-signed certificate committing to one branch's keys."""
    return sign_jws(
        JwsTyp.BRANCH_CERT,
        {
            "branch": branch.name,
            "dsa": key_digest(branch.dsa_pk),
            "esck": key_digest(branch.escrow_kem_pk),
            "escx": to_base64url(branch.escrow_x_pk),
            "iat": iat,
            "org": org_id,
            "rdr": to_base64url(branch.reader_pk),
            "sig": to_base64url(branch.ed_pk),
            "v": CERT_VERSION,
        },
        org_ed_seed,
    )


def agent_cert_claims(org_id: str, branch: str, node: AgentNode, iat: int) -> dict[str, str | int]:
    """The claims an agent cert commits to: every public key of one generation."""
    return {
        "agent": node.agent_id,
        "branch": branch,
        "dsa": key_digest(node.dsa_pk),
        "enc": to_base64url(node.x_pk),
        "gen": node.gen,
        "iat": iat,
        "kem": key_digest(node.kem_pk),
        "mls": to_base64url(node.mls_pk),
        "org": org_id,
        "sig": to_base64url(node.ed_pk),
        "v": CERT_VERSION,
    }


def issue_agent_cert(org_id: str, branch: BranchSecrets, node: AgentNode, iat: int) -> str:
    """The branch-signed certificate committing to one agent generation's keys."""
    return sign_jws(
        JwsTyp.AGENT_CERT, agent_cert_claims(org_id, branch.name, node, iat), branch.ed_seed
    )


def register_proof(api_url: str, org: OrgNode, challenge_id: str) -> str:
    """The proof of possession the org key signs at ``POST /auth/register/solve``."""
    return sign_jws(
        JwsTyp.REGISTER_POP,
        {
            "aud": f"{api_url}{_REGISTER_SOLVE_PATH}",
            "challenge_id": challenge_id,
            "dsa": key_digest(org.dsa_pk),
            "org": org.org_id,
            "rdr": to_base64url(org.reader_pk),
            "v": CERT_VERSION,
        },
        org.ed_seed,
    )


def branch_key_body(branch: BranchNode, certificate: str) -> dict[str, str]:
    """A branch's public keys and org-signed cert, as the register route takes them."""
    return {
        "signing_public_key": to_base64url(branch.ed_pk),
        "pq_signing_public_key": to_base64url(branch.dsa_pk),
        "escrow_public_key": to_base64url(branch.escrow_x_pk),
        "escrow_pq_public_key": to_base64url(branch.escrow_kem_pk),
        "reader_public_key": to_base64url(branch.reader_pk),
        "certificate": certificate,
    }


class AgentRequest:
    """A request body, and the leaf keys to save once the server accepts it."""

    __slots__ = ("body", "keys")

    def __init__(self, body: dict[str, Any], keys: AgentKeys) -> None:
        self.body = body
        self.keys = keys


def _agent_request(custody: Custody, agent_id: str, gen: int) -> AgentRequest:
    node = derive_agent(custody.branch.b_read, custody.branch.b_sign, agent_id, gen)
    keys = agent_keys_from_node(node)
    body: dict[str, Any] = {
        "branch": custody.branch.name,
        **public_keys_body(keys, node.dsa_pk),
        "agent_certificate": issue_agent_cert(
            custody.org_id, custody.branch, node, int(time.time())
        ),
    }
    return AgentRequest(body, keys)


def agent_create_request(
    custody: Custody, agent_id: str, name: str, *, human_oversight: bool, unlisted: bool
) -> AgentRequest:
    """The ``POST /agents`` body for a new agent: a client-minted id and generation-0 keys."""
    request = _agent_request(custody, agent_id, 0)
    request.body = {
        "id": agent_id,
        "name": name,
        "human_oversight": human_oversight,
        "unlisted": unlisted,
        **request.body,
    }
    return request


def agent_rotate_request(custody: Custody, agent_id: str, next_gen: int) -> AgentRequest:
    """The ``POST /agents/{id}/keys`` body for generation ``next_gen`` (the current plus one)."""
    request = _agent_request(custody, agent_id, next_gen)
    request.body = {"key_gen": next_gen, **request.body}
    return request
