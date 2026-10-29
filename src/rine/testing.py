"""A derived org for tests: real keys, real certificates, real key responses, real identity files.

A package's tests need a peer's published keys and an agent's on-disk identity that
pass the same chain check production runs. This module derives one org and branch
from a fixed root and signs what a server would serve, with the SDK's own
primitives; nothing here is a shortcut around :mod:`rine._crypto.certs`. It is for
tests only: the root is public.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from rine._crypto.certs import VerifiedAgentKeys, verify_agent_chain
from rine._crypto.derive_nodes import (
    AgentNode,
    BranchNode,
    OrgNode,
    derive_agent,
    derive_branch,
    derive_org,
)
from rine._crypto.jws import JwsTyp, sign_jws
from rine._crypto.keys import (
    AgentKeys,
    agent_keys_from_node,
    encryption_public_key_to_jwk,
    save_agent_keys,
    signing_public_key_to_jwk,
)
from rine._crypto.pq_keys import pq_public_key_to_jwk, pq_signing_public_key_to_jwk
from rine._owner import save_root
from rine._principal import agent_principal, org_principal
from rine._profiles import DEFAULT_PROFILE, add_profile_if_absent
from rine._types import Profile
from rine._utils import to_base64url

__all__ = ["WORLD", "World", "write_agent_identity", "write_owner"]

#: Fixed certificate issue time (seconds); the chain check only needs it to be in the past.
_IAT = 1790000000


def _digest(public_key: bytes) -> str:
    return to_base64url(hashlib.sha256(public_key).digest())


@dataclass
class World:
    """One org and one branch, from which any agent generation can be minted."""

    root: bytes = bytes(range(32))
    branch_name: str = "main"
    org: OrgNode = field(init=False)
    branch: BranchNode = field(init=False)

    def __post_init__(self) -> None:
        self.org = derive_org(self.root)
        self.branch = derive_branch(self.org.r_read, self.org.r_sign, self.branch_name)

    @property
    def org_id(self) -> str:
        """The org's id."""
        return self.org.org_id

    def node(self, agent_id: str, gen: int = 0) -> AgentNode:
        """The derived node of one agent generation."""
        return derive_agent(self.branch.b_read, self.branch.b_sign, agent_id, gen)

    def keys(self, agent_id: str, gen: int = 0) -> AgentKeys:
        """The leaf keys an agent holds at one generation."""
        return agent_keys_from_node(self.node(agent_id, gen))

    def branch_certificate(self) -> str:
        """The org-signed certificate of this world's branch."""
        return sign_jws(
            JwsTyp.BRANCH_CERT,
            {
                "branch": self.branch.name,
                "dsa": _digest(self.branch.dsa_pk),
                "esck": _digest(self.branch.escrow_kem_pk),
                "escx": to_base64url(self.branch.escrow_x_pk),
                "iat": _IAT,
                "org": self.org_id,
                "rdr": to_base64url(self.branch.reader_pk),
                "sig": to_base64url(self.branch.ed_pk),
                "v": 1,
            },
            self.org.ed_seed,
        )

    def agent_certificate(self, node: AgentNode) -> str:
        """The branch-signed certificate of one agent generation."""
        return sign_jws(
            JwsTyp.AGENT_CERT,
            {
                "agent": node.agent_id,
                "branch": self.branch.name,
                "dsa": _digest(node.dsa_pk),
                "enc": to_base64url(node.x_pk),
                "gen": node.gen,
                "iat": _IAT,
                "kem": _digest(node.kem_pk),
                "mls": to_base64url(node.mls_pk),
                "org": self.org_id,
                "sig": to_base64url(node.ed_pk),
                "v": 1,
            },
            self.branch.ed_seed,
        )

    def org_fields(self) -> dict[str, Any]:
        """The org and branch fields every key response carries."""
        return {
            "org_id": self.org_id,
            "org_signing_public_key": to_base64url(self.org.ed_pk),
            "org_pq_signing_public_key": to_base64url(self.org.dsa_pk),
            "branch": self.branch.name,
            "branch_certificate": self.branch_certificate(),
        }

    def keys_response(self, agent_id: str, gen: int = 0) -> dict[str, Any]:
        """A chain-valid ``GET /agents/{id}/keys`` body for one generation."""
        node = self.node(agent_id, gen)
        return {
            **self.org_fields(),
            "signing_public_key": signing_public_key_to_jwk(node.ed_pk),
            "encryption_public_key": encryption_public_key_to_jwk(node.x_pk),
            "pq_encryption_public_key": pq_public_key_to_jwk(node.kem_pk),
            "pq_signing_public_key": pq_signing_public_key_to_jwk(node.dsa_pk),
            "mls_signing_public_key": signing_public_key_to_jwk(node.mls_pk),
            "key_gen": gen,
            "agent_certificate": self.agent_certificate(node),
        }

    def verified(self, agent_id: str, gen: int = 0) -> VerifiedAgentKeys:
        """The chain-verified keys of one agent generation."""
        return verify_agent_chain(self.keys_response(agent_id, gen), agent_id)

    def escrow_response(self) -> dict[str, Any]:
        """A chain-valid branch escrow-key body."""
        return {
            **self.org_fields(),
            "escrow_public_key": to_base64url(self.branch.escrow_x_pk),
            "escrow_pq_public_key": to_base64url(self.branch.escrow_kem_pk),
        }


WORLD = World()
"""The shared world every test uses unless it needs a second org."""


def write_agent_identity(
    config_dir: str,
    agent_id: str,
    *,
    world: World = WORLD,
    profile: str = DEFAULT_PROFILE,
    poll_url: str | None = None,
) -> None:
    """Save the agent's derived leaf keys and name it in a runtime profile."""
    save_agent_keys(config_dir, agent_id, world.keys(agent_id))
    entry = Profile(
        org_id=world.org_id,
        principal=str(agent_principal(agent_id)),
        branch=world.branch_name,
        agent_id=agent_id,
    )
    if poll_url:
        entry["poll_url"] = poll_url
    add_profile_if_absent(config_dir, profile, entry)


def write_owner(owner_dir: str, *, world: World = WORLD, profile: str = DEFAULT_PROFILE) -> None:
    """Save the world's ``root.key`` and the org profile in an owner dir."""
    save_root(owner_dir, world.root)
    add_profile_if_absent(
        owner_dir,
        profile,
        Profile(org_id=world.org_id, principal=str(org_principal(world.org_id))),
    )
