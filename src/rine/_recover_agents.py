"""Step 4 of recovery: check one listed agent against the phrase's derivation.

An agent is restored only when every public key the server holds for it, and its
certificate, equal what the phrase derives. The leaf keys are returned, not
written: the caller writes them once every agent has been checked.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from rine._crypto.derive_nodes import AgentNode, BranchNode, derive_agent
from rine._crypto.jws import JwsError, JwsTyp, verify_jws
from rine._crypto.keys import AgentKeys, agent_keys_from_node, held_key_gen
from rine._http import _check_response
from rine._org_certs import agent_cert_claims
from rine._utils import to_base64url

if TYPE_CHECKING:
    import httpx

_KEY_FIELDS = (
    ("signing_public_key", "ed_pk"),
    ("encryption_public_key", "x_pk"),
    ("mls_signing_public_key", "mls_pk"),
    ("pq_encryption_public_key", "kem_pk"),
    ("pq_signing_public_key", "dsa_pk"),
)


class AgentRecoveryStatus(StrEnum):
    """What recovery did with one agent."""

    RESTORED = "restored"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class AgentRecovery:
    """One agent's outcome. ``reason`` says why a mismatching agent was refused."""

    agent_id: str
    name: str
    branch: str
    key_gen: int
    status: AgentRecoveryStatus
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class CheckedAgent:
    """An agent's outcome, with the leaf keys to write when it was restored."""

    recovery: AgentRecovery
    keys: AgentKeys | None = None


def mismatch_reason(
    org_id: str, branch: BranchNode, node: AgentNode, server: dict[str, Any]
) -> str | None:
    """The first way the server's copy of an agent differs from the derived keys, or ``None``."""
    for wire, attr in _KEY_FIELDS:
        if server[wire].get("x") != to_base64url(getattr(node, attr)):
            return f"{wire} differs from the key derived from this phrase"
    try:
        claims = verify_jws(server["agent_certificate"], branch.ed_pk, JwsTyp.AGENT_CERT)
    except JwsError:
        return "agent certificate does not verify under the derived branch key"
    expected = agent_cert_claims(org_id, branch.name, node, int(claims["iat"]))
    for key, value in expected.items():
        if claims.get(key) != value:
            return f"agent certificate claim '{key}' differs"
    return None


def _serves_newer_generation(http: httpx.Client, agent_id: str, key_gen: int) -> bool:
    """True when the server also serves ``key_gen + 1`` for an agent it reports at ``key_gen``.

    A server that rolls recovery back reports an old generation as current while still
    holding the newer ones, so the next generation answering 200 proves it.
    """
    resp = http.get(f"/agents/{agent_id}/keys", params={"gen": key_gen + 1})
    if resp.status_code == 404:
        return False
    _check_response(resp)
    return True


def check_agent(
    http: httpx.Client,
    config_dir: str,
    org_id: str,
    branches: dict[str, BranchNode],
    agent: dict[str, Any],
) -> CheckedAgent:
    """Fetch one agent's keys and check them against the derivation, writing nothing.

    A server that answers with an older generation than this device already holds
    would roll the agent back onto keys that were superseded, so it is refused.
    """
    agent_id = str(agent["id"])
    server = _check_response(http.get(f"/agents/{agent_id}/keys"))
    base = {
        "agent_id": agent_id,
        "name": str(agent["name"]),
        "branch": server["branch"],
        "key_gen": server["key_gen"],
    }

    def refused(reason: str) -> CheckedAgent:
        return CheckedAgent(
            AgentRecovery(**base, status=AgentRecoveryStatus.MISMATCH, reason=reason)
        )

    branch = branches.get(server["branch"])
    if branch is None:
        return refused("branch is not derivable from this phrase")
    held = held_key_gen(config_dir, agent_id)
    if held is not None and server["key_gen"] < held:
        return refused("the server's key generation is older than the one held on this device")
    if _serves_newer_generation(http, agent_id, server["key_gen"]):
        return refused("the server reports a current key generation below one it also serves")
    node = derive_agent(branch.b_read, branch.b_sign, agent_id, server["key_gen"])
    reason = mismatch_reason(org_id, branch, node, server)
    if reason is not None:
        return refused(reason)
    return CheckedAgent(
        AgentRecovery(**base, status=AgentRecoveryStatus.RESTORED), agent_keys_from_node(node)
    )
