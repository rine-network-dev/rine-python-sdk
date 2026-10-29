"""The org, branch and agent nodes of the derivation tree.

Each builder is a pure function of its parent secrets. Secret fields are
declared with ``field(repr=False)`` so a repr or traceback never prints key
material.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rine._crypto import _mldsa, _mlkem
from rine._crypto.derive import (
    canonical_agent_label_id,
    check_branch_name,
    derive,
    ed25519_public_key,
    org_id_from_keys,
    x25519_public_key,
)
from rine.errors import CryptoError


@dataclass(frozen=True, slots=True)
class OrgNode:
    """The org-level keys derived from a 32-byte root."""

    r_read: bytes = field(repr=False)
    r_sign: bytes = field(repr=False)
    reader_seed: bytes = field(repr=False)
    ed_seed: bytes = field(repr=False)
    dsa_xi: bytes = field(repr=False)
    reader_pk: bytes
    ed_pk: bytes
    dsa_pk: bytes
    org_id: str


@dataclass(frozen=True, slots=True)
class BranchNode:
    """The keys of one named branch under an org root."""

    name: str
    b_read: bytes = field(repr=False)
    b_sign: bytes = field(repr=False)
    escrow_x_sk: bytes = field(repr=False)
    escrow_kem_seed: bytes = field(repr=False)
    reader_seed: bytes = field(repr=False)
    ed_seed: bytes = field(repr=False)
    dsa_xi: bytes = field(repr=False)
    escrow_x_pk: bytes
    escrow_kem_pk: bytes
    reader_pk: bytes
    ed_pk: bytes
    dsa_pk: bytes


@dataclass(frozen=True, slots=True)
class AgentNode:
    """The keys of one agent generation under a branch."""

    agent_id: str
    gen: int
    x_sk: bytes = field(repr=False)
    kem_seed: bytes = field(repr=False)
    ed_seed: bytes = field(repr=False)
    dsa_xi: bytes = field(repr=False)
    mls_seed: bytes = field(repr=False)
    x_pk: bytes
    kem_pk: bytes
    ed_pk: bytes
    dsa_pk: bytes
    mls_pk: bytes


def derive_org(root: bytes) -> OrgNode:
    """Derive the org node from a 32-byte root."""
    if len(root) != 32:
        raise CryptoError("root must be 32 bytes")
    r_read = derive(root, "rine.v1.root/read", 32)
    r_sign = derive(root, "rine.v1.root/sign", 32)
    reader_seed = derive(r_read, "rine.v1.reader/ed25519", 32)
    ed_seed = derive(r_sign, "rine.v1.org/ed25519", 32)
    dsa_xi = derive(r_sign, "rine.v1.org/ml-dsa-65", 32)
    ed_pk = ed25519_public_key(ed_seed)
    dsa_pk = _mldsa.public_key_from_seed(dsa_xi)
    return OrgNode(
        r_read=r_read,
        r_sign=r_sign,
        reader_seed=reader_seed,
        ed_seed=ed_seed,
        dsa_xi=dsa_xi,
        reader_pk=ed25519_public_key(reader_seed),
        ed_pk=ed_pk,
        dsa_pk=dsa_pk,
        org_id=org_id_from_keys(ed_pk, dsa_pk),
    )


def branch_reader_seed(b_read: bytes) -> bytes:
    """The branch reader's Ed25519 seed, from the branch's read subtree secret."""
    return derive(b_read, "rine.v1.branch/reader/ed25519", 32)


def branch_ed_seed(b_sign: bytes) -> bytes:
    """The branch's Ed25519 signing seed, from the branch's sign subtree secret."""
    return derive(b_sign, "rine.v1.branch/ed25519", 32)


def _escrow_seeds(b_read: bytes) -> tuple[bytes, bytes]:
    """The branch escrow X25519 secret and ML-KEM-768 seed, from ``b_read``."""
    return (
        derive(b_read, "rine.v1.branch/escrow/x25519", 32),
        derive(b_read, "rine.v1.branch/escrow/ml-kem-768", 64),
    )


def escrow_read_keys(b_read: bytes) -> tuple[bytes, bytes]:
    """The branch escrow X25519 and ML-KEM-768 private keys, from ``b_read`` alone."""
    x_sk, kem_seed = _escrow_seeds(b_read)
    return x_sk, _mlkem.key_pair_from_seed(kem_seed)[1]


def branch_from_secrets(name: str, b_read: bytes, b_sign: bytes) -> BranchNode:
    """Build a branch node from the two branch subtree secrets.

    Raises:
        CryptoError: The name is not canonical or a secret is not 32 bytes.
    """
    check_branch_name(name)
    if len(b_read) != 32 or len(b_sign) != 32:
        raise CryptoError("branch secrets must be 32 bytes")
    escrow_x_sk, escrow_kem_seed = _escrow_seeds(b_read)
    reader_seed = branch_reader_seed(b_read)
    ed_seed = branch_ed_seed(b_sign)
    dsa_xi = derive(b_sign, "rine.v1.branch/ml-dsa-65", 32)
    return BranchNode(
        name=name,
        b_read=b_read,
        b_sign=b_sign,
        escrow_x_sk=escrow_x_sk,
        escrow_kem_seed=escrow_kem_seed,
        reader_seed=reader_seed,
        ed_seed=ed_seed,
        dsa_xi=dsa_xi,
        escrow_x_pk=x25519_public_key(escrow_x_sk),
        escrow_kem_pk=_mlkem.key_pair_from_seed(escrow_kem_seed)[0],
        reader_pk=ed25519_public_key(reader_seed),
        ed_pk=ed25519_public_key(ed_seed),
        dsa_pk=_mldsa.public_key_from_seed(dsa_xi),
    )


def derive_branch(r_read: bytes, r_sign: bytes, name: str) -> BranchNode:
    """Derive a branch node from the two root subtree secrets."""
    check_branch_name(name)
    b_read = derive(r_read, f"rine.v1.branch/{name}/read", 32)
    b_sign = derive(r_sign, f"rine.v1.branch/{name}/sign", 32)
    return branch_from_secrets(name, b_read, b_sign)


def _agent_base(agent_id: str, gen: int) -> str:
    """The label base of one agent generation, after checking both inputs."""
    if isinstance(gen, bool) or not isinstance(gen, int) or gen < 0:
        raise CryptoError("invalid generation")
    return f"rine.v1.agent/{canonical_agent_label_id(agent_id)}/{gen}"


def _agent_seeds(b_read: bytes, base: str) -> tuple[bytes, bytes]:
    """The agent's X25519 secret and ML-KEM-768 seed, from ``b_read``."""
    return derive(b_read, f"{base}/x25519", 32), derive(b_read, f"{base}/ml-kem-768", 64)


def agent_read_keys(b_read: bytes, agent_id: str, gen: int) -> tuple[bytes, bytes]:
    """An agent's X25519 and ML-KEM-768 private keys at one generation.

    Raises:
        CryptoError: The agent id is not canonical or the generation is invalid.
    """
    x_sk, kem_seed = _agent_seeds(b_read, _agent_base(agent_id, gen))
    return x_sk, _mlkem.key_pair_from_seed(kem_seed)[1]


def derive_agent(b_read: bytes, b_sign: bytes, agent_id: str, gen: int) -> AgentNode:
    """Derive an agent node from the two branch subtree secrets."""
    base = _agent_base(agent_id, gen)
    x_sk, kem_seed = _agent_seeds(b_read, base)
    ed_seed = derive(b_sign, f"{base}/ed25519", 32)
    dsa_xi = derive(b_sign, f"{base}/ml-dsa-65", 32)
    mls_seed = derive(b_sign, f"{base}/mls-ed25519", 32)
    return AgentNode(
        agent_id=canonical_agent_label_id(agent_id),
        gen=gen,
        x_sk=x_sk,
        kem_seed=kem_seed,
        ed_seed=ed_seed,
        dsa_xi=dsa_xi,
        mls_seed=mls_seed,
        x_pk=x25519_public_key(x_sk),
        kem_pk=_mlkem.key_pair_from_seed(kem_seed)[0],
        ed_pk=ed25519_public_key(ed_seed),
        dsa_pk=_mldsa.public_key_from_seed(dsa_xi),
        mls_pk=ed25519_public_key(mls_seed),
    )
