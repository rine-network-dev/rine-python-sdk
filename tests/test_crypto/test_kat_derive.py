"""Known-answer tests for the org-root derivation tree."""

from __future__ import annotations

from dataclasses import fields
from typing import Any

import pytest

from rine._crypto import _mldsa, _mlkem
from rine._crypto.derive import (
    canonical_agent_label_id,
    check_branch_name,
    derive,
    org_id_from_keys,
)
from rine._crypto.derive_nodes import (
    AgentNode,
    BranchNode,
    OrgNode,
    derive_agent,
    derive_branch,
    derive_org,
)
from rine.errors import CryptoError
from tests.test_crypto.kat import load_kat


def _roots() -> list[dict[str, Any]]:
    """Return the fixture's ``roots.roots`` list."""
    return load_kat()["roots"]["roots"]


def _constants() -> dict[str, Any]:
    """Return the fixture's ``constants`` section."""
    return load_kat()["constants"]


class TestHkdf:
    """The labelled HKDF primitive matches the fixture."""

    def test_every_vector(self) -> None:
        """Each vector's OKM is reproduced byte for byte."""
        for entry in _constants()["hkdf"]:
            okm = derive(bytes.fromhex(entry["parent"]), entry["label"], entry["length"])
            assert okm.hex() == entry["okm"], entry["label"]


class TestBranchNames:
    """Branch names are accepted or refused exactly as the fixture says."""

    def test_accepted(self) -> None:
        """Every accepted name is returned unchanged."""
        for name in _constants()["branch_names"]["accepted"]:
            assert check_branch_name(name) == name

    def test_refused(self) -> None:
        """Every refused name raises ``CryptoError``."""
        for entry in _constants()["branch_names"]["refused"]:
            with pytest.raises(CryptoError):
                check_branch_name(entry["input"])


class TestCanonicalAgentIds:
    """Agent ids are accepted or refused exactly as the fixture says."""

    def test_accepted(self) -> None:
        """Every accepted id is returned unchanged."""
        for agent_id in _constants()["canonical_agent_id"]["accepted"]:
            assert canonical_agent_label_id(agent_id) == agent_id

    def test_refused(self) -> None:
        """Every refused id raises ``CryptoError``."""
        for entry in _constants()["canonical_agent_id"]["refused"]:
            with pytest.raises(CryptoError):
                canonical_agent_label_id(entry["input"])


def _check_org(node: OrgNode, expected: dict[str, Any]) -> None:
    """Assert an org node matches its fixture entry."""
    org = expected["org"]
    assert node.r_read.hex() == expected["r_read"]
    assert node.r_sign.hex() == expected["r_sign"]
    assert node.reader_seed.hex() == org["reader"]["seed"]
    assert node.reader_pk.hex() == org["reader"]["pk"]
    assert node.ed_seed.hex() == org["ed25519"]["seed"]
    assert node.ed_pk.hex() == org["ed25519"]["pk"]
    assert node.dsa_xi.hex() == org["ml_dsa_65"]["xi"]
    assert node.dsa_pk.hex() == org["ml_dsa_65"]["pk"]
    assert node.org_id == org["org_id"]
    assert node.org_id == org_id_from_keys(node.ed_pk, node.dsa_pk)


def _check_branch(node: BranchNode, expected: dict[str, Any]) -> None:
    """Assert a branch node matches its fixture entry."""
    assert node.name == expected["name"]
    assert node.b_read.hex() == expected["b_read"]
    assert node.b_sign.hex() == expected["b_sign"]
    assert node.escrow_x_sk.hex() == expected["escrow_x25519"]["sk"]
    assert node.escrow_x_pk.hex() == expected["escrow_x25519"]["pk"]
    assert node.escrow_kem_seed.hex() == expected["escrow_ml_kem_768"]["seed"]
    assert node.escrow_kem_pk.hex() == expected["escrow_ml_kem_768"]["pk"]
    assert node.reader_seed.hex() == expected["reader"]["seed"]
    assert node.reader_pk.hex() == expected["reader"]["pk"]
    assert node.ed_seed.hex() == expected["ed25519"]["seed"]
    assert node.ed_pk.hex() == expected["ed25519"]["pk"]
    assert node.dsa_xi.hex() == expected["ml_dsa_65"]["xi"]
    assert node.dsa_pk.hex() == expected["ml_dsa_65"]["pk"]


def _check_agent(node: AgentNode, agent_id: str, expected: dict[str, Any]) -> None:
    """Assert an agent node matches its fixture entry."""
    assert node.agent_id == agent_id
    assert node.gen == expected["gen"]
    assert node.x_sk.hex() == expected["x25519"]["sk"]
    assert node.x_pk.hex() == expected["x25519"]["pk"]
    assert node.kem_seed.hex() == expected["ml_kem_768"]["seed"]
    assert node.kem_pk.hex() == expected["ml_kem_768"]["pk"]
    assert node.ed_seed.hex() == expected["ed25519"]["seed"]
    assert node.ed_pk.hex() == expected["ed25519"]["pk"]
    assert node.dsa_xi.hex() == expected["ml_dsa_65"]["xi"]
    assert node.dsa_pk.hex() == expected["ml_dsa_65"]["pk"]
    assert node.mls_seed.hex() == expected["mls_ed25519"]["seed"]
    assert node.mls_pk.hex() == expected["mls_ed25519"]["pk"]


class TestRoots:
    """Every root replays the whole tree."""

    def test_every_root(self) -> None:
        """Each root, branch and agent generation matches the fixture."""
        for root in _roots():
            org = derive_org(bytes.fromhex(root["entropy"]))
            _check_org(org, root)
            branches = {
                name: derive_branch(org.r_read, org.r_sign, name) for name in root["branches"]
            }
            for name, expected in root["branches"].items():
                _check_branch(branches[name], expected)
            for agent in root["agents"]:
                branch = branches[agent["branch"]]
                for gen in agent["gens"]:
                    node = derive_agent(branch.b_read, branch.b_sign, agent["id"], gen["gen"])
                    _check_agent(node, agent["id"], gen)


class TestAcvp:
    """The post-quantum key generation matches the ACVP vectors."""

    def test_ml_kem_768(self) -> None:
        """Each ML-KEM seed yields the fixture's encapsulation key."""
        for case in load_kat()["acvp"]["ml_kem_768"]["cases"]:
            public_key, _ = _mlkem.key_pair_from_seed(bytes.fromhex(case["seed"]))
            assert public_key.hex() == case["ek"], case["tcId"]

    def test_ml_dsa_65(self) -> None:
        """Each ML-DSA seed yields the fixture's public key."""
        for case in load_kat()["acvp"]["ml_dsa_65"]["cases"]:
            public_key = _mldsa.public_key_from_seed(bytes.fromhex(case["seed"]))
            assert public_key.hex() == case["pk"], case["tcId"]


def _first_tree() -> tuple[dict[str, Any], OrgNode, BranchNode, AgentNode]:
    """Return the first root's fixture entry and its org, branch and agent nodes."""
    root = _roots()[0]
    org = derive_org(bytes.fromhex(root["entropy"]))
    branch = derive_branch(org.r_read, org.r_sign, next(iter(root["branches"])))
    agent = root["agents"][0]
    node = derive_agent(branch.b_read, branch.b_sign, agent["id"], agent["gens"][0]["gen"])
    return root, org, branch, node


class TestReprHidesSecrets:
    """A repr never prints key material."""

    def test_repr_has_no_secret_hex(self) -> None:
        """No secret hex string appears in any node repr."""
        root, org, branch, node = _first_tree()
        secrets = [
            root["r_read"],
            root["r_sign"],
            root["org"]["reader"]["seed"],
            root["org"]["ed25519"]["seed"],
            root["org"]["ml_dsa_65"]["xi"],
        ]
        for item in (org, branch, node):
            secrets.extend(getattr(item, f.name).hex() for f in fields(item) if not f.repr)
        for text in (repr(org), repr(branch), repr(node)):
            for secret in secrets:
                assert secret not in text


class TestAgentGeneration:
    """A generation must be a non-negative integer, not a bool."""

    def test_bad_generation_is_refused(self) -> None:
        """``gen=-1`` and ``gen=True`` both raise ``CryptoError``."""
        root, _, branch, _ = _first_tree()
        agent_id = root["agents"][0]["id"]
        for gen in (-1, True):
            with pytest.raises(CryptoError):
                derive_agent(branch.b_read, branch.b_sign, agent_id, gen)
