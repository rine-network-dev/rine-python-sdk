"""SDK-side org-root contract: replay the server goldens through the SDK's readers.

Where the SDK has a model, the golden must parse into it; where it reads a raw dict (token
exchange, branches, escrow, the chain fields), the golden must carry every key the reader indexes.
Goldens hold sentinel ids, so the certificate chain itself is verified by the SDK's own suites
against real keys, not here.
"""

from __future__ import annotations

from rine._whoami import parse_whoami
from rine.types import AgentKeysResponse, AgentRead, WhoAmIKind

from ._loader import load

KEYS_VIEW_FIELDS = {
    "agent_id", "signing_public_key", "encryption_public_key", "pq_encryption_public_key",
    "pq_signing_public_key", "mls_signing_public_key", "org_id", "org_signing_public_key",
    "org_pq_signing_public_key", "branch", "branch_certificate", "key_gen", "agent_certificate",
}  # fmt: skip
ESCROW_KEY_FIELDS = {
    "org_id", "org_signing_public_key", "org_pq_signing_public_key", "branch",
    "branch_certificate", "escrow_public_key", "escrow_pq_public_key",
}  # fmt: skip
BRANCH_VIEW_FIELDS = {
    "name", "signing_public_key", "pq_signing_public_key", "escrow_public_key",
    "escrow_pq_public_key", "reader_public_key", "certificate", "created_at", "revoked_at",
}  # fmt: skip


def test_token_exchange_carries_what_the_cache_stores():
    body = load("token_exchange_200")["body"]
    assert isinstance(body["access_token"], str) and body["token_type"].lower() == "bearer"
    assert isinstance(body["expires_in"], int)


def test_agent_create_parses_as_agent_read():
    agent = AgentRead.model_validate(load("agents_create_201")["body"])
    assert agent.id is not None and agent.handle and agent.poll_url


def test_rotate_answers_with_the_agent_and_its_new_signing_key():
    rotated = load("agents_rotate_200")["body"]
    assert AgentRead.model_validate(rotated).id is not None
    assert rotated["signing_public_key"] != load("agents_create_201")["body"]["signing_public_key"]


def test_key_fetches_carry_the_chain_fields():
    for name in ("agents_keys_200", "agents_keys_200_rotated"):
        body = load(name)["body"]
        assert body.keys() >= KEYS_VIEW_FIELDS, name
        assert AgentKeysResponse.model_validate(body).agent_id is not None
    assert load("agents_keys_200")["body"]["key_gen"] == 0
    assert load("agents_keys_200_rotated")["body"]["key_gen"] == 1


def test_a_superseded_generation_carries_superseded_at():
    body = load("agents_keys_200_superseded")["body"]
    assert body.keys() >= KEYS_VIEW_FIELDS
    assert body["key_gen"] == 0 and body["superseded_at"]
    assert "superseded_at" not in load("agents_keys_200_rotated")["body"]


def test_branches_carry_the_fields_recovery_and_escrow_read():
    created = load("branches_create_201")["body"]
    assert created.keys() >= BRANCH_VIEW_FIELDS
    names = [view["name"] for view in load("branches_list_200")["body"]["branches"]]
    assert sorted(names) == ["fleet", "main"]
    assert load("branches_escrow_key_200")["body"].keys() >= ESCROW_KEY_FIELDS


def test_escrow_receipt_and_listing_row():
    receipt = load("escrow_upload_201")["body"]
    assert set(receipt) == {"epoch", "fp"}
    page = load("escrow_list_200")["body"]
    row = page["rows"][0]
    assert {
        "epoch",
        "fp",
        "branch",
        "uploader_agent_id",
        "uploader_key_gen",
        "uploader_sig",
        "sealed",
        "created_at",
    } <= row.keys()
    assert (row["epoch"], row["fp"]) == (receipt["epoch"], receipt["fp"])
    assert page["next_cursor"] is None


def test_whoami_is_consumed_by_the_sdk_for_every_principal():
    for name, kind in (
        ("whoami_200_org", WhoAmIKind.ORG),
        ("whoami_200_branch", WhoAmIKind.BRANCH),
        ("whoami_200_agent", WhoAmIKind.AGENT),
    ):
        body = load(name)["body"]
        who = parse_whoami(body)
        assert who.principal.kind is kind
        assert who.trust_tier == body["org"]["trust_tier"]
        assert who.org.id is not None and len(who.agents) == 1


def test_whoami_is_consumed_by_the_sdk_for_both_reader_principals():
    for name, kind in (
        ("whoami_200_org_reader", WhoAmIKind.ORG_READER),
        ("whoami_200_branch_reader", WhoAmIKind.BRANCH_READER),
    ):
        body = load(name)["body"]
        who = parse_whoami(body)
        assert who.principal.kind is kind
        assert who.trust_tier == body["org"]["trust_tier"]
        assert who.org.id is not None


def test_whoami_kind_names_every_principal_kind_the_server_has():
    assert {kind.value for kind in WhoAmIKind} == set(load("whoami_kinds")["body"]["kinds"])
