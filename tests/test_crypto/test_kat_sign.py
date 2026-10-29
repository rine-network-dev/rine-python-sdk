"""Replay of the message-signature vectors: the signing input, both scopes and the cross-domain refusals."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto.ed25519_strict import verify_ed25519_strict
from rine._crypto.jws import JwsError, JwsTyp, verify_jws
from rine._crypto.sign import (
    GroupSig,
    MessageSig,
    sign_message,
    signing_input,
    verify_message_signature,
)
from tests.test_crypto.kat import load_kat


def test_message_signature_replays_the_fixture() -> None:
    vector = load_kat()["signatures"]["message_signature"]
    scope = MessageSig(vector["recipient_agent_id"])
    payload = vector["payload_utf8"].encode()
    assert signing_input(scope, payload).hex() == vector["signing_input"]
    assert verify_message_signature(
        bytes.fromhex(vector["public_key"]), scope, payload, bytes.fromhex(vector["signature"])
    )


def test_group_message_signature_replays_the_fixture() -> None:
    vector = load_kat()["signatures"]["group_message_signature"]
    scope = GroupSig(vector["group_id"])
    payload = vector["payload_utf8"].encode()
    assert signing_input(scope, payload).hex() == vector["signing_input"]
    assert verify_message_signature(
        bytes.fromhex(vector["public_key"]), scope, payload, bytes.fromhex(vector["signature"])
    )


def test_message_signature_is_refused_for_another_scope() -> None:
    vector = load_kat()["signatures"]["message_signature"]
    key = bytes.fromhex(vector["public_key"])
    payload = vector["payload_utf8"].encode()
    signature = bytes.fromhex(vector["signature"])
    assert not verify_message_signature(
        key, MessageSig(vector["sender"]["agent_id"]), payload, signature
    )
    other_group = load_kat()["signatures"]["group_message_signature"]["group_id"]
    assert not verify_message_signature(key, GroupSig(other_group), payload, signature)


def test_cross_domain_signatures_are_refused() -> None:
    cross = load_kat()["signatures"]["cross_domain"]
    as_jws = cross["message_signature_as_jws"]
    with_pytest_raises = JwsError
    try:
        verify_jws(as_jws["compact_jws"], bytes.fromhex(as_jws["verifier_pk"]), JwsTyp.ASSERTION)
    except with_pytest_raises:
        pass
    else:
        raise AssertionError("a message signature must not verify as a JWS")
    as_message = cross["jws_as_message_signature"]
    assert not verify_message_signature(
        bytes.fromhex(as_message["public_key"]),
        MessageSig(as_message["recipient_agent_id"]),
        as_message["payload_utf8"].encode(),
        bytes.fromhex(as_message["signature"]),
    )


def test_cross_scope_signatures_are_refused_under_an_equal_id() -> None:
    cross = load_kat()["signatures"]["cross_scope"]
    scopes = {
        "message_signature_as_group": GroupSig,
        "group_signature_as_message": MessageSig,
    }
    for name, scope_type in scopes.items():
        vector = cross[name]
        assert not verify_message_signature(
            bytes.fromhex(vector["public_key"]),
            scope_type(vector["shared_id"]),
            vector["payload_utf8"].encode(),
            bytes.fromhex(vector["signature"]),
        ), name


def test_sign_message_round_trips_and_binds_scope() -> None:
    seed = Ed25519PrivateKey.generate().private_bytes_raw()
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    scope = MessageSig("8558188f-7713-44e4-824d-c2e060c9c5e1")
    signature = sign_message(seed, scope, b"hello")
    assert verify_message_signature(public, scope, b"hello", signature)
    assert not verify_message_signature(public, scope, b"hellO", signature)
    assert not verify_ed25519_strict(public, b"hello", signature)
