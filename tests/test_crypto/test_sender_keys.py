"""Tests for Sender Key encryption (group messages)."""

from __future__ import annotations

import pytest

from rine._crypto.envelope import decode_envelope
from rine._crypto.keys import make_kid
from rine._crypto.sender_keys import (
    VERSION_SENDER_KEY,
    derive_message_key,
    generate_sender_key,
    needs_rotation,
    open_group,
    seal_group,
)
from rine.errors import CryptoError, NoSenderKeyStateError
from rine.testing import WORLD

GROUP_ID = "00000000-0000-0000-0000-000000000001"
AGENT_ID = "00000000-0000-0000-0000-000000000002"


def _signing_key() -> bytes:
    """The derived Ed25519 signing key of the fixed agent."""
    return WORLD.keys(AGENT_ID).signing.private_key


def _kid() -> str:
    """The key id a group send by the fixed agent carries."""
    return make_kid(AGENT_ID, 0)


class TestDeriveMessageKey:
    def test_produces_32_byte_keys(self):
        chain_key = b"\x00" * 32
        mk, nck = derive_message_key(chain_key)
        assert len(mk) == 32
        assert len(nck) == 32

    def test_message_key_differs_from_next_chain_key(self):
        mk, nck = derive_message_key(b"\x01" * 32)
        assert mk != nck

    def test_deterministic(self):
        ck = b"\xab" * 32
        mk1, nck1 = derive_message_key(ck)
        mk2, nck2 = derive_message_key(ck)
        assert mk1 == mk2
        assert nck1 == nck2


class TestSealOpenGroup:
    def test_round_trip(self):
        sk = _signing_key()
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        original_index = state.message_index

        ct, updated = seal_group(sk, _kid(), state, b"hello group")
        assert updated.message_index == original_index + 1

        states = {state.sender_key_id: state}
        inner, skid, idx, new_state = open_group(states, ct)
        decoded = decode_envelope(inner)
        assert decoded.payload == b"hello group"
        assert idx == original_index

    def test_wire_format_version(self):
        sk = _signing_key()
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        ct, _ = seal_group(sk, _kid(), state, b"test")
        assert ct[0] == VERSION_SENDER_KEY

    def test_multiple_messages_advance_chain(self):
        sk = _signing_key()
        state = generate_sender_key(GROUP_ID, AGENT_ID)

        ct1, state = seal_group(sk, _kid(), state, b"msg1")
        ct2, state = seal_group(sk, _kid(), state, b"msg2")
        assert state.message_index == 2

    def test_out_of_order_decryption(self):
        """Decrypt messages received out of order."""
        sk = _signing_key()

        state_orig = generate_sender_key(GROUP_ID, AGENT_ID)
        ct_a, state_a = seal_group(sk, _kid(), state_orig, b"msg-a")
        ct_b, state_b = seal_group(sk, _kid(), state_a, b"msg-b")

        # Decrypt msg-b first (index 1, receiver at index 0)
        recv = generate_sender_key(GROUP_ID, AGENT_ID)
        recv.sender_key_id = state_orig.sender_key_id
        recv.chain_key = state_orig.chain_key
        recv.message_index = 0

        states_map = {recv.sender_key_id: recv}
        inner_b, _, idx_b, updated_b = open_group(states_map, ct_b)
        assert decode_envelope(inner_b).payload == b"msg-b"
        assert idx_b == 1

        # Now decrypt msg-a (index 0 - should be in skipped cache)
        states_map[updated_b.sender_key_id] = updated_b
        inner_a, _, idx_a, _ = open_group(states_map, ct_a)
        assert decode_envelope(inner_a).payload == b"msg-a"
        assert idx_a == 0

    def test_open_group_when_no_state_is_held_then_refuses_with_a_way_out(self):
        """The refusal names the cause and something the reader can do."""
        sk = _signing_key()
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        ct, _ = seal_group(sk, _kid(), state, b"test")

        with pytest.raises(NoSenderKeyStateError) as excinfo:
            open_group({}, ct)

        detail = str(excinfo.value)
        assert state.sender_key_id in detail
        assert "holds no sender key state" in detail
        assert "post to the group again" in detail
        assert "rejoin it" in detail
        # The old sentence's remedy — "fetch pending sender key distributions
        # first" — named a call every read path has already made before it can
        # reach this refusal.
        assert "Fetch pending" not in detail

    def test_open_group_when_no_state_is_held_then_stays_a_crypto_error(self):
        """The read paths retry a failed sender-key decrypt on ``CryptoError``.

        Narrowing this refusal out of that branch would delete the self-heal
        silently: the retry ingests pending distributions and tries once more,
        which is exactly the case this refusal describes.
        """
        assert issubclass(NoSenderKeyStateError, CryptoError)

    def test_payload_too_short_raises(self):
        with pytest.raises(CryptoError, match="too short"):
            open_group({}, b"\x02" + b"\x00" * 10)


class TestNeedsRotation:
    def test_fresh_key_does_not_need_rotation(self):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        assert not needs_rotation(state)

    def test_rotates_at_message_limit(self):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        state.message_index = 100
        assert needs_rotation(state)

    def test_rotates_on_age(self):
        import time

        state = generate_sender_key(GROUP_ID, AGENT_ID)
        state.created_at = int(time.time() * 1000) - (8 * 24 * 60 * 60 * 1000)
        assert needs_rotation(state)
