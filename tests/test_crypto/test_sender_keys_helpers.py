"""Tests for sender key state persistence (load/save)."""

from __future__ import annotations

import json
import os

import pytest

from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import (
    load_sender_key_states,
    save_sender_key_state,
)
from rine._utils import to_base64url

GROUP_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
AGENT_ID = "11111111-2222-3333-4444-555555555555"


class TestSenderKeyPersistence:
    def test_save_and_load_round_trip(self, tmp_config_dir):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [state])

        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert len(loaded) == 1
        assert loaded[0].sender_key_id == state.sender_key_id
        assert loaded[0].group_id == state.group_id
        assert loaded[0].sender_agent_id == state.sender_agent_id
        assert loaded[0].chain_key == state.chain_key
        assert loaded[0].message_index == state.message_index

    def test_skipped_keys_preserved(self, tmp_config_dir):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        state.skipped_keys = {0: to_base64url(b"\x01" * 32), 5: to_base64url(b"\x02" * 32)}
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [state])

        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert loaded[0].skipped_keys[0] == state.skipped_keys[0]
        assert loaded[0].skipped_keys[5] == state.skipped_keys[5]

    def test_skipped_keys_int_conversion(self, tmp_config_dir):
        """JSON keys are strings but should be loaded as int keys."""
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        state.skipped_keys = {42: to_base64url(b"\xaa" * 32)}
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [state])

        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert 42 in loaded[0].skipped_keys

    def test_multiple_states(self, tmp_config_dir):
        s1 = generate_sender_key(GROUP_ID, AGENT_ID)
        s2 = generate_sender_key(GROUP_ID, "22222222-3333-4444-5555-666666666666")
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [s1, s2])

        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert len(loaded) == 2

    def test_load_missing_file_returns_empty(self, tmp_config_dir):
        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert loaded == []

    def test_file_permissions(self, tmp_config_dir):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [state])

        path = os.path.join(
            tmp_config_dir, "keys", AGENT_ID, "sender_keys", f"{GROUP_ID}.json"
        )
        stat = os.stat(path)
        assert stat.st_mode & 0o777 == 0o600

    def test_distributed_to_preserved(self, tmp_config_dir):
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        state.distributed_to = ["agent-1", "agent-2"]
        save_sender_key_state(tmp_config_dir, AGENT_ID, GROUP_ID, [state])

        loaded = load_sender_key_states(tmp_config_dir, AGENT_ID, GROUP_ID)
        assert loaded[0].distributed_to == ["agent-1", "agent-2"]

    def test_invalid_agent_id_raises(self, tmp_config_dir):
        from rine.errors import CryptoError
        state = generate_sender_key(GROUP_ID, AGENT_ID)
        with pytest.raises(CryptoError):
            save_sender_key_state(tmp_config_dir, "bad-id", GROUP_ID, [state])
