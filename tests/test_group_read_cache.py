"""A group message is readable more than once per reader.

Both regimes spend a one-time key at the first decrypt, so the second read of an
inbox entry used to answer "Message key expired or already consumed" — an error
about a key that is simply gone. These drive the real sender-key crypto through
the public decrypt functions and hold the difference to ONE variable: the cache
file. The control arm deletes it and asks again, which is what makes the replay
attributable to the cache rather than to anything else the read path does.

The in-process :class:`rine._crypto._decrypt_memo.DecryptMemo` answers the same
question for a long-lived client; this is what answers it for a fresh process,
which is what a CLI invocation and a restarted worker both are.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

from rine._crypto.group_read_cache import (
    GROUP_READ_MAX_ENTRIES,
    delete_group_read_cache,
    lookup_group_read,
    record_group_read,
)
from rine._crypto.keys import generate_agent_keys, save_agent_keys
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_group_message_sync,
    encrypt_group_message,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import save_sender_key_state
from rine.errors import CryptoError, SenderMismatchError
from tests.test_sender_binding import GROUP_ID, PAYLOAD, SENDER_B, VICTIM_V, KeyServer

IMPOSTOR = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def _group_message(config_dir: str) -> tuple[str, object]:
    """One sender-key group message from B, with B's key ingested by the victim."""
    sender_keys = generate_agent_keys()
    save_agent_keys(config_dir, SENDER_B, sender_keys)
    save_agent_keys(config_dir, VICTIM_V, generate_agent_keys())
    state = generate_sender_key(GROUP_ID, SENDER_B)
    save_sender_key_state(
        config_dir,
        VICTIM_V,
        GROUP_ID,
        [
            SenderKeyState(
                sender_key_id=state.sender_key_id,
                group_id=GROUP_ID,
                sender_agent_id=SENDER_B,
                chain_key=state.chain_key,
                message_index=state.message_index,
            )
        ],
    )
    # The sender's own copy, which ``encrypt_group_message`` advances in place. A
    # stand-in sender needs it as much as a real one does: the tail refuses a
    # state that is on no disk at all rather than discarding the advance.
    save_sender_key_state(config_dir, SENDER_B, GROUP_ID, [state])
    sealed, _ = encrypt_group_message(config_dir, SENDER_B, GROUP_ID, state, PAYLOAD)
    return sealed.encrypted_payload, sender_keys


def _cache_file(config_dir: str) -> str:
    return os.path.join(config_dir, "keys", VICTIM_V, "group_reads", f"{GROUP_ID}.json")


class TestReadingTwice:
    """The second read of a row whose one-time key has been spent."""

    def test_second_read_when_the_key_is_spent_then_returns_the_same_plaintext(
        self, tmp_config_dir
    ):
        """The ordinary thing an operator does with an inbox stops being an error."""
        payload, sender_keys = _group_message(tmp_config_dir)
        server = KeyServer(sender_keys)

        first = decrypt_group_message_sync(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )
        second = decrypt_group_message_sync(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )

        assert json.loads(first.plaintext) == PAYLOAD
        assert json.loads(second.plaintext) == PAYLOAD
        assert second.verification_status == "verified"

    def test_second_read_when_the_cache_is_removed_then_the_key_is_gone(self, tmp_config_dir):
        """The control arm: one variable changes and the old refusal comes back."""
        payload, sender_keys = _group_message(tmp_config_dir)
        server = KeyServer(sender_keys)
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        delete_group_read_cache(tmp_config_dir, VICTIM_V, GROUP_ID)

        with pytest.raises(CryptoError, match="expired or already consumed"):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
            )

    def test_replay_when_the_row_names_a_different_sender_then_refuses(self, tmp_config_dir):
        """A replay is verified against the sender the server names on THIS read."""
        payload, sender_keys = _group_message(tmp_config_dir)
        server = KeyServer(sender_keys)
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        with pytest.raises(SenderMismatchError):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, IMPOSTOR
            )

    async def test_async_second_read_when_the_key_is_spent_then_returns_the_plaintext(
        self, tmp_config_dir
    ):
        """The twin, because a fix on one client and not the other is not a fix."""
        from tests.test_sender_binding import AsyncKeyServer

        payload, sender_keys = _group_message(tmp_config_dir)
        server = AsyncKeyServer(sender_keys)

        await decrypt_group_message_async(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )
        second = await decrypt_group_message_async(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
        )

        assert json.loads(second.plaintext) == PAYLOAD

    def test_replay_when_the_group_is_retired_then_the_cache_stays_shut(self, tmp_config_dir):
        """The marker a leave writes has to be re-armable."""
        from rine._crypto.sender_keys_helpers import mark_sender_keys_retired

        payload, sender_keys = _group_message(tmp_config_dir)
        server = KeyServer(sender_keys)
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        mark_sender_keys_retired(tmp_config_dir, VICTIM_V, GROUP_ID)

        with pytest.raises(CryptoError, match="expired or already consumed"):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
            )

    def test_cache_file_when_written_then_is_owner_only(self, tmp_config_dir):
        """Plaintext at rest under the same 0600 posture as the rest of the dir."""
        payload, sender_keys = _group_message(tmp_config_dir)
        decrypt_group_message_sync(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, KeyServer(sender_keys), SENDER_B
        )

        mode = stat.S_IMODE(os.stat(_cache_file(tmp_config_dir)).st_mode)
        assert mode == 0o600


class TestBounds:
    """It is a re-read buffer, so it has to stay one."""

    def test_recording_when_past_the_entry_bound_then_drops_the_oldest(self, tmp_config_dir):
        """A re-read buffer, never an archive."""
        overflow = GROUP_READ_MAX_ENTRIES + 5
        for i in range(overflow):
            record_group_read(
                tmp_config_dir, VICTIM_V, GROUP_ID, i.to_bytes(4, "big"), b"envelope"
            )

        assert (
            lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, (0).to_bytes(4, "big")) is None
        )
        assert (
            lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, (4).to_bytes(4, "big")) is None
        )
        assert (
            lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, (5).to_bytes(4, "big"))
            == b"envelope"
        )

    def test_lookup_when_the_file_is_damaged_then_answers_nothing(self, tmp_config_dir):
        """It holds no authority, so a damaged buffer degrades into "decrypt it again"."""
        record_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc", b"envelope")
        with open(_cache_file(tmp_config_dir), "w") as fh:
            fh.write("{not json")

        assert lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc") is None


class TestTheLeaveTakesIt:
    """A leave wipes the plaintext with the keys."""

    def test_leave_when_it_retires_the_group_then_the_read_cache_goes_too(self, tmp_config_dir):
        """Or the sentence a leave prints — that the messages no longer open — is false."""
        from rine._mls.leave import retire_local_group_state

        save_agent_keys(tmp_config_dir, VICTIM_V, generate_agent_keys())
        record_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc", b"envelope")

        retire_local_group_state(tmp_config_dir, GROUP_ID, VICTIM_V, VICTIM_V)

        assert lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc") is None
