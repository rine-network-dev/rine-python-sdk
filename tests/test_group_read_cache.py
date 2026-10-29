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

import hashlib
import json
import os
import stat

import pytest

from rine._crypto.group_read_cache import (
    GROUP_READ_MAX_BYTES,
    GROUP_READ_MAX_ENTRIES,
    delete_group_read_cache,
    lookup_group_read,
    record_group_read,
)
from rine._crypto.keys import save_agent_keys
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_group_message_sync,
    encrypt_group_message,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import save_sender_key_state
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError, SenderMismatchError
from rine.testing import WORLD
from tests._twin import core_source, ts_number
from tests.test_crypto.world import AsyncKeyServer, KeyServer
from tests.test_sender_binding import GROUP_ID, PAYLOAD, SENDER_B, VICTIM_V

IMPOSTOR = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def _group_message(config_dir: str) -> str:
    """One sender-key group message from B, with B's key ingested by the victim."""
    save_agent_keys(config_dir, SENDER_B, WORLD.keys(SENDER_B))
    save_agent_keys(config_dir, VICTIM_V, WORLD.keys(VICTIM_V))
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
    return sealed.encrypted_payload


def _cache_file(config_dir: str) -> str:
    return os.path.join(config_dir, "keys", VICTIM_V, "group_reads", f"{GROUP_ID}.json")


class TestReadingTwice:
    """The second read of a row whose one-time key has been spent."""

    def test_second_read_when_the_key_is_spent_then_returns_the_same_plaintext(
        self, tmp_config_dir
    ):
        """The ordinary thing an operator does with an inbox stops being an error."""
        payload = _group_message(tmp_config_dir)
        server = KeyServer()

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
        payload = _group_message(tmp_config_dir)
        server = KeyServer()
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        delete_group_read_cache(tmp_config_dir, VICTIM_V, GROUP_ID)

        with pytest.raises(CryptoError, match="expired or already consumed"):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
            )

    def test_replay_when_the_row_names_a_different_sender_then_refuses(self, tmp_config_dir):
        """A replay is verified against the sender the server names on THIS read."""
        payload = _group_message(tmp_config_dir)
        server = KeyServer()
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        with pytest.raises(SenderMismatchError):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, IMPOSTOR
            )

    async def test_async_second_read_when_the_key_is_spent_then_returns_the_plaintext(
        self, tmp_config_dir
    ):
        """The twin, because a fix on one client and not the other is not a fix."""
        payload = _group_message(tmp_config_dir)
        server = AsyncKeyServer()

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

        payload = _group_message(tmp_config_dir)
        server = KeyServer()
        decrypt_group_message_sync(tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B)

        mark_sender_keys_retired(tmp_config_dir, VICTIM_V, GROUP_ID)

        with pytest.raises(CryptoError, match="expired or already consumed"):
            decrypt_group_message_sync(
                tmp_config_dir, VICTIM_V, GROUP_ID, payload, server, SENDER_B
            )

    def test_cache_file_when_written_then_is_owner_only(self, tmp_config_dir):
        """Plaintext at rest under the same 0600 posture as the rest of the dir."""
        payload = _group_message(tmp_config_dir)
        decrypt_group_message_sync(
            tmp_config_dir, VICTIM_V, GROUP_ID, payload, KeyServer(), SENDER_B
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


class TestTheCrossStackFile:
    """One config dir driven by both stacks is ONE cache file, so its shape is a contract.

    ``rine-core/src/crypto/group-read-cache.ts`` builds the same path out of the
    same components and reads the same two entry keys, and a CLI and an SDK
    pointed at one ``RINE_CONFIG_DIR`` are the ordinary case rather than an exotic
    one. So the path, the digest and the entry keys are not implementation
    details of this module: change one here alone and the other stack reads a
    file it cannot parse, which :func:`rine._crypto.group_read_cache._load`
    tolerates as an empty cache — and for a row whose one-time key is already
    spent, an empty cache is the sealed-message refusal rather than a slow path.
    """

    def test_recording_when_the_group_id_is_upper_cased_then_the_file_is_lower_cased(
        self, tmp_config_dir
    ):
        """``groupId.toLowerCase()`` on the other side, so one group is one file.

        🔴 The id has to carry hex LETTERS. Every other group id in this suite is
        digits only, so an upper-cased spelling of one is the same string and a
        test built on it passes with the lower-casing deleted.

        🔴 Only the FIRST segment is upper-cased, and that is not cosmetic. An
        all-upper spelling reads to ``scripts/check-internal-ids.py`` as a
        citation of an internal record — its ``family`` class matches up to six
        upper-case letters, a hyphen and a digit, which any upper-cased hex
        segment followed by a numeric one satisfies — so it turns the mandated
        pre-mirror gate red on this file. Upper-casing one eight-character
        segment still differs from its own ``.lower()``, which is all the
        assertion needs.
        """
        mixed_case = "AABBCCDD-eeff-4011-8022-334455667788"
        record_group_read(tmp_config_dir, VICTIM_V, mixed_case, b"abc", b"envelope")

        expected = os.path.join(
            tmp_config_dir, "keys", VICTIM_V, "group_reads", f"{mixed_case.lower()}.json"
        )
        assert os.listdir(os.path.join(tmp_config_dir, "keys", VICTIM_V, "group_reads")) == [
            os.path.basename(expected)
        ]
        # And it answers under either spelling, which is what makes the two
        # stacks' spellings interchangeable rather than merely similar.
        assert lookup_group_read(tmp_config_dir, VICTIM_V, mixed_case.lower(), b"abc") == (
            b"envelope"
        )

    def test_entry_when_recorded_then_it_is_the_shape_the_other_stack_reads(self, tmp_config_dir):
        """``{"k": base64url sha256 of the ciphertext, "e": base64url envelope}``."""
        record_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"ciphertext", b"envelope")

        with open(_cache_file(tmp_config_dir)) as fh:
            entries = json.load(fh)

        assert [sorted(entry) for entry in entries] == [["e", "k"]]
        assert entries[0]["k"] == to_base64url(hashlib.sha256(b"ciphertext").digest())
        assert from_base64url(entries[0]["e"]) == b"envelope"

    def test_the_other_stack_still_builds_the_same_file(self):
        """The assertions above are computed from Python's own literals alone.

        So they pin this stack against itself and say nothing about the twin —
        change ``rine-core``'s entry bound, its digest or its lower-casing and
        the two stacks write one file the other cannot parse, with a green suite
        on this side. Read the twin's own source for the four values, in the
        shape ``test_actor_contract.py``'s ``TestThePeekHeaderConstant`` uses for
        the actor and peek headers: the two deployables cannot import each other,
        so a test is the only thing that can bind them.
        """
        source = core_source("crypto/group-read-cache.ts")

        # The two bounds. Both are written as one product on both stacks, so the
        # factors are read rather than the expression evaluated — a plain integer
        # is accepted too, because either spelling is the same contract.
        assert ts_number(source, "GROUP_READ_MAX_ENTRIES") == GROUP_READ_MAX_ENTRIES
        assert ts_number(source, "GROUP_READ_MAX_BYTES") == GROUP_READ_MAX_BYTES
        # The path, the lower-casing and the digest, each as one literal: the
        # directory name, ``groupId.toLowerCase()`` in the filename, and sha256
        # over the framed ciphertext.
        assert '"group_reads"' in source
        assert "${groupId.toLowerCase()}.json" in source
        assert "toBase64Url(sha256(ciphertext))" in source
        # The entry keys, as the twin WRITES them — the ``CacheEntry`` interface
        # declares the same two names, but a declaration a writer has stopped
        # honouring is not the contract. A rename on one side is an unparseable
        # file on the other, which both modules degrade to an empty cache.
        assert "{ k: key, e: toBase64Url(innerEnvelope) }" in source


class TestTheLeaveTakesIt:
    """A leave wipes the plaintext with the keys."""

    def test_leave_when_it_retires_the_group_then_the_read_cache_goes_too(self, tmp_config_dir):
        """Or the sentence a leave prints — that the messages no longer open — is false."""
        from rine._mls.leave import retire_local_group_state

        save_agent_keys(tmp_config_dir, VICTIM_V, WORLD.keys(VICTIM_V))
        record_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc", b"envelope")

        retire_local_group_state(tmp_config_dir, GROUP_ID, VICTIM_V, VICTIM_V)

        assert lookup_group_read(tmp_config_dir, VICTIM_V, GROUP_ID, b"abc") is None
