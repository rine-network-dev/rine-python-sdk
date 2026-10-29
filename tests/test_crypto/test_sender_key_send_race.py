"""The SEND half of one group's sender-key state file, under concurrent writers.

``test_sender_key_state_race.py`` covers the read half — a render opening many
rows against one file. This is its twin on the way out.
:func:`rine._sender_key_ops.get_or_create_sender_key_sync` distributes the
sender key as one 1:1 DM **per member**, so the state file can move under a
single send many times over: a peer's key arriving from the distribution ingest,
another sender's ratchet a concurrent decrypt advanced, a rotation another
holder ran. Both of that function's writes used to assert the array it read
BEFORE the fan-out, which discards every one of those.

It is a lost update, not a torn write, so the atomic save does nothing for it,
and the loss is silent: the reader is simply told the group is sealed under a key
no later message reopens, and the render after that opens it.

🔴 These drive the public function, not the fix. Only the network is a stand-in —
the seal, the ratchet and the state file are the real thing — so a rewrite that
keeps ``get_or_create_sender_key_sync``'s signature and gets the answers right
passes.

Exclusion is asserted too, and separately: the re-read is only half of it, since
nothing in a re-read stops another writer committing between it and the save.
``TestTwoRotationsAtOnce`` interleaves two threads inside that window, and
``TestTheThreadTier`` pins the primitive both tiers of the lock meet on — a
worker thread and a coroutine over one file exclude each other, over two files
they do not. Read :mod:`rine._crypto.sender_keys_thread_lock` for why a second
tier exists at all.

🔴 ``get_or_create_sender_key_sync`` is not the end of a send.
``rine._group_send.encrypt_for_group_sync`` calls
:func:`rine._crypto.message.encrypt_group_message` on the very next line, and
that tail re-asserts this agent's own row. A suite that stops one call short
cannot tell a working ``_record_distribution`` from one whose result is thrown
away — ``TestTheSendTail`` below is what closes that boundary, and it pins a
RESIDUAL as well as a guarantee. Read its docstrings before treating either as a
promise.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import json
import re
import threading
from typing import Any

import pytest

from rine import _sender_key_ops
from rine._crypto import message, sender_keys_store, sender_keys_thread_lock
from rine._crypto.keys import save_agent_keys
from rine._crypto.message import decrypt_group_message_sync, encrypt_group_message
from rine._crypto.sender_keys import (
    ROTATION_MESSAGE_LIMIT,
    SenderKeyState,
    generate_sender_key,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._crypto.sender_keys_store import with_sender_key_states, with_sender_key_states_sync
from rine._sender_key_ops import (
    delete_sender_key,
    get_or_create_sender_key_sync,
    sender_key_state_exists,
)
from rine.errors import UnpersistedSenderKeyStateError
from rine.testing import WORLD
from tests.conftest import sender_key_region_is_held_here
from tests.test_crypto.world import KeyServer

SENDER_ID = "00000000-1111-2222-3333-444444444444"
#: Already holds this agent's key.
MEMBER_A_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
#: Seated since the last send, so the fan-out is for this one.
MEMBER_B_ID = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
#: A second member that already holds the key, so the recorded order has a shape.
MEMBER_C_ID = "cccccccc-1111-4111-8111-cccccccccccc"
#: Sends to the group but is never a recipient here — its key is what the ingest
#: installs, and what an array read from before the fan-out throws away.
PEER_ID = "99999999-8888-4888-8888-999999999999"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
GROUP_HANDLE = "#ops@myorg.rine.network"
#: A resolved group on Sender Keys, as ``rine._group_send`` hands it over.
_GROUP = {"id": GROUP_ID, "handle": GROUP_HANDLE, "mls_group_id": None, "mls_pending": False}

_KEYS_PATH = re.compile(r"^/agents/([^/]+)/keys$")


class FanOutServer(KeyServer):
    """The roster read, key reads and distribution posts one send makes.

    ``on_post`` runs INSIDE the fan-out — the recipient's keys have been fetched
    and the DM sealed, and the caller has not yet recorded the delivery — which is
    the window every test here writes into. One hook is enough because each of
    these sends fans out to exactly one recipient; a second post would fire it
    again, which no test wants.

    Key reads are answered from :data:`rine.testing.WORLD`, so every
    agent's published keys are the derived ones it holds on disk and a self-read
    decrypt verifies this agent's signature against them.
    """

    def __init__(self, roster: list[str], on_post: Any = None) -> None:
        """Serve one group's roster and every agent's chain-valid published keys."""
        super().__init__()
        self.roster = roster
        self.posts: list[dict[str, Any]] = []
        self._on_post = on_post

    def get(self, path: str, **kwargs: Any) -> Any:
        """Answer the roster read and each agent's published keys."""
        if path == f"/groups/{GROUP_ID}/members":
            return {"items": [{"agent_id": a, "role": "member"} for a in self.roster]}
        if _KEYS_PATH.match(path) is None:
            raise AssertionError(f"unexpected GET {path}")
        return super().get(path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> dict[str, str]:
        """Accept one distribution DM, running the concurrent writer first."""
        assert path == "/messages"
        self.posts.append(kwargs["json_body"])
        if self._on_post is not None:
            self._on_post()
        return {"id": "dddddddd-eeee-ffff-0000-111111111111"}


def _seat_sender(config_dir: str) -> None:
    """The sending agent's own keys on disk, which every seal loads."""
    save_agent_keys(config_dir, SENDER_ID, WORLD.keys(SENDER_ID))


def _own_key(config_dir: str, distributed_to: list[str], message_index: int = 0) -> SenderKeyState:
    """This agent's current sender key, alone in the file.

    ``message_index`` is the rotation lever:
    :func:`rine._crypto.sender_keys.needs_rotation` fires at
    ``ROTATION_MESSAGE_LIMIT``, so a test picks its branch by handing that in
    rather than by arranging a departed member — which would take the member-change
    branch on the way and fan out twice.
    """
    own = generate_sender_key(GROUP_ID, SENDER_ID)
    own.distributed_to = distributed_to
    own.message_index = message_index
    save_sender_key_state(config_dir, SENDER_ID, GROUP_ID, [own])
    return own


def _peer_key(config_dir: str) -> SenderKeyState:
    """A peer's key as the reader receives it, appended to what is already there.

    The write is the distribution ingest's own shape
    (``rine._sync_client._fetch_pending_sk_distributions``): load the whole array,
    append, save — with no lock of its own.
    """
    arriving = generate_sender_key(GROUP_ID, PEER_ID)
    states = load_sender_key_states(config_dir, SENDER_ID, GROUP_ID)
    states.append(arriving)
    save_sender_key_state(config_dir, SENDER_ID, GROUP_ID, states)
    return arriving


def _advance_on_disk(config_dir: str, sender_key_id: str, to_index: int) -> None:
    """Move one row's ratchet forward, as a decrypt of that sender's post does."""
    states = load_sender_key_states(config_dir, SENDER_ID, GROUP_ID)
    for state in states:
        if state.sender_key_id == sender_key_id:
            state.message_index = to_index
    save_sender_key_state(config_dir, SENDER_ID, GROUP_ID, states)


def _rows(config_dir: str) -> dict[str, SenderKeyState]:
    """The state file as it stands, keyed by sender key id."""
    return {s.sender_key_id: s for s in load_sender_key_states(config_dir, SENDER_ID, GROUP_ID)}


def _own_ids(config_dir: str) -> list[str]:
    """This agent's own rows in FILE order, which is the order the send path reads."""
    return [
        s.sender_key_id
        for s in load_sender_key_states(config_dir, SENDER_ID, GROUP_ID)
        if s.sender_agent_id == SENDER_ID
    ]


def _order_no_set_reproduces(members: list[str], arriving: str) -> list[str]:
    """An already-distributed order that ``set()`` cannot reproduce this run.

    The union is ``dict.fromkeys([*live.distributed_to, *succeeded])`` and the
    regression it guards is a ``set()`` there. Set iteration order for a given set
    of strings is fixed within a process but keyed off the interpreter's
    per-process hash seed, so a fixed two-element expectation catches that
    mutation on roughly half of the seeds — a coin toss, not a gate. Asking the
    interpreter which orders it reproduces and handing back one it does not makes
    the expectation fail under ``set()`` instead.

    🔴 "At most one permutation equals its set's iteration order" is FALSE, and
    assuming it made this helper raise on about one interpreter start in 57. Each
    candidate builds its OWN set, and CPython's open addressing probes on collision,
    so iteration order depends on insertion order as well as on the hash seed — every
    candidate can therefore reproduce itself. That is a seed this run cannot
    discriminate on rather than a broken product, so it skips by name instead of
    failing: measured at 7 of 400 seeds by direct enumeration.
    """
    for candidate in itertools.permutations(members):
        ordered = [*candidate, arriving]
        if list(set(ordered)) != ordered:
            return list(candidate)
    pytest.skip(
        "this interpreter's hash seed reproduces every candidate order, so no "
        "expectation here can tell dict.fromkeys from set()"
    )


class TestDistributingToANewMember:
    """The write that records which members this agent's current key reached."""

    def test_peer_key_when_ingested_during_the_fan_out_then_it_survives(self, tmp_config_dir):
        """A key this send has no opinion about must not be written away by it."""
        _seat_sender(tmp_config_dir)
        prior = _order_no_set_reproduces([MEMBER_A_ID, MEMBER_C_ID], MEMBER_B_ID)
        own = _own_key(tmp_config_dir, distributed_to=list(prior))
        arriving: list[SenderKeyState] = []
        server = FanOutServer(
            [SENDER_ID, *prior, MEMBER_B_ID],
            lambda: arriving.append(_peer_key(tmp_config_dir)),
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        # The branch under test: the existing key is kept and handed to the one
        # member that did not have it.
        assert state.sender_key_id == own.sender_key_id
        assert [p["to_agent_id"] for p in server.posts] == [MEMBER_B_ID]

        rows = _rows(tmp_config_dir)
        # Losing this is what makes the next read of that peer's post report the
        # group sealed under a key no later message reopens.
        assert arriving[0].sender_key_id in rows
        # And the delivery was still recorded, so the next send does not re-send it
        # — in the FILE's order, which is what keeps ``distributed_to`` stable on
        # the wire rather than reshuffling it on every write.
        assert rows[own.sender_key_id].distributed_to == [*prior, MEMBER_B_ID]

    def test_delivery_when_a_peer_row_shares_this_key_id_then_it_is_recorded_on_the_own_row(
        self, tmp_config_dir
    ):
        """The fan-out is recorded against this agent's row, not whoever shares its id.

        🔴 A sender key id names a row only together with its sender. Searching the
        file by id alone answers with whichever such row comes first, and after the
        per-sender ingest check that can be a PEER's — so the delivery is written onto
        the peer's key while this agent's own row stays unrecorded, and the next send
        fans the same key out all over again. Planted FIRST on purpose: a squatter
        that lands after the own row is found by neither search, and would let an
        id-only lookup pass.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        squat = SenderKeyState(
            sender_key_id=own.sender_key_id,
            group_id=GROUP_ID,
            sender_agent_id=PEER_ID,
            chain_key=generate_sender_key(GROUP_ID, PEER_ID).chain_key,
            message_index=0,
        )
        save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [squat, own])
        server = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        assert state.sender_key_id == own.sender_key_id
        assert [p["to_agent_id"] for p in server.posts] == [MEMBER_B_ID]
        rows = load_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID)
        recorded = {s.sender_agent_id: list(s.distributed_to) for s in rows}
        assert recorded == {
            PEER_ID: [],
            SENDER_ID: [MEMBER_A_ID, MEMBER_B_ID],
        }
        # And the peer's chain key is what it was: the record is a metadata union,
        # never an excuse to write this agent's material over someone else's row.
        assert next(s for s in rows if s.sender_agent_id == PEER_ID).chain_key == squat.chain_key

    def test_peer_ratchet_when_advanced_during_the_fan_out_then_it_is_not_rolled_back(
        self, tmp_config_dir
    ):
        """The union is over ``distributed_to``; it may not carry chain material back.

        Writing this call's own pre-fan-out copy of a row would undo whatever a
        concurrent decrypt spent on it — and the reader then legitimately refuses
        every post that decrypt already consumed.
        """
        _seat_sender(tmp_config_dir)
        _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        peer = _peer_key(tmp_config_dir)
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID],
            lambda: _advance_on_disk(tmp_config_dir, peer.sender_key_id, 5),
        )

        get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        assert _rows(tmp_config_dir)[peer.sender_key_id].message_index == 5

    def test_own_key_when_rotated_away_during_the_fan_out_then_nothing_is_recorded(
        self, tmp_config_dir
    ):
        """A key that no longer exists has nothing left to record against.

        🔴 Re-adding it would resurrect a state the rotation retired on purpose —
        and put its chain key back on disk under a group that has moved on. The
        row is looked up by id and a miss returns. The sibling case, a ``group
        leave`` unlinking the file, is covered by the next test rather than by
        this one: the two differ in WHERE they land, and only the later window
        distinguishes the merge from a whole-array save.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        replacement = generate_sender_key(GROUP_ID, SENDER_ID)
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID],
            lambda: save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [replacement]),
        )

        get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        rows = _rows(tmp_config_dir)
        assert list(rows) == [replacement.sender_key_id]
        assert own.sender_key_id not in rows
        assert rows[replacement.sender_key_id].distributed_to == []

    def test_group_when_left_inside_the_recording_window_then_nothing_comes_back(
        self, tmp_config_dir, monkeypatch
    ):
        """A leave that completes while the delivery is being recorded is not undone.

        🔴 This is what makes the recording write a MERGE rather than a whole-array
        save of the array it just read, and nothing else in the tree pins that
        choice. ``_record_distribution`` loads the file to find its row, and
        :func:`rine._crypto.sender_keys_store.merge_sender_key_states` loads it
        again to merge; a ``group leave`` completing between those two loads meets
        a caller that has already decided it has something to write. The merge
        refuses — retired group, no file — where a save would re-create the file
        with this agent's live chain key in it, under a group it has left.

        The concurrent writer is injected at ``rine._sender_key_ops``'s own
        ``load_sender_key_states``, which is a different module-level name from the
        one the store resolves, so this hook opens the window without standing in
        for anything the merge does. It fires on the first load AFTER the fan-out
        has posted, which is the recording load in this branch. Under a
        whole-array save the same hook fires at the same moment — the two differ in
        the answer, not in the seam.
        """
        _seat_sender(tmp_config_dir)
        _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        server = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        left: list[bool] = []

        def load_then_leave(*args: Any, **kwargs: Any) -> list[SenderKeyState]:
            states = load_sender_key_states(*args, **kwargs)
            if server.posts and not left:
                left.append(True)
                delete_sender_key(tmp_config_dir, SENDER_ID, GROUP_ID)
            return states

        monkeypatch.setattr("rine._sender_key_ops.load_sender_key_states", load_then_leave)

        get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        # The hook has to have fired, or this asserts nothing at all.
        assert left == [True]
        assert sender_key_state_exists(tmp_config_dir, SENDER_ID, GROUP_ID) is False


class TestRotating:
    """The write that replaces this agent's key, which genuinely drops rows."""

    def test_peer_key_when_ingested_during_the_fan_out_then_it_survives(self, tmp_config_dir):
        """The rotation drops older own rows and nothing of anyone else's."""
        _seat_sender(tmp_config_dir)
        own = _own_key(
            tmp_config_dir, distributed_to=[MEMBER_A_ID], message_index=ROTATION_MESSAGE_LIMIT
        )
        arriving: list[SenderKeyState] = []
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID],
            lambda: arriving.append(_peer_key(tmp_config_dir)),
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        assert state.sender_key_id != own.sender_key_id
        assert [p["to_agent_id"] for p in server.posts] == [MEMBER_A_ID]

        rows = _rows(tmp_config_dir)
        assert arriving[0].sender_key_id in rows
        # The key this rotation supersedes is retained, BELOW the new one, and the
        # predicate that decides which own row that is comes from the fresh read.
        assert _own_ids(tmp_config_dir) == [own.sender_key_id, state.sender_key_id]
        assert rows[state.sender_key_id].distributed_to == [MEMBER_A_ID]

    def test_peer_ratchet_when_advanced_during_the_fan_out_then_it_is_not_rolled_back(
        self, tmp_config_dir
    ):
        """A rotation replaces one row; every other row is whatever the file says."""
        _seat_sender(tmp_config_dir)
        _own_key(
            tmp_config_dir, distributed_to=[MEMBER_A_ID], message_index=ROTATION_MESSAGE_LIMIT
        )
        peer = _peer_key(tmp_config_dir)
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID],
            lambda: _advance_on_disk(tmp_config_dir, peer.sender_key_id, 5),
        )

        get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        assert _rows(tmp_config_dir)[peer.sender_key_id].message_index == 5


class TestRotationAndSelfRead:
    """What an agent can still read of its OWN posts once its key rotates.

    The rotation retains exactly one superseded own row. Dropping it costs the
    agent every own post it had not already opened — a sender never distributes
    its key to itself, so no distribution DM exists for the recovery path to
    re-ingest and the refusal it gets offers two explanations that are both false
    of its own post. Keeping it is what the TypeScript stack does; keeping only
    one is what bounds the file.
    """

    def _post_then_rotate(
        self, config_dir: str
    ) -> tuple[FanOutServer, str, SenderKeyState, SenderKeyState]:
        """Send one group post, then lose a member, which is a rotation trigger.

        Returns the server standing after the rotation, the sealed payload of the
        post, the key it was sent under, and the key the rotation minted.
        """
        _seat_sender(config_dir)
        _own_key(config_dir, distributed_to=[MEMBER_A_ID, MEMBER_B_ID])
        seated = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        state = get_or_create_sender_key_sync(seated, config_dir, SENDER_ID, _GROUP)
        result, _ = encrypt_group_message(
            config_dir, SENDER_ID, GROUP_ID, state, {"body": "my own post"}
        )

        # MEMBER_B is gone from the roster, which is a rotation trigger.
        after = FanOutServer([SENDER_ID, MEMBER_A_ID])
        rotated = get_or_create_sender_key_sync(after, config_dir, SENDER_ID, _GROUP)
        assert rotated.sender_key_id != state.sender_key_id
        return after, result.encrypted_payload, state, rotated

    def test_own_post_when_the_key_rotates_then_it_still_opens(self, tmp_config_dir):
        """The user-visible half: the agent's own earlier post still renders.

        Asserted through the public group decrypt, not by reading the state file,
        because what regressed is the READ: ``NoSenderKeyStateError`` carrying
        ``sender_key_unavailable``, permanently, for a post this agent wrote
        itself.
        """
        after, sealed, _state, _rotated = self._post_then_rotate(tmp_config_dir)

        opened = decrypt_group_message_sync(
            tmp_config_dir, SENDER_ID, GROUP_ID, sealed, after, SENDER_ID
        )

        assert json.loads(opened.plaintext) == {"body": "my own post"}

    def test_own_states_when_rotating_twice_then_only_the_last_is_retained(self, tmp_config_dir):
        """Retention is ONE row, and it is the row this agent was just sending under.

        The bound is what stops the file growing per rotation, and "the row just
        used" is what the predicate has to name — deriving it from the id the call
        carried in from before its fan-out retains the WRONG row, which reads as a
        working retention and loses the self-read anyway.
        """
        _after, _sealed, first, second = self._post_then_rotate(tmp_config_dir)
        assert _own_ids(tmp_config_dir) == [first.sender_key_id, second.sender_key_id]

        # Every remaining member leaves too, so the removal check fires again.
        empty = FanOutServer([SENDER_ID])
        third = get_or_create_sender_key_sync(empty, tmp_config_dir, SENDER_ID, _GROUP)

        assert _own_ids(tmp_config_dir) == [second.sender_key_id, third.sender_key_id]
        assert first.sender_key_id not in _rows(tmp_config_dir)

    def test_key_when_a_removal_rotation_has_happened_then_the_next_send_does_not_rekey(
        self, tmp_config_dir
    ):
        """🔴 The retained row is readable, never selectable.

        The send path takes the LAST own row. Taking the first would select the
        state this rotation superseded — whose ``distributed_to`` still names the
        departed member — so the removal check would fire on every later send and
        turn one departure into a rekey per message, a full DM fan-out each time.
        That is the defect the retention would otherwise reintroduce, so the two
        belong in one commit.
        """
        _after, _sealed, _first, second = self._post_then_rotate(tmp_config_dir)

        unchanged = FanOutServer([SENDER_ID, MEMBER_A_ID])
        again = get_or_create_sender_key_sync(unchanged, tmp_config_dir, SENDER_ID, _GROUP)

        assert again.sender_key_id == second.sender_key_id
        assert unchanged.posts == []


class TestTheSendTail:
    """What ``encrypt_group_message`` does to the file one call later.

    ``get_or_create_sender_key_sync`` returns the PRE-fan-out ``own_state`` and
    the send hands that object straight on, so the tail re-asserts this agent's
    own row from it. Everything above stops before that; these three do not.
    """

    def test_distribution_when_recorded_then_the_send_tail_keeps_it(self, tmp_config_dir):
        """The recorded delivery survives the send — because of the in-memory half.

        🔴 ``get_or_create_sender_key_sync`` both extends ``own_state.distributed_to``
        in memory and merges the same union to disk, and the pair is not redundant:
        the tail writes the in-memory object back, so deleting the extend as dead
        code silently reverts ``distributed_to`` and the next send re-distributes
        to a member that already holds the key. This is the gate for that line.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        server = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        assert _rows(tmp_config_dir)[own.sender_key_id].distributed_to == [
            MEMBER_A_ID,
            MEMBER_B_ID,
        ]

    def test_peer_row_when_it_shares_this_agents_key_id_then_the_tail_leaves_it_alone(
        self, tmp_config_dir
    ):
        """The tail advances this agent's row, not every row wearing its id.

        🔴 Matching on the key id alone made the write a whole-array ``map`` that
        replaced EVERY row carrying that id with this agent's own state — so an
        ordinary send overwrote a peer's chain key with the sender's, and the peer's
        posts stopped opening for good. Planted first, so an id-only match finds it.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        squat = SenderKeyState(
            sender_key_id=own.sender_key_id,
            group_id=GROUP_ID,
            sender_agent_id=PEER_ID,
            chain_key=generate_sender_key(GROUP_ID, PEER_ID).chain_key,
            message_index=0,
        )
        save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [squat, own])

        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, own, {"body": "hi"})

        rows = load_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID)
        by_sender = {s.sender_agent_id: s for s in rows}
        assert len(rows) == 2
        assert by_sender[PEER_ID].chain_key == squat.chain_key
        assert by_sender[PEER_ID].message_index == 0
        assert by_sender[SENDER_ID].message_index == 1

    def test_group_when_left_during_the_fan_out_then_the_send_tail_leaves_it_gone(
        self, tmp_config_dir
    ):
        """A leave during the fan-out stays a leave — the send tail cannot undo it.

        This test is the INVERSION its predecessor asked for. It used to pin the
        opposite as a labelled residual: ``_record_distribution`` wrote nothing for
        a group this agent had left, and then the send's own tail re-created the
        state file anyway, because it filtered by ``sender_key_id`` and re-appended
        the row unconditionally. The tail now writes back only where the file still
        has the row, so a group whose file was unlinked mid-send gets nothing put
        back, and "no chain material goes back on disk after a leave" is true of
        both writers rather than only one.

        The same single change closes the more dangerous half of that append —
        restoring a key a concurrent ROTATION had retired, which the reader then
        selected as current because it is last. That half is covered by
        :meth:`test_group_when_rotated_during_the_fan_out_then_the_send_tail_leaves_it_gone`.
        """
        _seat_sender(tmp_config_dir)
        _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID],
            lambda: delete_sender_key(tmp_config_dir, SENDER_ID, GROUP_ID),
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        assert sender_key_state_exists(tmp_config_dir, SENDER_ID, GROUP_ID) is False

        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        assert sender_key_state_exists(tmp_config_dir, SENDER_ID, GROUP_ID) is False

    def test_group_when_rotated_during_the_fan_out_then_the_send_tail_leaves_it_gone(
        self, tmp_config_dir
    ):
        """🔴 A rotation that lands mid-send is not undone by the send's own tail.

        The dangerous half of the same append, and the one the leave case above
        cannot see. Nothing is missing from the file here — only the ORDER moves,
        and order is the whole of the answer:
        :func:`rine._sender_key_ops.get_or_create_sender_key_sync` takes the LAST
        own row as the current key, and a rotation retains the row it supersedes
        BELOW the new one. A tail that filtered its own row out and re-appended
        it therefore moved the SUPERSEDED key back to last, and the next send
        sealed the group under a key this agent had already rotated away from —
        with a ``distributed_to`` naming whoever the rotation was for.

        🔴 Asserted through the SELECTOR, not off the file. "Last own row" is the
        selector's rule and not a property of the file, so a file-shape assertion
        alone would pass a rewrite that reordered the rows and read them
        differently — and the failure this exists for is *which key the group is
        sealed under*, not which line of JSON came last.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        # The rotation's own shape, as ``get_or_create_sender_key_sync`` writes
        # it: the new key appended, and exactly the one row it supersedes kept
        # below it. Already distributed, so the send after it has no honest
        # reason to fan out and the next selection is a clean read.
        replacement = generate_sender_key(GROUP_ID, SENDER_ID)
        replacement.distributed_to = [MEMBER_A_ID, MEMBER_B_ID]
        server = FanOutServer(
            [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID],
            lambda: save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [own, replacement]),
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        # The superseded row is still there — it is what lets this agent re-read
        # the post it just sent — but it stays where the rotation put it.
        assert _own_ids(tmp_config_dir) == [own.sender_key_id, replacement.sender_key_id]

        unchanged = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        picked = get_or_create_sender_key_sync(unchanged, tmp_config_dir, SENDER_ID, _GROUP)

        assert picked.sender_key_id == replacement.sender_key_id
        # The material, not just the label: this is what the next post is sealed
        # under, and a retired chain key here is the whole defect.
        assert picked.chain_key == replacement.chain_key

    def test_own_row_when_two_rotations_dropped_it_then_the_send_tail_does_not_restore_it(
        self, tmp_config_dir
    ):
        """🔴 The row is GONE while the file still holds other keys of this agent's.

        The case neither test above can see, and the one a "re-append it when the
        file is not empty" rewrite passes both of them on. A rotation retains
        exactly the one own row it superseded, so the SECOND rotation to land
        during a single fan-out drops the row this send is holding. Re-appending it
        there puts a key retired two rotations ago at the END of the file, and the
        end is where :func:`rine._sender_key_ops.get_or_create_sender_key_sync`
        looks — so the next post goes out under it, with a ``distributed_to``
        naming a roster two rosters old. The leave case leaves an EMPTY file and
        the single rotation leaves the row PRESENT, so only this shape tells the
        two implementations apart.
        """
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        first = generate_sender_key(GROUP_ID, SENDER_ID)
        second = generate_sender_key(GROUP_ID, SENDER_ID)
        second.distributed_to = [MEMBER_A_ID, MEMBER_B_ID]

        def _two_rotations() -> None:
            save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [own, first])
            save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [first, second])

        server = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID], _two_rotations)

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        assert _own_ids(tmp_config_dir) == [first.sender_key_id, second.sender_key_id]

        # Through the SELECTOR, because that is what the defect costs: the key the
        # next post is sealed under.
        unchanged = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        picked = get_or_create_sender_key_sync(unchanged, tmp_config_dir, SENDER_ID, _GROUP)

        assert picked.sender_key_id == second.sender_key_id
        assert picked.chain_key == second.chain_key


class TestTheSendTailRefusesAnUnpersistedState:
    """The third absence: a state that was never on disk at all.

    The tail writes this agent's row back IN PLACE and writes nothing where the
    row is gone, because gone means RETIRED — a rotation dropped it, or a
    ``group leave`` unlinked the file. Both of those are silent on purpose.
    :func:`rine._crypto.message.encrypt_group_message` is importable next to
    :func:`rine._crypto.sender_keys.generate_sender_key` and
    :func:`rine._crypto.sender_keys_helpers.save_sender_key_state`, so a caller
    can compose the two and hand in a state nothing ever wrote. Skipping that
    silently produces a real, transmittable ciphertext whose ratchet advance and
    self-read key go nowhere: the sender cannot re-read its own post, and the next
    send starts from message index zero again.

    The three absences are told apart rather than collapsed, and each arm is held
    here. Twin: ``rine-core/test/crypto/sender-key-send-race.test.ts``.
    """

    def test_send_tail_when_the_state_was_never_persisted_then_it_refuses(self, tmp_config_dir):
        """Neither rotated away nor retired: nothing ever persisted this state."""
        _seat_sender(tmp_config_dir)
        unsaved = generate_sender_key(GROUP_ID, SENDER_ID)

        with pytest.raises(UnpersistedSenderKeyStateError):
            encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, unsaved, {"body": "hi"})

    def test_send_tail_when_the_state_was_never_persisted_then_it_creates_no_file(
        self, tmp_config_dir
    ):
        """The refusal must not leave behind the half-state it refused.

        A file created here would make
        :func:`rine._sender_key_ops.sender_key_state_exists` — which a leave reads
        to say which encryption it just retired — answer for a group this agent
        holds no material for.
        """
        _seat_sender(tmp_config_dir)
        unsaved = generate_sender_key(GROUP_ID, SENDER_ID)

        with pytest.raises(UnpersistedSenderKeyStateError):
            encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, unsaved, {"body": "hi"})

        assert sender_key_state_exists(tmp_config_dir, SENDER_ID, GROUP_ID) is False

    def test_send_tail_when_the_row_was_rotated_away_then_it_seals_without_raising(
        self, tmp_config_dir
    ):
        """Same absence, different history: this agent still holds keys here.

        Silent by design — the message is already sealed, and the advance of a key
        nobody will send under again is not worth writing.
        """
        _seat_sender(tmp_config_dir)
        rotated_away = generate_sender_key(GROUP_ID, SENDER_ID)
        current = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])

        result, _ = encrypt_group_message(
            tmp_config_dir, SENDER_ID, GROUP_ID, rotated_away, {"body": "hi"}
        )

        assert result.encryption_version == "sender-key-v1"
        assert _own_ids(tmp_config_dir) == [current.sender_key_id]

    def test_send_tail_when_the_group_was_left_then_it_seals_without_raising(self, tmp_config_dir):
        """No own row anywhere AND a retirement marker: the group was left."""
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        delete_sender_key(tmp_config_dir, SENDER_ID, GROUP_ID)

        result, _ = encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, own, {"body": "hi"})

        assert result.encryption_version == "sender-key-v1"
        assert sender_key_state_exists(tmp_config_dir, SENDER_ID, GROUP_ID) is False


#: How long one side holds a region while the other is given every chance to
#: barge into it, and how long a rendezvous waits for a partner the exclusion may
#: never let arrive. Generous by design: the racing side's whole send runs
#: against in-memory fakes, so it arrives in milliseconds when nothing stops it,
#: and every case below distinguishes "did not arrive in half a second" from
#: "arrived immediately" rather than measuring how long anything took.
_RACE_WINDOW_SECONDS = 0.5


class _Rendezvous:
    """A two-party meeting that stops being one once the exclusion is real.

    🔴 An unbounded barrier inside a region the fix makes exclusive is a deadlock,
    not a test: the second party can never arrive, so both sides hang forever.
    Every wait here is bounded and a timeout is an EXPECTED outcome — with the
    lock in place the first party waits it out and goes on alone; with the lock
    removed the two meet at once and the interleave happens. That difference is
    the whole measurement.
    """

    def __init__(self, timeout: float) -> None:
        """Arm a meeting for two, abandoned after *timeout* seconds."""
        self._barrier = threading.Barrier(2, timeout=timeout)

    def meet(self) -> None:
        """Wait for the other party, and give up rather than hang."""
        with contextlib.suppress(threading.BrokenBarrierError):
            self._barrier.wait()


class TestTwoRotationsAtOnce:
    """Two threads of one client, each rotating this agent's key in the same group.

    The realistic shape: an async client hands every group send to a worker
    thread (``rine._mls.bridge.with_sync_http``), so two sends in flight are two
    threads inside :func:`rine._sender_key_ops.get_or_create_sender_key_sync`.
    Its rotation re-reads the file after the fan-out and then saves the WHOLE
    array, which is an answer about rows it never looked at — so a rotation that
    lands between another's re-read and its save is erased by it, and the erased
    agent can never read its own post back.
    """

    def test_two_sends_when_both_rotate_at_once_then_neither_new_key_is_lost(
        self, tmp_config_dir, monkeypatch
    ):
        """Both minted keys are on disk, whichever order the two regions ran in.

        The interleave is forced where it matters: the rendezvous sits between the
        rotation's fresh read and its save, which is inside the region, so under
        exclusion the second thread cannot reach it and the first waits the
        rendezvous out. Without exclusion both threads read before either writes,
        and the second save silently drops the first agent's new key.
        """
        _seat_sender(tmp_config_dir)
        _own_key(
            tmp_config_dir, distributed_to=[MEMBER_A_ID], message_index=ROTATION_MESSAGE_LIMIT
        )
        rendezvous = _Rendezvous(_RACE_WINDOW_SECONDS)

        def save_after_meeting(*args: Any, **kwargs: Any) -> None:
            rendezvous.meet()
            save_sender_key_state(*args, **kwargs)

        monkeypatch.setattr("rine._sender_key_ops.save_sender_key_state", save_after_meeting)
        minted: list[str] = []

        def send() -> None:
            server = FanOutServer([SENDER_ID, MEMBER_A_ID])
            state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
            minted.append(state.sender_key_id)

        threads = [threading.Thread(target=send) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert [t.is_alive() for t in threads] == [False, False]
        # Both sends rotated, so both minted a key they will seal under and cache
        # their own self-read key in.
        assert len(minted) == 2
        assert len(set(minted)) == 2
        assert set(minted) <= set(_own_ids(tmp_config_dir))


class TestTheThreadTier:
    """The lock a coroutine takes and the lock a worker thread takes are ONE lock.

    :func:`rine._crypto.sender_keys_store.with_sender_key_states` alone cannot
    give this stack what ``withSenderKeyStates`` gives the TypeScript one. An
    :class:`asyncio.Lock` binds to the loop that first contends it, and the group
    send is synchronous, run on a thread that has no loop to contend from — so
    the exclusion is built in two tiers and these are what say the two tiers meet
    over the same file.
    """

    async def test_sync_region_when_a_coroutine_holds_the_file_then_it_waits(self, tmp_config_dir):
        """A worker thread may not enter a file a coroutine is holding."""
        held: list[str] = []
        overlaps: list[str] = []
        inside_loop = threading.Event()

        def worker() -> None:
            with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
                if inside_loop.is_set():
                    overlaps.append("the thread entered while the coroutine held it")
                held.append("thread")

        thread = threading.Thread(target=worker)
        async with with_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID):
            inside_loop.set()
            thread.start()
            # The loop stays live while the thread queues, which is why the
            # coroutine side polls for the thread tier instead of blocking on it:
            # a blocking acquire here would stop every task in the process.
            await asyncio.sleep(_RACE_WINDOW_SECONDS)
            assert held == []
            inside_loop.clear()

        thread.join(timeout=5)
        assert thread.is_alive() is False
        assert overlaps == []
        # And it did get in, once the coroutine left: exclusion, not exclusion
        # forever.
        assert held == ["thread"]
        assert sender_keys_thread_lock._thread_locks == {}

    async def test_coroutine_region_when_a_thread_holds_the_file_then_it_waits(
        self, tmp_config_dir
    ):
        """And the other way round, which is the direction a send blocks a render."""
        inside_thread = threading.Event()
        release = threading.Event()
        entered: list[str] = []
        overlaps: list[str] = []

        def worker() -> None:
            with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
                inside_thread.set()
                release.wait(timeout=10)

        async def enter() -> None:
            async with with_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID):
                if inside_thread.is_set() and not release.is_set():
                    overlaps.append("the coroutine entered while the thread held it")
                entered.append("loop")

        thread = threading.Thread(target=worker)
        thread.start()
        assert inside_thread.wait(timeout=5) is True
        task = asyncio.create_task(enter())
        await asyncio.sleep(_RACE_WINDOW_SECONDS)

        assert entered == []
        release.set()
        await asyncio.wait_for(task, timeout=5)
        thread.join(timeout=5)

        assert thread.is_alive() is False
        assert overlaps == []
        assert entered == ["loop"]
        assert sender_keys_thread_lock._thread_locks == {}

    async def test_a_second_group_when_another_is_held_then_it_is_not_blocked(
        self, tmp_config_dir
    ):
        """Per FILE, never one lock over the store.

        Without this the two tests above pass just as well against a single global
        lock, which would serialise every group in the process against every
        other for the length of a network verify.
        """
        other_group = "cccccccc-dddd-4ddd-8ddd-000000000000"
        entered: list[str] = []

        def worker() -> None:
            with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, other_group):
                entered.append("thread")

        async with with_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID):
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(timeout=5)
            assert entered == ["thread"]

        assert sender_keys_thread_lock._thread_locks == {}


class TestEveryWriteHappensInsideItsRegion:
    """Three of the four synchronous regions were asserted by nothing at all.

    ``TestTwoRotationsAtOnce`` interleaves two threads inside the rotation's
    region, so that one is pinned by behaviour. The send tail and
    ``_record_distribution`` carried their region as a source line only:
    replacing either with :func:`contextlib.nullcontext` left this whole suite
    green, which is the definition of a fix nothing guards — and the region is
    the half of the repair the merge cannot cover, since both of these writes
    ASSERT an array rather than merging one.

    Interleaving a second writer at these two is not available the way it is for
    the rotation: the window is inside a real seal, with no hook to stop in. So
    they ask from inside the write instead, which is a weaker statement honestly
    made — it says the region is held, not that a competing writer was excluded.
    ``sender_key_region_is_held_here`` says why that is still worth having.
    """

    def test_send_tail_when_it_writes_then_the_region_is_held(self, tmp_config_dir, monkeypatch):
        """``encrypt_group_message``'s write-back of this agent's own row."""
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        held: list[bool] = []
        real = message.save_sender_key_state

        def watched(config_dir, writer_id, gid, states):
            held.append(sender_key_region_is_held_here(config_dir, writer_id, gid))
            return real(config_dir, writer_id, gid, states)

        monkeypatch.setattr(message, "save_sender_key_state", watched)

        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, own, {"body": "hi"})

        assert held == [True]
        # The seal still landed with the writer wrapped, so the region assertion
        # is not passing over a path this test never reached.
        assert _rows(tmp_config_dir)[own.sender_key_id].message_index == 1

    def test_recorded_distribution_when_it_writes_then_the_region_is_held(
        self, tmp_config_dir, monkeypatch
    ):
        """``_record_distribution``'s merge of ``distributed_to``, after the fan-out."""
        _seat_sender(tmp_config_dir)
        own = _own_key(tmp_config_dir, distributed_to=[MEMBER_A_ID])
        server = FanOutServer([SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        held: list[bool] = []
        real = _sender_key_ops.merge_sender_key_states

        def watched(config_dir, writer_id, gid, states):
            held.append(sender_key_region_is_held_here(config_dir, writer_id, gid))
            return real(config_dir, writer_id, gid, states)

        monkeypatch.setattr(_sender_key_ops, "merge_sender_key_states", watched)

        get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)

        assert held == [True]
        assert _rows(tmp_config_dir)[own.sender_key_id].distributed_to == [
            MEMBER_A_ID,
            MEMBER_B_ID,
        ]


class TestTheThreadTierRefusesAFatalReentry:
    """A re-entry that could only hang now raises, and says which file.

    Non-reentrancy used to be prose in three docstrings. Breaking it parks a
    thread in :meth:`threading.Lock.acquire` against a lock that thread itself
    holds: no traceback, no file named, and — because ``rine-sdk``'s suite is a
    publish gate — a whole release train stopped on a test run that never
    finishes. These assert the refusal that replaces the hang, and just as
    importantly the two shapes it must NOT refuse.
    """

    def test_sync_region_when_reached_from_inside_one_over_the_same_file_then_it_raises(
        self, tmp_config_dir
    ):
        """The nested-region case, which is the one a reader introduces by accident."""
        with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
            with pytest.raises(RuntimeError, match="not reentrant"):
                with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
                    raise AssertionError("the second region was entered")

        # The refused acquirer took a holder count before it raised, so the entry
        # draining here is what says it gave that count back — a leak would leave
        # the file's lock in the table forever and never be visible any other way.
        assert sender_keys_thread_lock._thread_locks == {}

    async def test_sync_region_when_reached_on_the_loop_thread_under_the_async_one_then_it_raises(
        self, tmp_config_dir
    ):
        """The call-from-a-coroutine refusal, enforced rather than documented.

        This is the shape that cannot be waited out: the loop thread parks in a
        blocking acquire, so the coroutine holding the file can never be resumed
        to release it. Refusing is the only answer that terminates.
        """
        async with with_sender_key_states(tmp_config_dir, SENDER_ID, GROUP_ID):
            with pytest.raises(RuntimeError, match="not reentrant"):
                with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
                    raise AssertionError("the synchronous region was entered")

        assert sender_keys_thread_lock._thread_locks == {}

    def test_second_file_when_reached_from_inside_a_region_then_it_is_allowed(
        self, tmp_config_dir
    ):
        """Per file, so a guard keyed on the thread alone would be too wide.

        A send fans out one DM per member and the ingest walks several groups in
        one pass; refusing every nested region would refuse work the product
        does.
        """
        other_group = "dddddddd-eeee-4eee-8eee-111111111111"
        entered: list[str] = []

        with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, GROUP_ID):
            with with_sender_key_states_sync(tmp_config_dir, SENDER_ID, other_group):
                entered.append("second file")

        assert entered == ["second file"]
        assert sender_keys_thread_lock._thread_locks == {}

    async def test_polling_acquirer_when_the_holder_shares_its_ident_then_it_waits(
        self, tmp_config_dir
    ):
        """Two tasks on ONE loop queue for a file; they do not raise at each other.

        Every coroutine on a loop carries that loop thread's ident, so the ident
        the refusal keys on cannot tell "I already hold this" from "somebody else
        on my loop does". That is why the polling side records the holder and
        never consults it. The primitive is driven directly here because
        :func:`with_sender_key_states`' per-loop :class:`asyncio.Lock` excludes
        this pair before the thread tier ever sees it — which is exactly what
        would hide a wrong refusal until something reached the tier without it.
        """
        key = sender_keys_store._file_key(tmp_config_dir, SENDER_ID, GROUP_ID)
        entered: list[str] = []

        async def enter(tag: str) -> None:
            async with sender_keys_thread_lock.held_across_threads_async(key):
                entered.append(tag)
                await asyncio.sleep(_RACE_WINDOW_SECONDS)

        await asyncio.wait_for(asyncio.gather(enter("first"), enter("second")), timeout=5)

        assert entered == ["first", "second"]
        assert sender_keys_thread_lock._thread_locks == {}
