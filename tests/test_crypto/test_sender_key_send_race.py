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
passes. What they do NOT assert is exclusion: this path is sync and the async
client runs it on a worker thread, so it holds no lock and the residual window
between its own re-read and its save is documented rather than tested (see
:mod:`rine._crypto.sender_keys_store`, residual 1).

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

import itertools
import json
import re
from typing import Any

import pytest

from rine._crypto.keys import (
    generate_agent_keys,
    load_agent_keys,
    public_keys_body,
    save_agent_keys,
)
from rine._crypto.message import decrypt_group_message_sync, encrypt_group_message
from rine._crypto.sender_keys import (
    ROTATION_MESSAGE_LIMIT,
    SenderKeyState,
    generate_sender_key,
)
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._sender_key_ops import (
    delete_sender_key,
    get_or_create_sender_key_sync,
    sender_key_state_exists,
)
from rine.errors import UnpersistedSenderKeyStateError

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


class _ColdKeyCache:
    """The one client attribute the inbound-verify read reaches for.

    ``rine._crypto._agent_keys.get_agent_keys_sync`` consults ``client._keys_cache``
    before the network. Kept permanently cold so every verify goes to
    :class:`FanOutServer`, which is the only thing here that knows what this agent
    published.
    """

    def get(self, _agent_id: str) -> None:
        """Never answer from cache."""
        return None

    def set(self, _agent_id: str, _data: dict[str, Any]) -> None:
        """Keep nothing."""


class FanOutServer:
    """The roster read, key reads and distribution posts one send makes.

    ``on_post`` runs INSIDE the fan-out — the recipient's keys have been fetched
    and the DM sealed, and the caller has not yet recorded the delivery — which is
    the window every test here writes into. One hook is enough because each of
    these sends fans out to exactly one recipient; a second post would fire it
    again, which no test wants.

    The SENDER's own published keys are served from what ``_seat_sender`` wrote to
    disk, not minted fresh: a self-read decrypt verifies this agent's signature
    against them, and a freshly generated pair would fail that verify rather than
    answer the question under test. Construct this only after ``_seat_sender``.
    """

    def __init__(self, config_dir: str, roster: list[str], on_post: Any = None) -> None:
        """Serve one group's roster and every seated agent's published keys."""
        self.roster = roster
        self.posts: list[dict[str, Any]] = []
        self._on_post = on_post
        self._keys_cache = _ColdKeyCache()
        self._published: dict[str, dict[str, Any]] = {
            SENDER_ID: public_keys_body(load_agent_keys(config_dir, SENDER_ID))
        }
        for agent_id in roster:
            if agent_id == SENDER_ID:
                continue
            self._published[agent_id] = public_keys_body(generate_agent_keys())

    def get(self, path: str, **_kwargs: object) -> Any:
        """Answer the roster read and each agent's published keys."""
        if path == f"/groups/{GROUP_ID}/members":
            return {"items": [{"agent_id": a, "role": "member"} for a in self.roster]}
        match = _KEYS_PATH.match(path)
        if match is not None and match.group(1) in self._published:
            return self._published[match.group(1)]
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, **kwargs: Any) -> dict[str, str]:
        """Accept one distribution DM, running the concurrent writer first."""
        assert path == "/messages"
        self.posts.append(kwargs["json_body"])
        if self._on_post is not None:
            self._on_post()
        return {"id": "dddddddd-eeee-ffff-0000-111111111111"}


def _seat_sender(config_dir: str) -> None:
    """The sending agent's own keys on disk, which every seal loads."""
    save_agent_keys(config_dir, SENDER_ID, generate_agent_keys())


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
            tmp_config_dir,
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
        server = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])

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
            tmp_config_dir,
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
            tmp_config_dir,
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
        server = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
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
            tmp_config_dir,
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
            tmp_config_dir,
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
        seated = FanOutServer(config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
        state = get_or_create_sender_key_sync(seated, config_dir, SENDER_ID, _GROUP)
        result, _ = encrypt_group_message(
            config_dir, SENDER_ID, GROUP_ID, state, {"body": "my own post"}
        )

        # MEMBER_B is gone from the roster, which is a rotation trigger.
        after = FanOutServer(config_dir, [SENDER_ID, MEMBER_A_ID])
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
        empty = FanOutServer(tmp_config_dir, [SENDER_ID])
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

        unchanged = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID])
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
        server = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])

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
            tmp_config_dir,
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
            tmp_config_dir,
            [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID],
            lambda: save_sender_key_state(tmp_config_dir, SENDER_ID, GROUP_ID, [own, replacement]),
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        # The superseded row is still there — it is what lets this agent re-read
        # the post it just sent — but it stays where the rotation put it.
        assert _own_ids(tmp_config_dir) == [own.sender_key_id, replacement.sender_key_id]

        unchanged = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
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

        server = FanOutServer(
            tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID], _two_rotations
        )

        state = get_or_create_sender_key_sync(server, tmp_config_dir, SENDER_ID, _GROUP)
        encrypt_group_message(tmp_config_dir, SENDER_ID, GROUP_ID, state, {"body": "hello"})

        assert _own_ids(tmp_config_dir) == [first.sender_key_id, second.sender_key_id]

        # Through the SELECTOR, because that is what the defect costs: the key the
        # next post is sealed under.
        unchanged = FanOutServer(tmp_config_dir, [SENDER_ID, MEMBER_A_ID, MEMBER_B_ID])
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
