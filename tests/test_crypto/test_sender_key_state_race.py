"""One group's sender-key state file is a shared read-modify-write.

The defect these exist for: rendering a group transcript after being away came
back mostly ``[no sender key: ask the sender to post to the group again]``, and
asking for the same transcript again showed all of it. Every row of a render
opens against the same file, and on this stack a background SSE listener decrypts
into it from the same event loop as the foreground render — each site loads the
array, advances its own copy and writes the whole thing back, so every advance
but the last is discarded and a peer's key installed in the meantime goes with
it. Nothing in any suite decrypted two group rows at once, so nothing saw it.

These drive the public encrypt/decrypt/persist functions, not the lock: a rewrite
that keeps :func:`rine._crypto.message.decrypt_group_message_async`'s signature
and gets the answers right passes. Only the HTTP client is a stand-in; the crypto
is the real thing. The TypeScript twin is
``rine-core/test/crypto/sender-key-state-race.test.ts``.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading

from rine._crypto import sender_keys_store
from rine._crypto.keys import generate_agent_keys, public_keys_body, save_agent_keys
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_group_message_sync,
    encrypt_group_message,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import (
    load_sender_key_states,
    mark_sender_keys_retired,
    save_sender_key_state,
)
from rine._crypto.sender_keys_store import merge_sender_key_states
from rine._sender_key_ops import delete_sender_key

READER_ID = "11111111-1111-4111-8111-111111111111"
PEER_A_ID = "22222222-2222-4222-8222-222222222222"
PEER_B_ID = "33333333-3333-4333-8333-333333333333"
GROUP_ID = "44444444-4444-4444-8444-444444444444"
# One sender key id claimed by two senders — what the per-sender ingest check admits.
SHARED_KEY_ID = "55555555-5555-4555-8555-555555555555"
# A group whose id has letters in it, so the two spellings differ.
MIXED_GROUP_ID = "aaaaaaaa-5555-4555-8555-aaaaaaaaaaaa"

_KEYS_PATH = re.compile(r"^/agents/([^/]+)/keys$")


class _AlwaysCold:
    """A key cache that never hits, so every verify goes to the network.

    ``rine._crypto._agent_keys.get_agent_keys_async`` returns a cache HIT without
    awaiting anything, and awaiting a coroutine that never suspends does not yield
    the event loop. A cached verify therefore cannot race, and a stub that let the
    second row hit the cache would close the very window under test.
    """

    def get(self, _agent_id: str) -> None:
        """Never answer from cache."""
        return None

    def set(self, _agent_id: str, _data: dict) -> None:
        """Keep nothing."""


class ReverseOrderKeyServer:
    """Answers ``GET /agents/{id}/keys``, running ``on_fetch`` while callers wait.

    🔴 Concurrent callers are answered in REVERSE arrival order, and that is what
    gives the first test below its discriminating power. Answering them FIFO makes
    the LAST row to arrive the last row to write, and that row carries the HIGHEST
    ratchet index — so an implementation that merges by ``sender_key_id`` but
    serialises nothing records the right index by accident, and the lock could be
    deleted against a green suite. Answering backwards makes the first, lowest-index
    row the last writer: only a holder that reloads under exclusion still gets the
    arithmetic right.

    The queue is a COUNTED number of ``asyncio.sleep(0)`` yields, never a
    wall-clock sleep: a bare yield reschedules the task at the end of the ready
    queue, so every concurrent row has reached this point and been counted before
    the first one is answered, and the ordering is the same on every machine.
    """

    def __init__(self, published: dict[str, dict], on_fetch=None) -> None:
        """Serve the given agents' published keys, from cold."""
        self._published = published
        self._on_fetch = on_fetch
        self._arrived = 0
        self._keys_cache = _AlwaysCold()

    async def get(self, path: str, **_kwargs: object) -> dict:
        """Answer one key read after a wait that shortens with each arrival."""
        match = _KEYS_PATH.match(path)
        if match is None or match.group(1) not in self._published:
            raise AssertionError(f"unexpected GET {path}")
        # The window this whole file is about: real work lands between a decrypt's
        # load and its save because the decrypt goes to the network in between.
        if self._on_fetch is not None:
            self._on_fetch()
        rounds = max(1, 32 - 4 * self._arrived)
        self._arrived += 1
        for _ in range(rounds):
            await asyncio.sleep(0)
        return self._published[match.group(1)]


def _peers(config_dir: str) -> dict[str, dict]:
    """Both peers plus the reader on disk, and the peers' keys as published."""
    published = {}
    for peer_id in (PEER_A_ID, PEER_B_ID):
        keys = generate_agent_keys()
        save_agent_keys(config_dir, peer_id, keys)
        published[peer_id] = public_keys_body(keys)
    save_agent_keys(config_dir, READER_ID, generate_agent_keys())
    return published


def _backlog(config_dir: str, peer_id: str, count: int) -> tuple[SenderKeyState, list[str]]:
    """``count`` posts from one peer, plus the state a reader needs to open them.

    🔴 Each post is sealed from the sender's ADVANCED state, so the indices run
    ``0..count-1``. Re-using one un-advanced state seals everything at index 0, the
    recipient then legitimately refuses all but the first, and the control fails in
    a way indistinguishable from the product defect.
    """
    reader_state = generate_sender_key(GROUP_ID, peer_id)
    # The peer's own copy, which ``encrypt_group_message`` advances in place. A
    # stand-in sender needs it as much as a real one does: the tail refuses a state
    # that is on no disk at all rather than discarding the advance. It lands under
    # the PEER's own directory, never the reader's.
    save_sender_key_state(config_dir, peer_id, GROUP_ID, [_reader_view(reader_state)])
    state = reader_state
    payloads = []
    for i in range(count):
        result, state = encrypt_group_message(
            config_dir, peer_id, GROUP_ID, state, {"text": f"post {i} from {peer_id}"}
        )
        payloads.append(result.encrypted_payload)
    return reader_state, payloads


def _reader_view(state: SenderKeyState) -> SenderKeyState:
    """The peer's key as the reader receives it: chain at index 0, nothing cached."""
    return SenderKeyState(
        sender_key_id=state.sender_key_id,
        group_id=state.group_id,
        sender_agent_id=state.sender_agent_id,
        chain_key=state.chain_key,
        message_index=state.message_index,
    )


def _ingest_peer_key(config_dir: str, state: SenderKeyState) -> None:
    """Install a peer's key exactly as the distribution ingest does.

    Mirrors the writer inside
    ``rine._client.RineClient._scan_pending_sk_distributions``: load the whole
    array, append the new state, save the whole array — with no lock, and no
    ``await`` of its own between the load and the save.
    """
    states = load_sender_key_states(config_dir, READER_ID, GROUP_ID)
    states.append(_reader_view(state))
    save_sender_key_state(config_dir, READER_ID, GROUP_ID, states)


def _state_path(config_dir: str) -> str:
    return os.path.join(config_dir, "keys", READER_ID, "sender_keys", f"{GROUP_ID}.json")


def _indices(config_dir: str) -> dict[str, int]:
    """Where each sender's ratchet stands on disk."""
    return {
        s.sender_agent_id: s.message_index
        for s in load_sender_key_states(config_dir, READER_ID, GROUP_ID)
    }


class TestConcurrentWriters:
    """What the state file must hold when more than one writer is in flight."""

    async def test_group_rows_when_decrypted_concurrently_then_every_advance_persists(
        self, tmp_config_dir
    ):
        """Three posts per sender were opened, so each sender's ratchet stands at 3."""
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 3)
        b_state, b_posts = _backlog(tmp_config_dir, PEER_B_ID, 3)
        save_sender_key_state(
            tmp_config_dir,
            READER_ID,
            GROUP_ID,
            [_reader_view(a_state), _reader_view(b_state)],
        )
        server = ReverseOrderKeyServer(published)

        # The shape a render has: both keys are loaded by every row before any row
        # saves. That is forced, not lucky — the load is synchronous and the first
        # await in each row comes after it.
        rows = [(p, PEER_A_ID) for p in a_posts] + [(p, PEER_B_ID) for p in b_posts]
        opened = await asyncio.gather(
            *(
                decrypt_group_message_async(
                    tmp_config_dir, READER_ID, GROUP_ID, payload, server, sender
                )
                for payload, sender in rows
            )
        )

        assert len(opened) == 6
        # A writer that asserts the whole array from a pre-network snapshot leaves
        # at most one sender advanced and the other exactly where it was loaded.
        assert _indices(tmp_config_dir) == {PEER_A_ID: 3, PEER_B_ID: 3}

    async def test_peer_key_when_ingested_during_a_decrypts_verify_then_it_survives(
        self, tmp_config_dir
    ):
        """A key the decrypt never had an opinion about must not be written away."""
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 1)
        b_state, b_posts = _backlog(tmp_config_dir, PEER_B_ID, 1)
        # The reader starts holding A's key only. B's arrives as its distribution
        # DM is opened, which is what the pending-distribution scan does while a
        # cold render is in flight.
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [_reader_view(a_state)])

        ingested = []

        def _ingest_once() -> None:
            if ingested:
                return
            ingested.append(True)
            _ingest_peer_key(tmp_config_dir, b_state)

        server = ReverseOrderKeyServer(published, _ingest_once)

        await decrypt_group_message_async(
            tmp_config_dir, READER_ID, GROUP_ID, a_posts[0], server, PEER_A_ID
        )

        # Losing B's key is exactly what makes the next row report the group sealed
        # under a key "no later message reopens" — and the render after that opens it.
        assert sorted(_indices(tmp_config_dir)) == sorted([PEER_A_ID, PEER_B_ID])

        # And B's key still opens B's post, which is the part a reader sees.
        opened = await decrypt_group_message_async(
            tmp_config_dir, READER_ID, GROUP_ID, b_posts[0], server, PEER_B_ID
        )
        assert json.loads(opened.plaintext) == {"text": f"post 0 from {PEER_B_ID}"}

    async def test_group_when_retired_during_a_decrypts_verify_then_the_wipe_holds(
        self, tmp_config_dir
    ):
        """A leave that lands mid-decrypt is not undone by whatever was in flight."""
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 1)
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [_reader_view(a_state)])

        # One terminal running `group leave` against the config dir another is
        # reading. The decrypt loaded this peer's chain key before the wipe and is
        # still holding it, so its save is the one writer that can put retired key
        # material back on disk — the retirement marker does not stop it, because
        # the marker only refuses INGESTS.
        server = ReverseOrderKeyServer(
            published, lambda: delete_sender_key(tmp_config_dir, READER_ID, GROUP_ID)
        )

        await decrypt_group_message_async(
            tmp_config_dir, READER_ID, GROUP_ID, a_posts[0], server, PEER_A_ID
        )

        assert not os.path.exists(_state_path(tmp_config_dir))
        assert load_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID) == []

    async def test_one_row_when_two_readers_open_it_at_once_then_both_get_the_plaintext(
        self, tmp_config_dir
    ):
        """The ratchet spends a message key once; two readers of one row are two.

        🔴 The shape is the one this whole file is about — a background SSE
        listener calling ``read(M)`` while a foreground render decrypts the page M
        is on. Serialising them is not enough on its own: the loser reloads the
        state the winner advanced, finds no skipped key for the index the winner
        consumed, and gets ``CryptoError("Message key expired or already
        consumed")``. On the render path that is terminal — ``_decrypt_thread_row``
        spends its recovery budget on ``NoSenderKeyStateError`` alone — so the row
        comes back as the sealed-message refusal, which is the defect, produced by
        the fix for it. The winner records its read INSIDE the exclusion, so the
        loser is answered from that cache.
        """
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 1)
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [_reader_view(a_state)])
        server = ReverseOrderKeyServer(published)

        first, second = await asyncio.gather(
            *(
                decrypt_group_message_async(
                    tmp_config_dir, READER_ID, GROUP_ID, a_posts[0], server, PEER_A_ID
                )
                for _ in range(2)
            )
        )

        expected = {"text": f"post 0 from {PEER_A_ID}"}
        assert json.loads(first.plaintext) == expected
        assert json.loads(second.plaintext) == expected
        # One row was opened, so the ratchet moved by one — the second reader was
        # answered from the read cache and did not step it again.
        assert _indices(tmp_config_dir) == {PEER_A_ID: 1}


class TestAcrossEventLoops:
    """A CLI runs one command per process; a host may run one loop per thread."""

    def test_decrypt_when_run_in_two_successive_event_loops_then_both_open(self, tmp_config_dir):
        """🔴 An ``asyncio.Lock`` binds to a loop the first time it is CONTENDED.

        Mere reuse does not bind it: CPython's uncontended ``acquire`` sets
        ``_locked`` and returns without touching the loop, so a gate that decrypts
        one row per run can be handed a lock table with no per-loop key at all and
        still pass. Both runs below therefore contend, and a lock carried from a
        closed loop into a live one raises ``<asyncio.locks.Lock object …> is bound
        to a different event loop``.

        This case is defended TWICE — the table is keyed per loop, and an entry is
        dropped when its last holder leaves, so a finished run leaves nothing to
        carry. The test below is the one that isolates the per-loop key.
        """
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 4)
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [_reader_view(a_state)])
        server = ReverseOrderKeyServer(published)

        async def _read_pair(payloads: list[str]):
            return await asyncio.gather(
                *(
                    decrypt_group_message_async(
                        tmp_config_dir, READER_ID, GROUP_ID, payload, server, PEER_A_ID
                    )
                    for payload in payloads
                )
            )

        first = asyncio.run(_read_pair(a_posts[:2]))
        second = asyncio.run(_read_pair(a_posts[2:]))

        opened = {json.loads(r.plaintext)["text"] for r in [*first, *second]}
        assert opened == {f"post {i} from {PEER_A_ID}" for i in range(4)}
        assert _indices(tmp_config_dir) == {PEER_A_ID: 4}
        # Nothing outlives the loops that used it. A contended ``asyncio.Lock``
        # holds its loop STRONGLY, so a table that never released would pin both
        # closed loops here — invisible from outside, hence the private read.
        assert sender_keys_store._locks == {}

    def test_decrypt_when_two_loops_run_at_once_then_neither_waits_on_the_other(
        self, tmp_config_dir
    ):
        """Two event loops in two threads must not share one file's lock.

        🔴 This is what the per-loop key buys that dropping the entry does not: a
        table keyed by file identity alone hands both loops ONE ``asyncio.Lock``,
        and the second acquire is contended — it binds the lock to its own loop and
        waits on a future the other thread will complete, from the other thread,
        with no ``call_soon_threadsafe`` anywhere. The reader that waits never
        arrives, which is why the barrier and the join both carry timeouts: the
        failure is a hang, and a hang has to be reported as one.

        The two decrypts are of different senders and the threads are not excluded
        from each other, so nothing here asserts what the file ends up holding —
        only that both readers got their plaintext.
        """
        published = _peers(tmp_config_dir)
        a_state, a_posts = _backlog(tmp_config_dir, PEER_A_ID, 1)
        b_state, b_posts = _backlog(tmp_config_dir, PEER_B_ID, 1)
        save_sender_key_state(
            tmp_config_dir,
            READER_ID,
            GROUP_ID,
            [_reader_view(a_state), _reader_view(b_state)],
        )
        # Both loops are inside their decrypt, awaiting the key fetch, before
        # either is answered — the overlap is forced rather than hoped for.
        both_inside = threading.Barrier(2, timeout=10)
        opened: dict[str, str] = {}
        failed: dict[str, BaseException] = {}

        def _read(peer_id: str, payload: str) -> None:
            server = ReverseOrderKeyServer(published, both_inside.wait)
            try:
                result = asyncio.run(
                    decrypt_group_message_async(
                        tmp_config_dir, READER_ID, GROUP_ID, payload, server, peer_id
                    )
                )
                opened[peer_id] = json.loads(result.plaintext)["text"]
            except BaseException as exc:  # noqa: BLE001 — reported, not swallowed
                failed[peer_id] = exc

        readers = [
            threading.Thread(target=_read, args=(PEER_A_ID, a_posts[0]), daemon=True),
            threading.Thread(target=_read, args=(PEER_B_ID, b_posts[0]), daemon=True),
        ]
        for reader in readers:
            reader.start()
        for reader in readers:
            reader.join(timeout=20)

        assert [reader.is_alive() for reader in readers] == [False, False]
        assert failed == {}
        assert opened == {
            PEER_A_ID: f"post 0 from {PEER_A_ID}",
            PEER_B_ID: f"post 0 from {PEER_B_ID}",
        }


class TestRetiredGroupRefusal:
    """What the merge must refuse once a leave has removed the file."""

    def test_merge_when_retired_and_only_the_other_spelling_exists_then_nothing_is_written(
        self, tmp_config_dir
    ):
        """The refusal has to read the file the merge itself would read.

        🔴 The group id is a FILENAME, and this stack spells it two ways:
        ``sender_keys_retired`` lower-cases, ``load_sender_key_states`` and
        ``save_sender_key_state`` take the caller's spelling verbatim, and
        ``sender_key_state_exists`` (written for the leave path) probes BOTH. A
        refusal that borrows the dual-spelling answer sees the lower-case file,
        decides the group was re-created, and lets the merge write live chain
        material to a SECOND file under a spelling nothing else reads — in a group
        this agent has retired.
        """
        state = _reader_view(generate_sender_key(MIXED_GROUP_ID, PEER_A_ID))
        save_sender_key_state(tmp_config_dir, READER_ID, MIXED_GROUP_ID, [state])
        mark_sender_keys_retired(tmp_config_dir, READER_ID, MIXED_GROUP_ID)
        os.remove(
            os.path.join(
                tmp_config_dir, "keys", READER_ID, "sender_keys", f"{MIXED_GROUP_ID}.json"
            )
        )
        # The lower-case file is back — another writer's, not this holder's.
        save_sender_key_state(tmp_config_dir, READER_ID, MIXED_GROUP_ID, [state])

        merge_sender_key_states(tmp_config_dir, READER_ID, MIXED_GROUP_ID.upper(), [state])

        upper_path = os.path.join(
            tmp_config_dir, "keys", READER_ID, "sender_keys", f"{MIXED_GROUP_ID.upper()}.json"
        )
        assert not os.path.exists(upper_path)


class _SyncKeyServer:
    """The sync twin of :class:`ReverseOrderKeyServer`, with nothing to interleave."""

    def __init__(self, published: dict[str, dict]) -> None:
        """Serve the given agents' published keys, from cold."""
        self._published = published
        self._keys_cache = _AlwaysCold()

    def get(self, path: str, **_kwargs: object) -> dict:
        """Answer one key read."""
        match = _KEYS_PATH.match(path)
        if match is None or match.group(1) not in self._published:
            raise AssertionError(f"unexpected GET {path}")
        return self._published[match.group(1)]


def _row(sender_id: str, key_id: str, chain_key: bytes) -> SenderKeyState:
    """One state file row, spelled out rather than minted."""
    return SenderKeyState(
        sender_key_id=key_id,
        group_id=GROUP_ID,
        sender_agent_id=sender_id,
        chain_key=chain_key,
        message_index=0,
    )


def _collision(config_dir: str, squatter_last: bool) -> tuple[str, dict[str, dict]]:
    """One post from A, and a row from B claiming A's key id, on the reader's disk.

    Two rows sharing one ``sender_key_id`` is the state the per-sender ingest check
    admits ON PURPOSE: the id is minted by whoever sends it, so refusing a second
    row by id alone would let whoever claims a peer's id first take its slot for
    good. What the reader holds afterwards is exactly this — the honest peer's key,
    and another agent's key filed under the same name.
    """
    keys_a = generate_agent_keys()
    save_agent_keys(config_dir, PEER_A_ID, keys_a)
    save_agent_keys(config_dir, READER_ID, generate_agent_keys())

    genuine = _row(PEER_A_ID, SHARED_KEY_ID, generate_sender_key(GROUP_ID, PEER_A_ID).chain_key)
    save_sender_key_state(config_dir, PEER_A_ID, GROUP_ID, [genuine])
    result, _ = encrypt_group_message(
        config_dir, PEER_A_ID, GROUP_ID, genuine, {"text": "from the honest peer"}
    )

    # A different chain key under the same name: nothing this row holds opens A's
    # post, which is what makes displacement visible rather than silent.
    squat = _row(PEER_B_ID, SHARED_KEY_ID, generate_sender_key(GROUP_ID, PEER_B_ID).chain_key)
    reader_view = _reader_view(genuine)
    rows = [reader_view, squat] if squatter_last else [squat, reader_view]
    save_sender_key_state(config_dir, READER_ID, GROUP_ID, rows)
    return result.encrypted_payload, {PEER_A_ID: public_keys_body(keys_a)}


def _rows_by_sender(config_dir: str) -> dict[str, str]:
    """Which sender key id the reader holds for each sender."""
    return {
        s.sender_agent_id: s.sender_key_id
        for s in load_sender_key_states(config_dir, READER_ID, GROUP_ID)
    }


class TestCollidingSenderKeyIds:
    """One sender key id can name two rows, and no path may treat it as naming one."""

    def test_squatted_row_when_a_sync_decrypt_persists_then_it_is_still_on_disk(
        self, tmp_config_dir
    ):
        """The sync decrypt asserts one row, not an array keyed by sender key id.

        🔴 The deletion this pins is not the decrypt's answer — that was right — but
        what it wrote afterwards. Keying the whole file by ``sender_key_id`` collapses
        a colliding pair on the way IN, and a whole-array save then rebuilt the file
        from the collapsed map: the losing row was gone from disk, permanently, with
        nothing raised anywhere. Asserting only the returned plaintext passes with
        the deletion still in place.
        """
        payload, published = _collision(tmp_config_dir, squatter_last=False)
        before = _rows_by_sender(tmp_config_dir)
        assert before == {PEER_A_ID: SHARED_KEY_ID, PEER_B_ID: SHARED_KEY_ID}

        opened = decrypt_group_message_sync(
            tmp_config_dir, READER_ID, GROUP_ID, payload, _SyncKeyServer(published), PEER_A_ID
        )
        assert json.loads(opened.plaintext) == {"text": "from the honest peer"}

        assert _rows_by_sender(tmp_config_dir) == before

    def test_honest_post_when_a_squatted_row_landed_last_then_it_still_opens(self, tmp_config_dir):
        """A row from the sender the SERVER named wins the id it shares."""
        payload, published = _collision(tmp_config_dir, squatter_last=True)

        opened = decrypt_group_message_sync(
            tmp_config_dir, READER_ID, GROUP_ID, payload, _SyncKeyServer(published), PEER_A_ID
        )
        assert json.loads(opened.plaintext) == {"text": "from the honest peer"}
        assert _rows_by_sender(tmp_config_dir) == {
            PEER_A_ID: SHARED_KEY_ID,
            PEER_B_ID: SHARED_KEY_ID,
        }

    async def test_honest_post_when_a_squatted_row_landed_last_then_async_opens_it_too(
        self, tmp_config_dir
    ):
        """The async twin prefers the same row, and its merge keeps the other one."""
        payload, published = _collision(tmp_config_dir, squatter_last=True)

        opened = await decrypt_group_message_async(
            tmp_config_dir,
            READER_ID,
            GROUP_ID,
            payload,
            ReverseOrderKeyServer(published),
            PEER_A_ID,
        )
        assert json.loads(opened.plaintext) == {"text": "from the honest peer"}
        # The merge is keyed by the (sender, key) pair too: keyed by the id alone it
        # would collapse the pair on load and write one of them out of existence.
        assert _rows_by_sender(tmp_config_dir) == {
            PEER_A_ID: SHARED_KEY_ID,
            PEER_B_ID: SHARED_KEY_ID,
        }

    def test_ratchet_advance_when_merged_over_a_colliding_pair_then_it_lands_on_the_sender(
        self, tmp_config_dir
    ):
        """The advance belongs to the row it came from, not to whoever shares its id."""
        payload, published = _collision(tmp_config_dir, squatter_last=True)
        decrypt_group_message_sync(
            tmp_config_dir, READER_ID, GROUP_ID, payload, _SyncKeyServer(published), PEER_A_ID
        )

        advanced = {
            s.sender_agent_id: s.message_index
            for s in load_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID)
        }
        assert advanced == {PEER_A_ID: 1, PEER_B_ID: 0}


class TestMergeOrdering:
    """The position guarantee ``merge_sender_key_states`` states, held to.

    Two rules that pull in opposite directions. A row already on disk is reassigned
    IN PLACE, because reassigning a key already in a dict keeps its position — that
    is what lets a self-read decrypt merge its own advanced state back without
    moving it. A row that is NOT on disk is added, and added means last: for a peer
    that is the merge's whole purpose, and for a row of this agent's OWN it is
    skipped instead, because absent is what a rotation leaves behind and last is
    exactly where :func:`rine._sender_key_ops.get_or_create_sender_key_sync` looks
    for the key to seal the next post under.

    Nothing else in the tree pins either half: a merge rewritten as
    ``[*untouched, *touched]`` — which reads as an equivalent refactor — passes
    every other sender-key suite while moving the state the decrypt was holding to
    the BOTTOM, and the next send then encrypts under the superseded key.
    """

    def test_merge_when_it_touches_an_existing_id_then_that_id_keeps_its_position(
        self, tmp_config_dir
    ):
        """A touched id is reassigned in place, never moved to the end."""
        own_superseded = generate_sender_key(GROUP_ID, READER_ID)
        own_fresh = generate_sender_key(GROUP_ID, READER_ID)
        peer = _reader_view(generate_sender_key(GROUP_ID, PEER_A_ID))
        # The order a rotation leaves: peers, the one state it superseded, then the
        # key the next send is to use.
        save_sender_key_state(
            tmp_config_dir, READER_ID, GROUP_ID, [peer, own_superseded, own_fresh]
        )

        # What a self-read decrypt merges back: its own state, advanced.
        advanced = SenderKeyState(
            sender_key_id=own_fresh.sender_key_id,
            group_id=own_fresh.group_id,
            sender_agent_id=own_fresh.sender_agent_id,
            chain_key=own_fresh.chain_key,
            message_index=own_fresh.message_index + 1,
        )
        merge_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID, [advanced])

        states = load_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID)
        assert [s.sender_key_id for s in states] == [
            peer.sender_key_id,
            own_superseded.sender_key_id,
            own_fresh.sender_key_id,
        ]
        # The consequence the ordering exists for: the send path still picks the
        # fresh key, not the one a rotation superseded.
        last_own = [s for s in states if s.sender_agent_id == READER_ID][-1]
        assert last_own.sender_key_id == own_fresh.sender_key_id
        assert last_own.message_index == own_fresh.message_index + 1

    async def test_own_row_when_a_rotation_drops_it_mid_decrypt_then_the_merge_leaves_it_gone(
        self, tmp_config_dir
    ):
        """A rotation that lands mid-decrypt is not undone by the merge behind it.

        🔴 The merge's asymmetry, driven through the REAL path rather than a
        hand-built array: :func:`rine._crypto.message.decrypt_group_message_async`
        loads inside the lock, goes to the network to verify, and merges its
        pre-network row back afterwards. A rotation runs in that window — on this
        stack literally on another thread, since the send is dispatched with
        ``asyncio.to_thread`` and an ``asyncio.Lock`` cannot exclude a thread — and
        rotations DROP own rows.

        The merge is keyed by id over a dict seeded from disk, so a row that is no
        longer on disk would be INSERTED, and insertion means last. Last is exactly
        where ``_sender_key_ops`` looks for the current key, so the resurrected row
        becomes what the next post is sealed under: a key this agent rotated away
        from, whose recipients were told about a roster that has moved on. Peer rows
        must still be added — that is the merge's whole purpose, and
        ``test_peer_key_when_ingested_during_a_decrypts_verify_then_it_survives``
        above holds it to that.
        """
        keys = generate_agent_keys()
        save_agent_keys(tmp_config_dir, READER_ID, keys)
        own = generate_sender_key(GROUP_ID, READER_ID)
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [own])
        result, _ = encrypt_group_message(
            tmp_config_dir, READER_ID, GROUP_ID, own, {"text": "my own post"}
        )

        # Where two rotations leave the file: each keeps exactly the one own row it
        # superseded, so the second drops ``own`` altogether while the file stays
        # non-empty. The decrypt below is still holding ``own`` — it loaded before
        # either of them landed.
        first = generate_sender_key(GROUP_ID, READER_ID)
        second = generate_sender_key(GROUP_ID, READER_ID)
        rotated: list[bool] = []

        def _rotate_once() -> None:
            if rotated:
                return
            rotated.append(True)
            save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [own, first])
            save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [first, second])

        server = ReverseOrderKeyServer({READER_ID: public_keys_body(keys)}, _rotate_once)

        opened = await decrypt_group_message_async(
            tmp_config_dir, READER_ID, GROUP_ID, result.encrypted_payload, server, READER_ID
        )
        assert json.loads(opened.plaintext) == {"text": "my own post"}
        assert rotated, "the rotation never ran, so the window under test never opened"

        # The rotation's file, unchanged: the retired row is not back, and the row
        # the next send picks is still the one the rotation minted.
        after = load_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID)
        assert [s.sender_key_id for s in after] == [first.sender_key_id, second.sender_key_id]
        assert after[-1].sender_key_id == second.sender_key_id

    def test_merge_when_the_id_is_new_then_it_appends_below_what_was_there(self, tmp_config_dir):
        """A genuinely new id has no position to keep, so it takes the last one."""
        own = generate_sender_key(GROUP_ID, READER_ID)
        save_sender_key_state(tmp_config_dir, READER_ID, GROUP_ID, [own])

        arrived = _reader_view(generate_sender_key(GROUP_ID, PEER_B_ID))
        merge_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID, [arrived])

        states = load_sender_key_states(tmp_config_dir, READER_ID, GROUP_ID)
        assert [s.sender_key_id for s in states] == [own.sender_key_id, arrived.sender_key_id]
