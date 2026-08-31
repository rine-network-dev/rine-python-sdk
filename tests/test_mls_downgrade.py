"""The downgrade guard, Python side.

The four-cell truth table is local MLS state × what the server claims. Only one
cell refuses; the other three are ordinary, and one of them (no local state,
server says not-MLS) is the open billboard group's permanent shape, so the
converse test matters as much as the refusal.

These drive the real ``rine-mls`` core — nothing about the local state is faked —
so a refusal asserted here is the refusal a member would actually get.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import rine
from rine._crypto._key_cache import KeyCache
from rine._crypto.keys import generate_agent_keys, public_keys_body, save_agent_keys
from rine._crypto.message import (
    decrypt_group_message_async,
    decrypt_group_message_sync,
    encrypt_group_message,
)
from rine._crypto.sender_keys import SenderKeyState, generate_sender_key
from rine._crypto.sender_keys_helpers import load_sender_key_states, save_sender_key_state
from rine._mls import group_access
from rine._mls.api import MlsGroupInfo, MlsMemberStatus, MlsWelcomeDelivery
from rine._mls.binding import (
    MlsCoreError,
    MlsStoreError,
    SelfMessageNotCachedError,
    open_mls_client,
)
from rine._mls.downgrade import assert_no_mls_downgrade
from rine._mls.external_join import ExternalJoin, external_join_mls_group
from rine._mls.failures import is_recoverable_mls_failure, is_unprocessable_commit
from rine._mls.group_access import (
    holds_mls_state,
    mls_group_id_bytes,
    note_mls_state_changed,
)
from rine._mls.group_init import init_mls_group
from rine._mls.leave import wipe_mls_state
from rine._mls.welcomes import process_mls_welcomes
from rine.errors import (
    DOWNGRADE_REFUSED_CODE,
    CryptoError,
    MlsDowngradeError,
    NoMlsGroupStateError,
)

SENDER_B = "11111111-1111-1111-1111-111111111111"
READER_V = "22222222-2222-2222-2222-222222222222"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
OTHER_GROUP_ID = "44444444-4444-4444-4444-444444444444"
PAYLOAD = {"announcement": "open enrolment, all welcome"}


class _KeyServer:
    """A stand-in HTTP client that serves one agent's published signing key."""

    def __init__(self, keys) -> None:
        self._keys_cache = KeyCache(600.0, 256)
        self._body = public_keys_body(keys)

    def get(self, _path: str, **_kwargs: object) -> dict:
        return self._body


class _AsyncKeyServer(_KeyServer):
    async def get(self, _path: str, **_kwargs: object) -> dict:  # type: ignore[override]
        return self._body


def _agent(config_dir: str, agent_id: str):
    keys = generate_agent_keys()
    save_agent_keys(config_dir, agent_id, keys)
    return keys


def _plant_mls_state(config_dir: str, agent_id: str, group_id: str = GROUP_ID) -> None:
    """Give this agent real local MLS state for the group, as a Welcome would.

    Including the invalidation the production establisher does at its own
    mutation site — the memo is keyed by config dir, and every test gets a fresh
    one, so nothing else is needed to keep tests independent.
    """
    open_mls_client(config_dir, agent_id).create_group(mls_group_id_bytes(group_id)).save()
    note_mls_state_changed(config_dir, agent_id, group_id)


def _sender_key_row(config_dir: str, payload: object = PAYLOAD) -> tuple[str, object]:
    """One sender-key group row from B, with B's key already ingested by V."""
    sender_keys = _agent(config_dir, SENDER_B)
    state = generate_sender_key(GROUP_ID, SENDER_B)
    save_sender_key_state(
        config_dir,
        READER_V,
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
    sealed, _ = encrypt_group_message(config_dir, SENDER_B, GROUP_ID, state, payload)
    return sealed.encrypted_payload, sender_keys


def _count_store_opens(monkeypatch) -> list[int]:
    """Start counting the native-store opens the memo makes, as a 1-element list.

    The requirement is about the store, not about caching for its own sake:
    the guard runs once per row of a group read, and opening the compiled core
    per row is what it must not do. A ``stat`` of one file is not a store open,
    so counting opens is the requirement stated directly.
    """
    count = [0]
    real_open = group_access.open_mls_client

    def counted(*args, **kwargs):
        count[0] += 1
        return real_open(*args, **kwargs)

    monkeypatch.setattr(group_access, "open_mls_client", counted)
    return count


def _persisted_index(config_dir: str) -> int:
    states = load_sender_key_states(config_dir, READER_V, GROUP_ID)
    return next(s.message_index for s in states if s.sender_agent_id == SENDER_B)


# ---------------------------------------------------------------------------
# The four-cell truth table
# ---------------------------------------------------------------------------


class TestTruthTable:
    """Local MLS state × the server's claim, all four cells."""

    def test_assert_no_mls_downgrade_when_no_state_and_server_says_sender_key_passes(
        self, tmp_config_dir
    ):
        _agent(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

    def test_assert_no_mls_downgrade_when_no_state_and_server_says_mls_passes(
        self, tmp_config_dir
    ):
        _agent(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, True)

    def test_assert_no_mls_downgrade_when_state_and_server_says_mls_passes(self, tmp_config_dir):
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, True)

    def test_assert_no_mls_downgrade_when_state_and_server_says_sender_key_refuses(
        self, tmp_config_dir
    ):
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)

        with pytest.raises(MlsDowngradeError) as caught:
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        assert caught.value.code == DOWNGRADE_REFUSED_CODE
        assert caught.value.group_id == GROUP_ID

    def test_assert_no_mls_downgrade_when_state_is_another_groups_passes(self, tmp_config_dir):
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, OTHER_GROUP_ID, False)

    def test_assert_no_mls_downgrade_when_asked_repeatedly_opens_the_store_once(
        self, tmp_config_dir, monkeypatch
    ):
        """The memo is what keeps a group read off the MLS store per row.

        A group read asks the guard once per row, so the store open has to be
        amortised across the whole page. What keeps the memo honest is
        invalidation at the mutation plus the on-disk stamp, covered by
        ``TestMemoAcrossAStateChange`` and ``TestMemoUnderConcurrency`` below.
        """
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)
        opens = _count_store_opens(monkeypatch)

        for _ in range(20):
            with pytest.raises(MlsDowngradeError):
                assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        assert opens == [1]

    def test_assert_no_mls_downgrade_when_a_billboard_row_repeats_opens_the_store_once(
        self, tmp_config_dir, monkeypatch
    ):
        """The hot path: an open-enrolment group holds no state, every row asks."""
        _agent(tmp_config_dir, READER_V)
        opens = _count_store_opens(monkeypatch)

        for _ in range(20):
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        assert opens == [1]


# ---------------------------------------------------------------------------
# Outside the MLS recoverable taxonomy
# ---------------------------------------------------------------------------


class TestClassification:
    """The refusal must survive the retry loops, so it is not an MLS failure."""

    def test_downgrade_error_when_classified_is_not_a_recoverable_mls_failure(self):
        assert is_recoverable_mls_failure(MlsDowngradeError(GROUP_ID)) is False

    def test_downgrade_error_when_classified_is_not_an_unprocessable_commit(self):
        # An unprocessable commit earns a NACK. A downgrade refusal reaching
        # that path would roll back a commit and then be retried away.
        assert is_unprocessable_commit(MlsDowngradeError(GROUP_ID)) is False

    def test_downgrade_error_when_classified_branches_on_class_not_on_a_code_prefix(self):
        # The Python taxonomy branches on classes, which is why the code needs
        # no namespace trick — but the control matters: the predicates DO say
        # yes to the core's own failures.
        assert issubclass(MlsDowngradeError, CryptoError)
        assert not issubclass(MlsDowngradeError, MlsCoreError)
        assert is_recoverable_mls_failure(NoMlsGroupStateError(GROUP_ID)) is True
        assert is_unprocessable_commit(SelfMessageNotCachedError("cold")) is True
        assert is_unprocessable_commit(MlsStoreError("disk")) is False

    def test_downgrade_error_when_read_for_a_code_is_outside_the_mls_namespace(self):
        # Callers branch on the code, never on the message: a refusal recognised
        # by its text stops being recognised the moment the text is reworded.
        assert DOWNGRADE_REFUSED_CODE == "RINE_DOWNGRADE_REFUSED"
        assert not DOWNGRADE_REFUSED_CODE.startswith("RINE_MLS_")
        assert MlsDowngradeError(GROUP_ID).code == DOWNGRADE_REFUSED_CODE

    def test_downgrade_error_when_raised_carries_the_group_id_as_a_field(self):
        """A caller reads the group off the error, never back out of its text."""
        err = MlsDowngradeError(GROUP_ID)
        assert err.group_id == GROUP_ID
        assert GROUP_ID in str(err)


# ---------------------------------------------------------------------------
# The read path, both clients
# ---------------------------------------------------------------------------


class TestGroupRead:
    """One decision point, shared by the sync and async group decrypts."""

    def test_decrypt_group_message_when_open_billboard_group_has_no_mls_state_decrypts(
        self, tmp_config_dir
    ):
        """The converse: a billboard group holds no MLS state and keeps reading."""
        _agent(tmp_config_dir, READER_V)
        payload, sender_keys = _sender_key_row(tmp_config_dir)

        result = decrypt_group_message_sync(
            tmp_config_dir, READER_V, GROUP_ID, payload, _KeyServer(sender_keys), SENDER_B
        )

        assert json.loads(result.plaintext) == PAYLOAD
        assert result.verification_status == "verified"

    async def test_decrypt_group_message_async_when_no_mls_state_decrypts(self, tmp_config_dir):
        _agent(tmp_config_dir, READER_V)
        payload, sender_keys = _sender_key_row(tmp_config_dir)

        result = await decrypt_group_message_async(
            tmp_config_dir, READER_V, GROUP_ID, payload, _AsyncKeyServer(sender_keys), SENDER_B
        )

        assert json.loads(result.plaintext) == PAYLOAD

    def test_decrypt_group_message_when_sender_key_row_and_local_mls_state_refuses(
        self, tmp_config_dir
    ):
        _agent(tmp_config_dir, READER_V)
        payload, sender_keys = _sender_key_row(tmp_config_dir)
        _plant_mls_state(tmp_config_dir, READER_V)
        before = _persisted_index(tmp_config_dir)

        with pytest.raises(MlsDowngradeError) as caught:
            decrypt_group_message_sync(
                tmp_config_dir, READER_V, GROUP_ID, payload, _KeyServer(sender_keys), SENDER_B
            )

        assert caught.value.code == DOWNGRADE_REFUSED_CODE
        # The refusal lands before the ratchet is touched: nothing was consumed.
        assert _persisted_index(tmp_config_dir) == before

    async def test_decrypt_group_message_async_when_local_mls_state_refuses(self, tmp_config_dir):
        _agent(tmp_config_dir, READER_V)
        payload, sender_keys = _sender_key_row(tmp_config_dir)
        _plant_mls_state(tmp_config_dir, READER_V)
        before = _persisted_index(tmp_config_dir)

        with pytest.raises(MlsDowngradeError):
            await decrypt_group_message_async(
                tmp_config_dir,
                READER_V,
                GROUP_ID,
                payload,
                _AsyncKeyServer(sender_keys),
                SENDER_B,
            )

        assert _persisted_index(tmp_config_dir) == before

    def test_decrypt_group_message_when_mls_state_is_another_groups_still_decrypts(
        self, tmp_config_dir
    ):
        _agent(tmp_config_dir, READER_V)
        payload, sender_keys = _sender_key_row(tmp_config_dir)
        _plant_mls_state(tmp_config_dir, READER_V, OTHER_GROUP_ID)

        result = decrypt_group_message_sync(
            tmp_config_dir, READER_V, GROUP_ID, payload, _KeyServer(sender_keys), SENDER_B
        )

        assert json.loads(result.plaintext) == PAYLOAD


# ---------------------------------------------------------------------------
# The memo, across a state change in ONE process
# ---------------------------------------------------------------------------


def _patch(monkeypatch, module_path: str, **replacements) -> None:
    for name, value in replacements.items():
        monkeypatch.setattr(f"{module_path}.{name}", value)


def _peer_group(tmp_path, key_packages: list[bytes]):
    """A real group founded by a peer, optionally admitting the given KeyPackages."""
    peer_dir = str(tmp_path / "peer")
    save_agent_keys(peer_dir, SENDER_B, generate_agent_keys())
    group = open_mls_client(peer_dir, SENDER_B).create_group_with_members(
        mls_group_id_bytes(GROUP_ID), key_packages
    )
    group.save()
    return group


def _join_by_welcome(monkeypatch, config_dir: str, agent_id: str, tmp_path) -> None:
    """Drive the real Welcome establisher, with only the server stubbed out."""
    key_package = open_mls_client(config_dir, agent_id).generate_key_package()
    group = _peer_group(tmp_path, [key_package])
    delivery = MlsWelcomeDelivery(
        id="77777777-8888-9999-aaaa-bbbbbbbbbbbb",
        group_id=GROUP_ID,
        welcome=group.last_commit().welcomes[0],
    )
    _patch(
        monkeypatch,
        "rine._mls.welcomes",
        fetch_welcomes=lambda *_a: [delivery],
        replenish_mls_key_packages=lambda *_a: None,
    )
    assert process_mls_welcomes(None, config_dir, agent_id).group_ids == (GROUP_ID,)


class TestMemoAcrossAStateChange:
    """A memo that is never invalidated cannot be caught by a fresh-process test.

    Every test here mutates local MLS state through a REAL establisher or the
    real retirement, then re-asks the guard in the SAME process.
    """

    def test_guard_refuses_a_sender_key_row_after_the_agent_joins_mls_in_the_same_process(
        self, tmp_config_dir, tmp_path, monkeypatch
    ):
        _agent(tmp_config_dir, READER_V)
        # The read that remembers "this agent holds none" — before the join.
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        _join_by_welcome(monkeypatch, tmp_config_dir, READER_V, tmp_path)

        with pytest.raises(MlsDowngradeError):
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

    def test_guard_refuses_a_sender_key_row_after_founding_the_group_in_the_same_process(
        self, tmp_config_dir, monkeypatch
    ):
        _agent(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        _patch(
            monkeypatch,
            "rine._mls.group_init",
            replenish_mls_key_packages=lambda *_a: None,
            mls_init=lambda *_a: [MlsMemberStatus(agent_id=READER_V, has_key_package=True)],
        )
        # Founding creates the native state inside the shared admission loop, so
        # that is where the commit is published from and where it is stubbed.
        _patch(monkeypatch, "rine._mls.admission_state", mls_commit=lambda *_a: 1)
        init_mls_group(None, tmp_config_dir, READER_V, GROUP_ID, {})

        with pytest.raises(MlsDowngradeError):
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

    def test_guard_refuses_a_sender_key_row_after_an_external_join_in_the_same_process(
        self, tmp_config_dir, tmp_path, monkeypatch
    ):
        _agent(tmp_config_dir, READER_V)
        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        group = _peer_group(tmp_path, [])
        _patch(
            monkeypatch,
            "rine._mls.external_join",
            fetch_group_info=lambda *_a: MlsGroupInfo(blob=group.group_info(), epoch=1),
            mls_commit=lambda *_a: 2,
        )
        external_join_mls_group(
            ExternalJoin(
                client=None,
                config_dir=tmp_config_dir,
                agent_id=READER_V,
                group_id=GROUP_ID,
                extra_headers={},
            )
        )

        with pytest.raises(MlsDowngradeError):
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

    def test_guard_allows_a_billboard_read_after_the_agent_leaves_in_the_same_process(
        self, tmp_config_dir, tmp_path, monkeypatch
    ):
        _agent(tmp_config_dir, READER_V)
        _join_by_welcome(monkeypatch, tmp_config_dir, READER_V, tmp_path)
        # The read that remembers "this agent holds state" — before the leave.
        with pytest.raises(MlsDowngradeError):
            assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)

        wipe_mls_state(tmp_config_dir, READER_V, GROUP_ID)

        assert_no_mls_downgrade(tmp_config_dir, READER_V, GROUP_ID, False)


# ---------------------------------------------------------------------------
# The memo under concurrency: another thread, and another process
# ---------------------------------------------------------------------------


def _plant_mls_state_unnoticed(config_dir: str, agent_id: str, group_id: str = GROUP_ID) -> None:
    """Establish real state the way ANOTHER PROCESS would — without invalidating.

    ``note_mls_state_changed`` is an in-process call, so a join performed by
    ``rine`` on the command line while an MCP server holds the same config dir
    reaches that server only through the store on disk. Modelling it means
    writing the state and deliberately NOT invalidating.
    """
    open_mls_client(config_dir, agent_id).create_group(mls_group_id_bytes(group_id)).save()


def _retire_mls_state_unnoticed(config_dir: str, agent_id: str) -> None:
    """The converse: another process left the group and retired its state."""
    shutil.rmtree(Path(config_dir) / "keys" / agent_id / "mls2" / "groups")


class TestMemoUnderConcurrency:
    """The memo has to survive a mutation it was never told about.

    Two of those are real: another OS thread in this process racing between the
    memo's store read and its write-back, and another process (``rine-cli`` next
    to a long-running ``rine-mcp`` on the same config dir) mutating the store
    with no way to reach this process's map at all. Both fail OPEN — a
    remembered "holds none" is what stops the downgrade guard firing.
    """

    def test_holds_mls_state_when_another_process_establishes_state_stops_answering_no(
        self, tmp_config_dir
    ):
        """The security direction: a stale "holds none" is a guard that never fires."""
        _agent(tmp_config_dir, READER_V)
        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is False

        _plant_mls_state_unnoticed(tmp_config_dir, READER_V)

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is True

    def test_holds_mls_state_when_another_process_retires_state_stops_answering_yes(
        self, tmp_config_dir
    ):
        """The annoyance direction: a stale "holds" refuses a legitimate billboard read."""
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)
        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is True

        _retire_mls_state_unnoticed(tmp_config_dir, READER_V)

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is False

    def test_holds_mls_state_when_a_join_lands_during_the_store_read_keeps_no_stale_answer(
        self, tmp_config_dir, monkeypatch
    ):
        """The read-then-write window, made deterministic.

        A join completing between the store read and the write-back invalidates
        the memo — and then the write-back re-inserts the very answer the
        invalidation removed. Returning ``False`` from the in-flight call is a
        legitimate linearisation; *keeping* it is the defect, and it lasts for
        the life of the process.
        """
        _agent(tmp_config_dir, READER_V)
        real_load = group_access.load_mls_group
        raced: list[bool] = []

        def load_then_join(client, group_id):
            answer = real_load(client, group_id)
            if not raced:
                raced.append(True)
                # The concurrent join completes HERE: state established and the
                # memo invalidated, before this call reaches its write-back.
                _plant_mls_state(tmp_config_dir, READER_V, group_id)
            return answer

        monkeypatch.setattr(group_access, "load_mls_group", load_then_join)

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is False
        assert raced == [True]

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is True

    def test_holds_mls_state_when_a_leave_lands_during_the_store_read_keeps_no_stale_answer(
        self, tmp_config_dir, monkeypatch
    ):
        """The same window in the other direction: a stale refusal, forever."""
        _agent(tmp_config_dir, READER_V)
        _plant_mls_state(tmp_config_dir, READER_V)
        real_load = group_access.load_mls_group
        raced: list[bool] = []

        def load_then_leave(client, group_id):
            answer = real_load(client, group_id)
            if not raced:
                raced.append(True)
                wipe_mls_state(tmp_config_dir, READER_V, group_id)
            return answer

        monkeypatch.setattr(group_access, "load_mls_group", load_then_leave)

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is True
        assert raced == [True]

        assert holds_mls_state(tmp_config_dir, READER_V, GROUP_ID) is False


# ---------------------------------------------------------------------------
# The invalidation contract, enforced instead of remembered
# ---------------------------------------------------------------------------

#: Native ``MlsClient``/``MlsGroup`` calls that create or destroy local group state.
_STATE_MUTATORS = (
    ".create_group(",
    ".create_group_with_members(",
    ".join_from_welcome(",
    ".join_by_external_commit(",
    ".delete_group_state(",
)

_INVALIDATOR = "note_mls_state_changed"

_SRC_ROOT = Path(rine.__file__).parent


def _mutating_modules() -> dict[str, bool]:
    """Every module under ``rine/`` that mutates the native store → does it invalidate."""
    found = {}
    for path in sorted(_SRC_ROOT.rglob("*.py")):
        body = path.read_text()
        if any(call in body for call in _STATE_MUTATORS):
            found[str(path.relative_to(_SRC_ROOT))] = _INVALIDATOR in body
    return found


class TestEveryMlsStateWriterInvalidatesTheMemo:
    """The memo is sound only while every writer invalidates AT the mutation.

    That cannot be expressed in the type system — establishment and retirement
    are methods on the native client, and a new call site that forgets to
    invalidate fails OPEN, silently, and only in a long-running process. So it is
    asserted over the source: a module that mutates the native store must also
    name the invalidator. The TypeScript mirror is
    ``rine-core/test/crypto/mls-state-writers.test.ts``.
    """

    def test_source_scan_when_a_module_mutates_native_mls_state_it_names_the_invalidator(self):
        assert [name for name, ok in _mutating_modules().items() if not ok] == []

    def test_source_scan_when_run_finds_the_known_mutating_modules(self):
        # Guards the scan itself: a pattern that stopped matching anything would
        # make the test above pass vacuously.
        assert sorted(_mutating_modules()) == [
            "_mls/admission_state.py",
            "_mls/external_join.py",
            "_mls/leave.py",
            "_mls/welcomes.py",
        ]
