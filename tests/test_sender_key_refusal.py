"""Explain the sender-key refusal once per render, then mark — claiming only what was found out.

A render that carries N rows used to say ``[unavailable]`` on every one of them
(``thread()``) or spend the whole four-clause paragraph on every one of them
(the connectors, through ``decrypt_error``). Neither is what an agent needs: the
first is a cause-free nothing, the second is the same 600 characters bought once
per row.

These tests pin the middle: the first row with this cause explains it, every
later row in the SAME render marks it, and a fresh render explains again. That
last one is the whole reason the state is an instance — a module-level flag
passes every test that renders once and fails silently in production, where a
client renders for hours.

They also pin WHICH explanation each surface has earned. ``inbox()``,
``read()`` and ``thread()`` ingest every pending distribution and retry before
they refuse, so they state the verdict and stamp ``decrypt_error_code`` —
``thread()`` buying **one** scan for the whole transcript rather than one per
row, which is all a scan that ingests everything could ever be worth.
``get_conversation_messages()`` hands its rows to a caller's own renderer and
fetches nothing on their behalf, so it says that it did not look and stamps
nothing.

That split is the point of the two sentences, and the tests that hold it are
symmetrical: a transcript with a distribution waiting for it **opens the row**
(``TestThreadRecoversTheKey``), the same transcript with nothing waiting states
the verdict it has now earned (``TestThreadEarnsItsRefusal``), and the reader
that never looks says so on both (``TestConversationMessagesFetchNothing``).

The TypeScript twin is ``rine-core/src/sender-key-words.ts`` and the render it
feeds is ``rine-core/src/crypto/thread-row.ts``, which calls
``decryptGroupMessageWithRecovery`` (``rine-core/src/sender-key-recovery.ts``) —
the behaviour ``thread()`` mirrors here. ⚠️ Mirrors the RECOVERY, not its bound:
that render is a ``Promise.all`` and scans per failing row, where ``thread()``
scans once per transcript (:mod:`rine._render_recovery`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import UUID

import httpx
import pytest
import respx

from rine._constants import MessageType
from rine._thread import UNAVAILABLE, to_thread_entry
from rine.errors import (
    SENDER_KEY_UNAVAILABLE_CODE,
    CryptoError,
    NoSenderKeyStateError,
    SenderMismatchError,
)
from rine.sender_key_words import (
    SENDER_KEY_NOT_RECOVERED_PREVIEW,
    SENDER_KEY_UNAVAILABLE_PREVIEW,
    SINGLE_MESSAGE_READ_REMEDY,
    SenderKeyRefusal,
    no_sender_key_state_detail,
    sender_key_not_recovered_detail,
)
from rine.types import DecryptedMessage

API = "https://rine.network"
KEY_ID = "77777777-8888-9999-aaaa-bbbbbbbbbbbb"
SECOND_KEY_ID = "66666666-5555-4444-3333-222222222222"
TS_WORDS = Path(__file__).parents[2] / "rine-core" / "src" / "sender-key-words.ts"


def _not_recovered_shape(text: str) -> UUID:
    """Assert ``text`` IS the un-earned sentence, and return the key it names.

    Byte-exact on everything but the id, which the fixture mints per run: the
    sentence is split on a placeholder rather than matched by a phrase, so a
    reworded clause fails here instead of passing a ``in`` check.
    """
    head, _, tail = sender_key_not_recovered_detail("<KEY>").partition("<KEY>")
    assert text.startswith(head), text
    assert text.endswith(tail), text
    return UUID(text[len(head) : len(text) - len(tail)])


def _earned_shape(text: str) -> UUID:
    """Assert ``text`` IS the earned verdict, and return the key it names.

    The twin of :func:`_not_recovered_shape`, so the two contracts are asserted
    by the same kind of check and neither can drift into the other's wording.
    """
    head, _, tail = no_sender_key_state_detail("<KEY>").partition("<KEY>")
    assert text.startswith(head), text
    assert text.endswith(tail), text
    return UUID(text[len(head) : len(text) - len(tail)])


def _refused_row(message_id: str, sender_key_id: str = KEY_ID) -> DecryptedMessage:
    """A row that came back from the degrade unopened for want of a sender key."""
    msg = DecryptedMessage(
        id=message_id,
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="opaque",
        encryption_version="sender-key-v1",
        created_at="2024-01-01T00:00:00Z",
        direction="received",
    )
    msg.decrypt_error = no_sender_key_state_detail(sender_key_id)
    msg.decrypt_error_code = SENDER_KEY_UNAVAILABLE_CODE
    return msg


def _other_failure_row(message_id: str) -> DecryptedMessage:
    """A row that failed for a cause this refusal has nothing to say about."""
    msg = DecryptedMessage(
        id=message_id,
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="opaque",
        encryption_version="hpke-v1",
        created_at="2024-01-01T00:00:00Z",
        direction="received",
    )
    msg.decrypt_error = "Message key expired or already consumed"
    return msg


CONVERSATION_ID = "cccccccc-dddd-eeee-ffff-000000000103"


def _mock_identity_routes(agent_id: str) -> None:
    """The token and the org's agent list — what every client call asks for first."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": agent_id,
                        "name": "test-agent",
                        "handle": "test-agent@myorg.rine.network",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _mock_empty_distribution_scan(agent_id: str) -> respx.Route:
    """The pending-distribution listing, answering that nothing is waiting.

    ⚠️ Register it BEFORE any unfiltered ``/agents/{id}/messages`` route: respx
    matches in registration order and both share that path, so an inbox page
    registered first would be served to the scan.
    """
    return respx.get(
        f"{API}/agents/{agent_id}/messages",
        params={"type": MessageType.SENDER_KEY_DISTRIBUTION},
    ).mock(return_value=httpx.Response(200, json={"items": []}))


def _distribution_scans() -> list[httpx.Request]:
    """Every request this test made to the pending-distribution listing.

    Counted off the recorded calls rather than a route's ``call_count`` so a
    test can assert the bound against routes it did not register itself — the
    shared ``mock_group_message_routes`` fixture hands back no route objects.
    """
    return [
        call.request
        for call in respx.calls
        if call.request.url.params.get("type") == MessageType.SENDER_KEY_DISTRIBUTION
    ]


def _mock_conversation(rows: list[dict]) -> None:
    """The transcript route both readers fetch."""
    respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": rows, "truncated": False})
    )


def _group_rows(fixture, count: int) -> list[dict]:
    """``count`` received copies of the fixture's group row, distinctly identified.

    One ciphertext across all of them, which is what a transcript of one
    sender's posts looks like to a reader opening them in order: the ratchet
    spends the message key at the first decrypt and the group read cache answers
    every repeat (``_crypto/message.py::_replayed_envelope``).
    """
    rows = []
    for index in range(1, count + 1):
        row = dict(fixture.message_row)
        row["id"] = f"11111111-0000-0000-0000-00000000000{index}"
        row["conversation_id"] = CONVERSATION_ID
        row["direction"] = "received"
        rows.append(row)
    return rows


def _malformed_mls_row(message_id: str, sender_id: str) -> dict:
    """An ``mls-v1`` row naming no group — a group failure a scan cannot help with.

    ``decrypt_mls_group_message`` refuses it before it touches MLS state or the
    network (*"names no group, so there is no MLS state to open it with"*),
    which makes it the deterministic stand-in for every non-sender-key cause. A
    group that cut over from Sender Keys to MLS carries both kinds of row in one
    transcript, so this is the shape the render's budget guard exists for.
    """
    return {
        "id": message_id,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": sender_id,
        "type": "rine.v1.task_request",
        "encrypted_payload": "opaque",
        "encryption_version": "mls-v1",
        "created_at": "2024-01-01T00:00:00Z",
        "direction": "received",
    }


# ---------------------------------------------------------------------------
# The bounded marker, and its twin on the other stack
# ---------------------------------------------------------------------------


def test_preview_when_read_beside_the_typescript_twin_then_the_two_stacks_agree():
    """One spelling of the refusal, pinned rather than assumed.

    Nothing else binds these two files — no server half states this sentence, so
    a reader meeting the marker on hermes and then on the CLI is the only thing
    that would ever notice a drift.
    """
    if not TS_WORDS.is_file():  # pragma: no cover - rine-core not checked out
        return
    assert f'"{SENDER_KEY_UNAVAILABLE_PREVIEW}"' in TS_WORDS.read_text()


def test_unearned_words_when_read_beside_the_typescript_twin_then_the_two_stacks_agree():
    """The un-earned marker and its remedy, pinned the same way.

    Two spellings of "nothing went looking" — one met on an MCP inbox page, the
    next on a Python transcript — is the drift this asserts against, and nothing
    else in either tree would notice it.
    """
    if not TS_WORDS.is_file():  # pragma: no cover - rine-core not checked out
        return
    source = TS_WORDS.read_text()
    assert f'"{SENDER_KEY_NOT_RECOVERED_PREVIEW}"' in source
    assert f'"{SINGLE_MESSAGE_READ_REMEDY}"' in source


def test_unearned_sentence_when_composed_beside_the_typescript_twin_then_it_is_byte_identical():
    """The whole sentence, not just its constants.

    Rebuilt from the literals ``senderKeyNotRecoveredMessage`` concatenates, so
    a clause reworded on either stack fails here — the constants can agree while
    the sentences they are joined into do not. The remedy substituted is
    ``SINGLE_MESSAGE_READ_REMEDY`` because that is the only one true on this
    stack: ``RECOVERY_LEFT_ON_REMEDY`` names ``retrySenderKey``, a switch no
    Python surface exposes.
    """
    if not TS_WORDS.is_file():  # pragma: no cover - rine-core not checked out
        return
    body = TS_WORDS.read_text().split("export function senderKeyNotRecoveredMessage(")[1]
    literals = re.findall(r"\"([^\"]*)\"|`([^`]*)`", body.split("\n}")[0])
    composed = (
        "".join(double or backtick for double, backtick in literals)
        .replace("${senderKeyId}", KEY_ID)
        .replace("${remedy}", SINGLE_MESSAGE_READ_REMEDY)
    )

    assert composed == sender_key_not_recovered_detail(KEY_ID)


def test_preview_when_rendered_then_it_names_no_key_no_group_and_no_agent():
    """The repeated marker is byte-identical across rows.

    It is printed once per unopenable row, so anything it carried about the row
    would let a reader count distinct keys off a transcript. The id rides on the
    once-per-render sentence instead.
    """
    first = SenderKeyRefusal()
    second = SenderKeyRefusal()
    first.text_for(_refused_row("11111111-0000-0000-0000-000000000001"))
    second.text_for(_refused_row("11111111-0000-0000-0000-000000000002", SECOND_KEY_ID))

    marks = [
        first.text_for(_refused_row("11111111-0000-0000-0000-000000000003")),
        second.text_for(_refused_row("11111111-0000-0000-0000-000000000004", SECOND_KEY_ID)),
    ]

    assert marks == [SENDER_KEY_UNAVAILABLE_PREVIEW, SENDER_KEY_UNAVAILABLE_PREVIEW]
    assert KEY_ID not in SENDER_KEY_UNAVAILABLE_PREVIEW
    assert SECOND_KEY_ID not in SENDER_KEY_UNAVAILABLE_PREVIEW


# ---------------------------------------------------------------------------
# The helper: explain once, then mark
# ---------------------------------------------------------------------------


def test_text_for_when_the_first_row_lacks_a_sender_key_then_the_whole_refusal_is_read():
    """The cause is stated in full on the row that first carries it."""
    refusal = SenderKeyRefusal()

    text = refusal.text_for(_refused_row("11111111-0000-0000-0000-000000000001"))

    assert text == no_sender_key_state_detail(KEY_ID)


def test_text_for_when_a_later_row_lacks_a_sender_key_then_only_the_marker_repeats():
    """The explanation is bought once per render, not once per row."""
    refusal = SenderKeyRefusal()
    refusal.text_for(_refused_row("11111111-0000-0000-0000-000000000001"))

    later = [
        refusal.text_for(_refused_row("11111111-0000-0000-0000-000000000002")),
        refusal.text_for(_refused_row("11111111-0000-0000-0000-000000000003")),
    ]

    assert later == [SENDER_KEY_UNAVAILABLE_PREVIEW, SENDER_KEY_UNAVAILABLE_PREVIEW]


def test_text_for_when_a_new_render_starts_then_the_refusal_is_explained_again():
    """🔴 The state is per render, and this is the test that says so.

    A module-level "already explained" flag renders identically to this design
    on a single render and diverges here — the second transcript an operator
    reads would carry a marker whose explanation appeared in the first one,
    minutes ago, in another conversation.
    """
    first_render = SenderKeyRefusal()
    first_render.text_for(_refused_row("11111111-0000-0000-0000-000000000001"))

    second_render = SenderKeyRefusal()
    text = second_render.text_for(_refused_row("11111111-0000-0000-0000-000000000002"))

    assert text == no_sender_key_state_detail(KEY_ID)


def test_text_for_when_the_row_failed_for_another_cause_then_nothing_is_claimed():
    """Scoped to one cause: another failure is the caller's to render."""
    refusal = SenderKeyRefusal()

    assert refusal.text_for(_other_failure_row("11111111-0000-0000-0000-000000000001")) is None


def test_text_for_when_another_cause_came_first_then_it_did_not_spend_the_explanation():
    """ "Explained" pools per cause, never per render-with-any-failure."""
    refusal = SenderKeyRefusal()
    refusal.text_for(_other_failure_row("11111111-0000-0000-0000-000000000001"))

    text = refusal.text_for(_refused_row("11111111-0000-0000-0000-000000000002"))

    assert text == no_sender_key_state_detail(KEY_ID)


def test_text_for_when_the_row_opened_cleanly_then_nothing_is_claimed():
    """A decrypted row carries no cause code and is not this class's business."""
    msg = DecryptedMessage(
        id="11111111-0000-0000-0000-000000000001",
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="opaque",
        encryption_version="sender-key-v1",
        created_at="2024-01-01T00:00:00Z",
        direction="received",
    )
    msg.plaintext = json.dumps({"text": "hello group"})

    assert SenderKeyRefusal().text_for(msg) is None


# ---------------------------------------------------------------------------
# The typed cause: written from the exception, never inferred from the words
# ---------------------------------------------------------------------------


class TestDecryptErrorCode:
    """``decrypt_error_code`` is what a renderer branches on."""

    def test_degrade_when_no_sender_key_state_then_the_cause_is_typed_on_the_row(
        self, sync_client
    ):
        """The connectors read a field, not a paragraph."""
        msg = _other_failure_row("11111111-0000-0000-0000-000000000001")
        msg.decrypt_error = None

        degraded = sync_client._apply_decrypt_failure(
            msg, NoSenderKeyStateError(no_sender_key_state_detail(KEY_ID), KEY_ID)
        )

        assert degraded.decrypt_error_code == SENDER_KEY_UNAVAILABLE_CODE
        assert degraded.decrypt_error == no_sender_key_state_detail(KEY_ID)

    def test_degrade_when_no_recovery_ran_then_no_verdict_is_claimed(self, sync_client):
        """The seam the un-earned refusal hangs on.

        The choke point classifies the cause; only the caller knows whether it
        gave the recovery a turn. Handed that fact, it writes the weaker
        sentence and stamps nothing — a code here would be a verdict on a
        distribution nobody went looking for.
        """
        msg = _other_failure_row("11111111-0000-0000-0000-000000000001")
        msg.decrypt_error = None

        degraded = sync_client._apply_decrypt_failure(
            msg,
            NoSenderKeyStateError(no_sender_key_state_detail(KEY_ID), KEY_ID),
            no_recovery=SenderKeyRefusal(),
        )

        assert degraded.decrypt_error == sender_key_not_recovered_detail(KEY_ID)
        assert degraded.decrypt_error_code is None

    def test_degrade_when_no_recovery_ran_then_another_cause_is_untouched(self, sync_client):
        """Only this cause is re-said. Every other failure degrades as it always did."""
        msg = _other_failure_row("11111111-0000-0000-0000-000000000001")

        degraded = sync_client._apply_decrypt_failure(
            msg, SenderMismatchError("Signed by another agent"), no_recovery=SenderKeyRefusal()
        )

        assert degraded.decrypt_error == "Signed by another agent"
        assert degraded.verification_status == "sender-mismatch"

    @pytest.mark.parametrize(
        "error",
        [
            CryptoError("Message key expired or already consumed"),
            SenderMismatchError("Signed by another agent"),
            ValueError("something else entirely"),
        ],
    )
    def test_degrade_when_any_other_failure_then_no_cause_is_claimed(self, sync_client, error):
        """A code that meant "some failure" would tell a renderer nothing."""
        msg = _other_failure_row("11111111-0000-0000-0000-000000000001")

        degraded = sync_client._apply_decrypt_failure(msg, error)

        assert degraded.decrypt_error_code is None


# ---------------------------------------------------------------------------
# The render this lane owns: thread()
# ---------------------------------------------------------------------------


def test_thread_entry_when_the_row_failed_for_another_cause_then_it_stays_unavailable():
    """Only the cause with a move for the operator to make gains a sentence."""
    entry = to_thread_entry(
        _other_failure_row("11111111-0000-0000-0000-000000000001"), SenderKeyRefusal()
    )

    assert entry.text == UNAVAILABLE


def test_earned_rows_when_rendered_one_by_one_then_the_first_one_explains():
    """Rows that earned the verdict state the cause once and mark the rest.

    These are ``inbox()``/``read()`` rows — the ones carrying the code — handed
    to the renderer by a caller of its own. ``thread()`` cannot produce them: it
    runs no recovery, so its rows carry no code and are recognised by the
    refusal that decrypted them instead.
    """
    refusal = SenderKeyRefusal()
    rows = [
        _refused_row("11111111-0000-0000-0000-000000000001"),
        _refused_row("11111111-0000-0000-0000-000000000002"),
        _refused_row("11111111-0000-0000-0000-000000000003"),
    ]

    texts = [to_thread_entry(row, refusal).text for row in rows]

    assert texts[0] == no_sender_key_state_detail(KEY_ID)
    assert texts[1:] == [SENDER_KEY_UNAVAILABLE_PREVIEW, SENDER_KEY_UNAVAILABLE_PREVIEW]
    assert UNAVAILABLE not in texts


def test_text_for_when_a_conversation_row_meets_a_fresh_refusal_then_it_declines():
    """A ``get_conversation_messages()`` row is not a fresh refusal's to tier.

    It carries no code — nothing went looking, so there is no verdict to stamp —
    and a refusal that did not decrypt it holds no record of it. So ``text_for``
    answers ``None`` and the caller prints the row's own ``decrypt_error``,
    which is the whole sentence. Tiering that list is ``thread()``'s job: it is
    the render that hands one refusal to the decrypt and to the print.
    """
    row = _refused_row("11111111-0000-0000-0000-000000000009")
    row.decrypt_error = sender_key_not_recovered_detail(KEY_ID)  # what that decrypt writes
    row.decrypt_error_code = None  # ...and the code it does not stamp

    assert SenderKeyRefusal().text_for(row) is None
    assert row.decrypt_error == sender_key_not_recovered_detail(KEY_ID)


class TestSingleMessageTier:
    """One message asked about is one full sentence, and no marker.

    The tier is chosen by how many messages the caller asked for, never by which
    package renders — so ``read()`` says the whole thing even though ``thread()``
    over the same row would mark it. Repetition is impossible here, and the
    marker's promise ("the full sentence is one read away") is only true while
    this holds.
    """

    @respx.mock
    async def test_read_when_no_distribution_arrives_then_the_whole_refusal_is_returned(
        self, async_client, group_message_fixture, agent_id
    ):
        """The self-heal ingested nothing, so the answer is final and says so."""
        fixture = group_message_fixture
        _mock_identity_routes(agent_id)
        _mock_empty_distribution_scan(agent_id)
        respx.get(f"{API}/messages/{fixture.message_id}").mock(
            return_value=httpx.Response(200, json=fixture.message_row)
        )

        msg = await async_client.read(fixture.message_id)

        assert msg.plaintext is None
        assert msg.decrypt_error is not None
        assert msg.decrypt_error.startswith("Refusing to open a group message")
        assert msg.decrypt_error_code == SENDER_KEY_UNAVAILABLE_CODE
        assert SENDER_KEY_UNAVAILABLE_PREVIEW not in msg.decrypt_error
        assert SenderKeyRefusal().text_for(msg) == msg.decrypt_error
        await async_client.close()


class TestConversationMessagesFetchNothing:
    """The one reader that never goes looking — and the sentence that says so.

    ``get_conversation_messages()`` hands rows back for a caller's own renderer,
    and a caller cannot be charged for a fetch it did not ask for. So the
    un-earned refusal is still printed by a live public method, and it is still
    true of it: no code on the row, no claim about what is waiting on the
    server.
    """

    @respx.mock
    async def test_conversation_messages_when_the_key_never_arrived_then_no_verdict_is_claimed(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """🔴 The row a connector renders from carries the sentence and NO code.

        This read never ran the recovery, so there is no verdict to record:
        ``decrypt_error_code`` is what a connector branches on, and branching on
        it here would treat a state the next ``read()`` repairs as final. The
        sentence is complete on every row — the data says the whole thing and
        the *render* is what gets tiered.
        """
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 2))

        messages = await async_client.get_conversation_messages(CONVERSATION_ID)

        assert [m.decrypt_error_code for m in messages] == [None, None]
        assert [_not_recovered_shape(m.decrypt_error) for m in messages] == [
            _not_recovered_shape(messages[0].decrypt_error)
        ] * 2
        await async_client.close()

    @respx.mock
    async def test_conversation_messages_when_a_distribution_waits_then_it_is_never_fetched(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """The claim the sentence makes about this reader, asserted as a request count.

        A distribution IS sitting on the server here — the same one ``thread()``
        spends a scan on — and this reader must still not go for it. Without
        this, "did not go looking" is prose nothing holds to the wire.
        """
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 2))

        await async_client.get_conversation_messages(CONVERSATION_ID)

        assert _distribution_scans() == []
        await async_client.close()

    @respx.mock
    def test_conversation_messages_when_read_on_the_sync_client_then_it_answers_the_same(
        self, sync_client, group_message_fixture, mock_group_message_routes
    ):
        """The sync client is a hand-mirror, and this is where the split could land on one."""
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 2))

        messages = sync_client.get_conversation_messages(CONVERSATION_ID)

        assert [m.decrypt_error_code for m in messages] == [None, None]
        _not_recovered_shape(messages[0].decrypt_error)
        assert _distribution_scans() == []
        sync_client.close()


class TestThreadRecoversTheKey:
    """🔴 A transcript that meets a row it cannot open goes looking — once.

    The behaviour ``rine-core``'s ``decryptGroupMessageWithRecovery`` and
    ``rine-ts-sdk``'s ``retrySenderKey`` have always had and this stack did not:
    the verb an operator reaches for first was the one reader that refused to
    repair the row it was most likely to meet.

    The bound is what makes it affordable, and it is a property of the scan
    rather than a compromise: the listing ingests every pending distribution, so
    a second scan in the same render can only re-read what the first installed.
    """

    @respx.mock
    async def test_thread_when_a_distribution_is_waiting_then_the_render_opens_the_row_async(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """Both rows read as text, from a transcript that arrived unopenable."""
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 2))

        entries = await async_client.thread(CONVERSATION_ID)

        assert [entry.text for entry in entries] == ["hello group", "hello group"]
        assert len(_distribution_scans()) == 1
        await async_client.close()

    @respx.mock
    def test_thread_when_a_distribution_is_waiting_then_the_render_opens_the_row_sync(
        self, sync_client, group_message_fixture, mock_group_message_routes
    ):
        """The sync client is a hand-mirror and recovers identically.

        Hand-mirrored code diverges silently, and a remedy landing on one client
        and not the other is exactly the shape that drift takes here.
        """
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 2))

        entries = sync_client.thread(CONVERSATION_ID)

        assert [entry.text for entry in entries] == ["hello group", "hello group"]
        assert len(_distribution_scans()) == 1
        sync_client.close()

    @respx.mock
    async def test_thread_when_the_distribution_is_there_then_it_agrees_with_read(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """🔴 The defect this closes, stated as the two calls that used to disagree.

        The same routes, the same ciphertext under the same sender key.
        ``thread()`` refused it and pointed at ``read()``; ``read()`` ingested
        the distribution sitting on the server and opened it. An operator's
        first verb was wrong about a row their second verb repaired — honestly
        wrong, which is what the weaker wording bought, but wrong. Both open it now,
        and the transcript's read does not cost the single-message read its own.
        """
        mock_group_message_routes()
        _mock_conversation(_group_rows(group_message_fixture, 1))

        entries = await async_client.thread(CONVERSATION_ID)
        opened = await async_client.read(group_message_fixture.message_id)

        assert entries[0].text == "hello group"
        assert opened.plaintext == group_message_fixture.plaintext
        assert opened.decrypt_error is None
        await async_client.close()

    @respx.mock
    async def test_thread_when_many_rows_lack_the_key_then_the_scan_runs_exactly_once(
        self, async_client, group_message_fixture, agent_id
    ):
        """🔴 The bound, and the only thing in this package that pins it.

        Three rows fail here and one listing answers all three. Per-row would be
        three listings plus a fetch per pending distribution on each of them —
        the cost the one-scan budget keeps off render paths — for nothing the
        first one had not already installed.
        """
        _mock_identity_routes(agent_id)
        scan = _mock_empty_distribution_scan(agent_id)
        _mock_conversation(_group_rows(group_message_fixture, 3))

        entries = await async_client.thread(CONVERSATION_ID)

        assert scan.call_count == 1
        assert len(entries) == 3
        await async_client.close()

    @respx.mock
    async def test_thread_when_nothing_needs_recovering_then_no_scan_runs(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """A transcript with no missing sender key pays nothing for the affordance."""
        mock_group_message_routes()
        _mock_conversation(
            [
                _malformed_mls_row(
                    "11111111-0000-0000-0000-000000000009", group_message_fixture.sender_id
                )
            ]
        )

        entries = await async_client.thread(CONVERSATION_ID)

        assert _distribution_scans() == []
        assert entries[0].text == UNAVAILABLE
        await async_client.close()

    @respx.mock
    async def test_thread_when_another_group_failure_comes_first_then_it_does_not_spend_the_scan(
        self, async_client, group_message_fixture, mock_group_message_routes
    ):
        """🔴 The budget is spent for a missing sender key and for nothing else.

        A group that cut over from Sender Keys to MLS carries both kinds of row
        in one transcript. An MLS failure buys nothing from a distribution scan
        — the self-heal refuses a non-``sender-key-v1`` row outright — so a
        budget spent on it would leave the sender-key row behind it refused by a
        render that never looked, in the words of one that did.
        """
        mock_group_message_routes()
        rows = [
            _malformed_mls_row(
                "11111111-0000-0000-0000-000000000009", group_message_fixture.sender_id
            ),
            *_group_rows(group_message_fixture, 1),
        ]
        _mock_conversation(rows)

        entries = await async_client.thread(CONVERSATION_ID)

        assert len(_distribution_scans()) == 1
        assert entries[0].text == UNAVAILABLE
        assert entries[1].text == "hello group"
        await async_client.close()


class TestThreadEarnsItsRefusal:
    """The scan ran and found nothing, so the transcript may state the verdict.

    This is the half of the split the remedy keeps: a render prints the sentence its
    own behaviour has earned, never a stronger one. What changed is which
    sentence ``thread()`` earns — it looks now, so it may say that no
    distribution is waiting — and the marker moves with it, from the un-earned
    one to :data:`SENDER_KEY_UNAVAILABLE_PREVIEW`, whose remedy a final answer
    is allowed to offer.
    """

    @respx.mock
    async def test_thread_when_no_distribution_arrives_then_the_first_row_explains_async(
        self, async_client, group_message_fixture, agent_id
    ):
        """Explains once, in the words it has now earned, and marks the rest."""
        _mock_identity_routes(agent_id)
        _mock_empty_distribution_scan(agent_id)
        _mock_conversation(_group_rows(group_message_fixture, 2))

        entries = await async_client.thread(CONVERSATION_ID)

        _earned_shape(entries[0].text)
        assert entries[1].text == SENDER_KEY_UNAVAILABLE_PREVIEW
        assert UNAVAILABLE not in [entry.text for entry in entries]
        await async_client.close()

    @respx.mock
    def test_thread_when_no_distribution_arrives_then_the_first_row_explains_sync(
        self, sync_client, group_message_fixture, agent_id
    ):
        """The sync hand-mirror, tiered identically."""
        _mock_identity_routes(agent_id)
        _mock_empty_distribution_scan(agent_id)
        _mock_conversation(_group_rows(group_message_fixture, 2))

        entries = sync_client.thread(CONVERSATION_ID)

        _earned_shape(entries[0].text)
        assert entries[1].text == SENDER_KEY_UNAVAILABLE_PREVIEW
        sync_client.close()

    @respx.mock
    async def test_thread_when_no_distribution_arrives_then_it_claims_no_more_than_read_does(
        self, async_client, group_message_fixture, agent_id
    ):
        """🔴 The two readers that both looked say the same thing about the same row.

        The un-earned sentence — "this read did not go looking ... not a final
        answer" — would now be false here, and printing it would send an
        operator to a ``read()`` that has nothing further to try. What the
        transcript says instead is exactly what ``read()`` says.
        """
        _mock_identity_routes(agent_id)
        _mock_empty_distribution_scan(agent_id)
        _mock_conversation(_group_rows(group_message_fixture, 2))
        respx.get(f"{API}/messages/{group_message_fixture.message_id}").mock(
            return_value=httpx.Response(200, json=group_message_fixture.message_row)
        )

        entries = await async_client.thread(CONVERSATION_ID)
        opened = await async_client.read(group_message_fixture.message_id)

        assert entries[0].text == opened.decrypt_error
        assert SINGLE_MESSAGE_READ_REMEDY not in " ".join(entry.text for entry in entries)
        await async_client.close()

    @respx.mock
    async def test_thread_when_called_again_then_it_explains_again_and_looks_again(
        self, async_client, group_message_fixture, agent_id
    ):
        """A second transcript is a second render: a second sentence and a second scan.

        Both budgets are per call for the same reason. A client renders for
        hours, and one that declined to look because an earlier render already
        had would refuse a row whose distribution arrived in between.
        """
        _mock_identity_routes(agent_id)
        scan = _mock_empty_distribution_scan(agent_id)
        _mock_conversation(_group_rows(group_message_fixture, 2))

        await async_client.thread(CONVERSATION_ID)
        entries = await async_client.thread(CONVERSATION_ID)

        _earned_shape(entries[0].text)
        assert scan.call_count == 2
        await async_client.close()


class TestEarnedRefusalIsUnchanged:
    """🔴 The paths that DO go looking keep the verdict and the code.

    The narrowing is of one render, not of the contract. A change that quietly took the
    typed code off ``inbox()`` would delete the field the five connectors
    branch on, and every one of their renders reads green without it.
    """

    @staticmethod
    def _mock_cold_inbox(fixture, agent_id: str) -> None:
        """List the group row, and let the distribution scan come back empty."""
        _mock_identity_routes(agent_id)
        # The scan is registered first: respx matches in registration order and
        # both share this path, so it must not be served the inbox page.
        _mock_empty_distribution_scan(agent_id)
        respx.get(f"{API}/agents/{agent_id}/messages").mock(
            return_value=httpx.Response(200, json={"items": [fixture.message_row], "total": 1})
        )

    @respx.mock
    async def test_inbox_when_no_distribution_arrives_then_the_verdict_and_the_code_both_stand(
        self, async_client, group_message_fixture, agent_id
    ):
        """The scan ran and found nothing, so this refusal is final and typed."""
        self._mock_cold_inbox(group_message_fixture, agent_id)

        rows = (await async_client.inbox()).items

        _earned_shape(rows[0].decrypt_error)
        assert rows[0].decrypt_error_code == SENDER_KEY_UNAVAILABLE_CODE
        await async_client.close()
