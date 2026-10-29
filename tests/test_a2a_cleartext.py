"""An A2A cleartext row reads as flagged plaintext on both clients, not as unsupported."""

from __future__ import annotations

from datetime import UTC, datetime

from rine._thread import to_thread_entry
from rine.a2a_cleartext import A2A_CLEARTEXT_NOTICE
from rine.sender_key_words import SenderKeyRefusal
from rine.types import DecryptedMessage

SENDER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
# One text part "plain" as the server serves it: unpadded base64url of the parts' JSON.
WIRE_PAYLOAD = "W3sidGV4dCI6ICJwbGFpbiJ9XQ"
PARTS = '[{"text": "plain"}]'


def _row(type_: str = "rine.v1.a2a_message", version: str = "none") -> DecryptedMessage:
    return DecryptedMessage(
        id="11111111-2222-3333-4444-555555555555",
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type=type_,
        encrypted_payload=WIRE_PAYLOAD,
        encryption_version=version,
        created_at=datetime(2024, 1, 1, tzinfo=UTC),
        direction="received",
        from_agent_id=SENDER,
    )


def test_decrypt_message_when_the_row_is_a2a_cleartext_then_it_is_flagged_plaintext(
    sync_client, agent_id
) -> None:
    """The sync client flags the payload as plaintext with the notice."""
    msg = sync_client._decrypt_message(agent_id, _row())

    assert msg.a2a_cleartext is True
    assert msg.a2a_cleartext_notice == A2A_CLEARTEXT_NOTICE
    assert msg.plaintext == PARTS
    assert msg.decrypt_error is None
    assert msg.verified is False


async def test_decrypt_message_when_the_row_is_a2a_cleartext_async_then_it_is_flagged_plaintext(
    async_client, agent_id
) -> None:
    """The async client flags the payload as plaintext too."""
    msg = await async_client._decrypt_message(agent_id, _row())

    assert msg.a2a_cleartext is True
    assert msg.plaintext == PARTS
    assert msg.decrypt_error is None


def test_decrypt_message_when_a_non_a2a_row_claims_no_encryption_then_it_stays_unsupported(
    sync_client, agent_id
) -> None:
    """A row of another type claiming no encryption is still unsupported."""
    msg = sync_client._decrypt_message(agent_id, _row(type_="rine.v1.text"))

    assert msg.a2a_cleartext is False
    assert msg.plaintext is None
    assert "Unsupported encryption_version" in (msg.decrypt_error or "")


def test_decrypt_message_when_the_cleartext_payload_is_not_base64url_text_then_decrypt_error(
    sync_client, agent_id
) -> None:
    """A payload that does not decode degrades to a per-message error, not an exception."""
    row = _row()
    row.encrypted_payload = "gA"  # decodes to the single byte 0x80, not UTF-8

    msg = sync_client._decrypt_message(agent_id, row)

    assert msg.plaintext is None
    assert msg.decrypt_error is not None
    assert msg.a2a_cleartext is True


def test_to_thread_entry_when_the_row_is_a2a_cleartext_then_entry_is_flagged_and_text_keeps_notice(
    sync_client, agent_id
) -> None:
    """The turn carries the typed flag and still leads its text with the notice."""
    msg = sync_client._decrypt_message(agent_id, _row())

    entry = to_thread_entry(msg, SenderKeyRefusal())

    assert entry.a2a_cleartext is True
    assert entry.text.startswith(f"[{A2A_CLEARTEXT_NOTICE}] ")


def test_to_thread_entry_when_the_row_is_not_cleartext_then_flag_is_false() -> None:
    """An ordinary readable turn is not flagged."""
    msg = _row(type_="rine.v1.text", version="hpke-hybrid-v2")
    msg.plaintext = "hello"

    assert to_thread_entry(msg, SenderKeyRefusal()).a2a_cleartext is False


def test_to_thread_entry_when_a_cleartext_row_fails_to_decode_then_flag_is_false(
    sync_client, agent_id
) -> None:
    """An unreadable turn carries no flag and no notice: nothing was shown."""
    row = _row()
    row.encrypted_payload = "gA"
    msg = sync_client._decrypt_message(agent_id, row)

    entry = to_thread_entry(msg, SenderKeyRefusal())

    assert entry.a2a_cleartext is False
    assert A2A_CLEARTEXT_NOTICE not in entry.text


def test_decrypt_message_when_the_row_is_a2a_cleartext_then_the_notice_is_the_literal_sentence(
    sync_client, agent_id
) -> None:
    """The sentence every surface shows is pinned by value, not by the constant that holds it.

    Comparing a notice to ``A2A_CLEARTEXT_NOTICE`` passes for any value, an empty one included.
    """
    literal = "Received as A2A cleartext: this message was not end-to-end encrypted."

    msg = sync_client._decrypt_message(agent_id, _row())
    entry = to_thread_entry(msg, SenderKeyRefusal())

    assert msg.a2a_cleartext_notice == literal
    assert entry.text.startswith(f"[{literal}] ")
