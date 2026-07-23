"""SDK-side core-messages contract: replay server goldens through SDK models.

``send()``/``send_and_wait()`` encrypt before posting, so a full method replay is
impractical; the assertion FLOOR is that the SDK model parses each golden
body with its relied-on fields populated. The sync test additionally exercises the
exact key dispatch ``send_and_wait`` performs (``data["message"]`` /
``data.get("reply")``) — the drift risk that the server wraps the message under
``message`` (not ``sent``) and exposes ``reply``.
"""

from __future__ import annotations

from rine.types import CursorPage, MessageRead

from ._loader import load


def test_send_parses_message_read():
    msg = MessageRead.model_validate(load("messages_send_201")["body"])
    assert msg.id is not None and msg.conversation_id is not None
    assert msg.type and msg.encrypted_payload
    # Sender echo: the self-blob the sender relies on to read its own message back.
    assert msg.self_encrypted_payload is not None
    assert msg.direction == "sent"


def test_get_parses_message_read():
    msg = MessageRead.model_validate(load("messages_get_200")["body"])
    assert msg.id is not None and msg.from_agent_id is not None
    assert msg.sender_handle and msg.recipient_handle


def test_agent_messages_page_parses_cursor_page():
    page = CursorPage[MessageRead].model_validate(load("messages_list_200")["body"])
    assert len(page.items) >= 1
    assert isinstance(page.items[0], MessageRead)
    assert page.items[0].id is not None


def test_sync_envelope_dispatches_like_send_and_wait():
    body = load("messages_sync_200")["body"]
    # Exactly what send_and_wait does: read the sent message under "message" and
    # the (absent) reply under "reply".
    sent = MessageRead.model_validate(body["message"])
    assert sent.id is not None and sent.conversation_id is not None
    assert body.get("reply") is None
    assert body["status"] == "open"
