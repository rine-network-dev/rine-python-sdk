"""Shared thread-rendering helpers used by both the async and sync clients.

A single source for mapping a decrypted message to a :class:`ThreadEntry` so the
two hand-mirrored clients (and the TypeScript SDK) render the transcript
identically.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rine.sender_key_words import SenderKeyRefusal
    from rine.types import DecryptedMessage, ThreadEntry

UNAVAILABLE = "[unavailable]"


def render_text(plaintext: object, content_type: str | None = None) -> str:
    """Render decrypted plaintext to the human-readable body string.

    Connectors wrap the message body as ``{"text": "..."}``; surface that string
    directly. A bare string passes through; any other shape is stringified. This
    rule mirrors the TypeScript SDK's ``renderText`` so transcripts read
    identically across surfaces.

    The JSON-unwrap step is gated on ``content_type`` exactly as the TS SDK's
    ``autoParsePlaintext`` (which only ``JSON.parse``s when the content type is
    ``application/json`` or absent). A ``text/plain`` body that merely *looks*
    like JSON is therefore passed through literally in both SDKs, instead of
    being silently unwrapped on the Python side only.
    """
    if isinstance(plaintext, str):
        if content_type is not None and content_type != "application/json":
            return plaintext
        # Inbox/_decrypt_message stores plaintext as the raw decrypted string,
        # which for JSON payloads is a serialized object — parse it so the
        # ``{"text": ...}`` shape can be unwrapped, same as the TS auto-parse.
        try:
            parsed = json.loads(plaintext)
        except (ValueError, TypeError):
            return plaintext
        return _render_parsed(parsed, fallback=plaintext)
    return _render_parsed(plaintext, fallback=str(plaintext))


def _render_parsed(value: object, *, fallback: str) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        if isinstance(text, str):
            return text
    try:
        # ensure_ascii=False keeps non-ASCII bytes intact, matching the TS
        # mirror's `JSON.stringify` so structured payloads render identically.
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return fallback


def to_thread_entry(msg: DecryptedMessage, refusal: SenderKeyRefusal) -> ThreadEntry:
    """Map a decrypted message to a role-tagged :class:`ThreadEntry`.

    ``refusal`` is one render's "explain once, then mark" state and is required
    rather than defaulted: a transcript is rendered by a loop, and the choice
    between the full sentence and the bounded marker belongs to the render, not
    to the row. Defaulting it would let a caller loop over rows and silently get
    the paragraph on every one of them, which is the behaviour the tier exists
    to remove. Build one per transcript.

    Args:
        msg: The decrypted (or refused) row.
        refusal: This render's sender-key refusal state.

    Returns:
        The rendered turn.
    """
    from rine.types import ThreadEntry

    if msg.decrypt_error is not None or msg.plaintext is None:
        # A row this reader cannot open says so; the one cause with a move for
        # the operator to make says which move, on the first row that has it.
        text = refusal.text_for(msg) or UNAVAILABLE
    else:
        text = render_text(msg.plaintext, msg.content_type)
    return ThreadEntry(
        direction=msg.direction or "received",
        sender_handle=msg.sender_handle,
        text=text,
        verification_status=msg.verification_status,
        type=msg.type,
        created_at=msg.created_at,
    )
