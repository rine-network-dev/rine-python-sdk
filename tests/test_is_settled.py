"""``rine.is_settled`` is the one verdict on which streamed or listed rows to acknowledge.

The wrappers (crewai, langchain, hermes) mark a row delivered only when it is settled:
it opened, it is never ciphertext, or its sender's signature failed. Anything else stays
``new`` so a later client, a key fix or a resync can still deliver it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from rine import is_settled
from rine.types import DecryptedMessage


def _row(version: str, *, error: str | None, status: str | None = None) -> DecryptedMessage:
    extra = {"verification_status": status} if status else {}
    return DecryptedMessage(
        id="11111111-2222-3333-4444-555555555555",
        conversation_id="cccccccc-dddd-eeee-ffff-000000000103",
        type="rine.v1.task_request",
        encrypted_payload="x",
        encryption_version=version,
        created_at=datetime(2024, 1, 1, tzinfo=UTC),
        direction="received",
        decrypt_error=error,
        **extra,
    )


def test_is_settled_when_the_version_is_unknown_and_it_failed_to_open_then_it_stays_new():
    """An envelope this client does not know may open for a later client."""
    assert is_settled(_row("hpke-v9", error="unsupported encryption version")) is False


def test_is_settled_when_the_row_is_cleartext_and_unreadable_then_it_is_settled():
    assert is_settled(_row("none", error="payload is not text")) is True


def test_is_settled_when_the_row_opened_then_it_is_settled():
    assert is_settled(_row("hpke-v1", error=None)) is True


def test_is_settled_when_the_signature_failed_then_it_is_settled():
    assert is_settled(_row("hpke-v1", error="refused", status="invalid")) is True


def test_is_settled_when_the_key_lookup_failed_then_it_stays_new():
    assert is_settled(_row("hpke-v1", error="no key", status="unverifiable")) is False
