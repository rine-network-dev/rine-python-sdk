"""The cleartext send-body helper shared by send()/reply() (marker plumbing)."""

from __future__ import annotations

from rine._utils import apply_cleartext_fields


def test_apply_cleartext_fields_when_none_leaves_body_unchanged() -> None:
    """Apply cleartext fields when none leaves body unchanged."""
    body = {"type": "rine.v1.task_request", "encrypted_payload": "x"}
    apply_cleartext_fields(body, None, None)
    assert body == {"type": "rine.v1.task_request", "encrypted_payload": "x"}


def test_apply_cleartext_fields_when_present_attaches_both() -> None:
    """Apply cleartext fields when present attaches both."""
    body: dict = {"type": "rine.v1.x402_payment"}
    marker = {"rine.x402": {"status": "payment-submitted", "rail": "x402"}}
    apply_cleartext_fields(body, marker, "application/json")
    assert body["metadata"] == marker
    assert body["content_type"] == "application/json"
