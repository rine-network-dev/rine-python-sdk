"""Message builders: type/marker wiring and verbatim payload round-trip."""

from __future__ import annotations

import json

import pytest

from rine._constants import MessageType
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.messages import (
    build_payment_required,
    build_receipt,
    parse_x402_payload,
    payment_message,
    receipt_from_settlement,
)
from rine.x402.types import X402_METADATA_KEY, X402Status

REQ = {
    "scheme": "exact",
    "network": "eip155:8453",
    "amount": "100000",
    "asset": "0x60a3e35cc302bfa44cb288bc5a4f316fdb1adb42",
    "payTo": "0xpayee",
    "maxTimeoutSeconds": 60,
    "extra": {"name": "EURC", "version": "2"},
}


def test_build_payment_required_sets_type_and_required_marker() -> None:
    """Build payment required sets type and required marker."""
    msg = build_payment_required(accepts=[REQ], resource={"description": "task"})
    assert msg.message_type == MessageType.X402_PAYMENT_REQUIRED
    assert msg.metadata[X402_METADATA_KEY]["status"] == X402Status.REQUIRED
    assert msg.payload["accepts"] == [REQ]
    assert msg.payload["x402Version"] == 2


def test_payment_message_sets_submitted_marker() -> None:
    """Payment message sets submitted marker."""
    signed = {
        "x402Version": 2,
        "accepted": REQ,
        "payload": {"signature": "0x", "authorization": {}},
    }
    msg = payment_message(signed)
    assert msg.message_type == MessageType.X402_PAYMENT
    assert msg.metadata[X402_METADATA_KEY]["status"] == X402Status.SUBMITTED


def test_build_receipt_when_failure_sets_failed_marker() -> None:
    """Build receipt when failure sets failed marker."""
    msg = build_receipt(
        success=False,
        transaction="",
        network="eip155:8453",
        payer="0xp",
        error_reason="insufficient_funds",
    )
    assert msg.message_type == MessageType.X402_RECEIPT
    assert msg.metadata[X402_METADATA_KEY]["status"] == X402Status.FAILED
    assert msg.payload["errorReason"] == "insufficient_funds"


def test_receipt_from_settlement_preserves_unknown_keys_verbatim() -> None:
    """Receipt from settlement preserves unknown keys verbatim."""
    settlement = {
        "success": True,
        "transaction": "0xhash",
        "network": "eip155:8453",
        "payer": "0xpayer",
        "extensions": {"vendorField": 7},
        "someFutureKey": "kept",
    }
    msg = receipt_from_settlement(settlement)
    assert msg.payload == settlement  # verbatim passthrough
    assert msg.metadata[X402_METADATA_KEY]["status"] == X402Status.COMPLETED


def test_add_marker_false_omits_metadata() -> None:
    """Add marker false omits metadata."""
    msg = build_payment_required(accepts=[REQ], add_marker=False)
    assert msg.metadata == {}


def test_parse_x402_payload_roundtrips_verbatim_from_json_string() -> None:
    """Parse x402 payload roundtrips verbatim from json string."""
    original = build_payment_required(accepts=[REQ], resource={"url": "u"}).payload
    # The inbox stores the decrypted plaintext as a JSON string.
    wire = json.dumps(original)
    assert parse_x402_payload(wire) == original


def test_parse_x402_payload_when_not_json_object_raises_malformed() -> None:
    """A non-object / non-JSON body is a typed malformed-payload refusal."""
    for bad in ("[]", "not json", "null"):
        with pytest.raises(X402Error) as exc:
            parse_x402_payload(bad)
        assert exc.value.code == X402ErrorCode.MALFORMED_PAYLOAD
