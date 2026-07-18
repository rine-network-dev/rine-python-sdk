"""Cleartext status marker: enum-only, never economic, fail-closed reads."""

from __future__ import annotations

import json

import pytest

from rine._constants import MessageType
from rine.x402.marker import (
    build_marker,
    marker_metadata,
    read_marker,
    status_for_message_type,
)
from rine.x402.types import X402_METADATA_KEY, X402Status


def test_status_for_message_type_maps_each_x402_type() -> None:
    """Status for message type maps each x402 type."""
    assert status_for_message_type(MessageType.X402_PAYMENT_REQUIRED) == X402Status.REQUIRED
    assert status_for_message_type(MessageType.X402_PAYMENT) == X402Status.SUBMITTED
    assert status_for_message_type(MessageType.X402_RECEIPT) == X402Status.COMPLETED
    assert status_for_message_type(MessageType.X402_RECEIPT, success=False) == X402Status.FAILED


def test_status_for_message_type_when_not_x402_raises() -> None:
    """Status for message type when not x402 raises."""
    with pytest.raises(ValueError):
        status_for_message_type(MessageType.TASK_REQUEST)


def test_marker_metadata_never_contains_economic_detail() -> None:
    """Marker metadata never contains economic detail."""
    # Whatever a payment carries, the cleartext marker must expose only status+rail.
    meta = marker_metadata(MessageType.X402_PAYMENT)
    blob = json.dumps(meta)
    marker = meta[X402_METADATA_KEY]
    assert set(marker.keys()) == {"status", "rail"}
    for forbidden in ("amount", "100000", "asset", "0x", "payTo", "transaction", "EURC"):
        assert forbidden not in blob


def test_build_marker_when_invalid_status_raises() -> None:
    """Build marker when invalid status raises."""
    with pytest.raises(ValueError):
        build_marker("paid")


def test_read_marker_when_valid_returns_status_and_rail() -> None:
    """Read marker when valid returns status and rail."""
    meta = {X402_METADATA_KEY: {"status": X402Status.COMPLETED, "rail": "x402"}}
    assert read_marker(meta) == {"status": X402Status.COMPLETED, "rail": "x402"}


def test_read_marker_when_status_out_of_enum_fails_closed() -> None:
    """Read marker when status out of enum fails closed."""
    assert read_marker({X402_METADATA_KEY: {"status": "paid", "rail": "x402"}}) is None


def test_read_marker_when_absent_returns_none() -> None:
    """Read marker when absent returns none."""
    assert read_marker(None) is None
    assert read_marker({}) is None
    assert read_marker({"other": 1}) is None
