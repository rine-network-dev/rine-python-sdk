"""Tests for wire-format constant values."""

from __future__ import annotations

from rine import MessageType


class TestMessageType:
    def test_webhook_value(self):
        # A relayed inbound webhook (the rine Funnel) arrives as this message type.
        assert MessageType.WEBHOOK == "rine.v1.webhook"
