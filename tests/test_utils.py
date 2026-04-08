"""Tests for base64url and compact JSON utilities."""

from __future__ import annotations

from rine._utils import compact_json, from_base64url, to_base64url


class TestBase64url:
    def test_round_trip(self):
        data = b"hello world"
        assert from_base64url(to_base64url(data)) == data

    def test_no_padding(self):
        # 1 byte → 2 chars (would need 2 padding)
        encoded = to_base64url(b"\x00")
        assert "=" not in encoded

    def test_url_safe_chars(self):
        # Bytes that produce + and / in standard base64
        data = bytes(range(256))
        encoded = to_base64url(data)
        assert "+" not in encoded
        assert "/" not in encoded

    def test_accepts_padded_input(self):
        data = b"test"
        encoded = to_base64url(data) + "=="
        assert from_base64url(encoded) == data

    def test_empty(self):
        assert to_base64url(b"") == ""
        assert from_base64url("") == b""

    def test_32_byte_key(self):
        """Keys are 32 bytes — verify no padding issues."""
        key = b"\x01" * 32
        encoded = to_base64url(key)
        assert from_base64url(encoded) == key


class TestCompactJson:
    def test_no_whitespace(self):
        result = compact_json({"a": 1, "b": [2, 3]})
        assert b" " not in result

    def test_matches_js_stringify(self):
        """Matches JSON.stringify() output."""
        result = compact_json({"key": "value"})
        assert result == b'{"key":"value"}'

    def test_unicode(self):
        result = compact_json({"emoji": "\u00e9"})
        assert b"\xc3\xa9" in result  # UTF-8 encoded é

    def test_nested(self):
        result = compact_json({"a": {"b": [1, 2]}})
        assert result == b'{"a":{"b":[1,2]}}'
