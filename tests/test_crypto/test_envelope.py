"""Tests for inner envelope encode/decode."""

from __future__ import annotations

import pytest

from rine._crypto.envelope import (
    MAX_KID_LENGTH,
    SIGNATURE_SIZE,
    decode_envelope,
    encode_envelope,
)
from rine.errors import CryptoError


class TestEnvelope:
    def test_round_trip(self):
        kid = "rine:12345678-1234-1234-1234-123456789abc"
        sig = b"\x00" * 64
        payload = b"hello world"
        encoded = encode_envelope(kid, sig, payload)
        decoded = decode_envelope(encoded)
        assert decoded.kid == kid
        assert decoded.signature == sig
        assert decoded.payload == payload

    def test_wire_format(self):
        kid = "test"
        sig = b"\xaa" * 64
        payload = b"\xbb\xcc"
        encoded = encode_envelope(kid, sig, payload)
        assert encoded[0] == 4  # kid length
        assert encoded[1:5] == b"test"
        assert encoded[5:69] == sig
        assert encoded[69:] == payload

    def test_empty_payload(self):
        kid = "k"
        sig = b"\x00" * 64
        encoded = encode_envelope(kid, sig, b"")
        decoded = decode_envelope(encoded)
        assert decoded.payload == b""

    def test_kid_too_long_raises(self):
        with pytest.raises(CryptoError, match="KID too long"):
            encode_envelope("x" * 256, b"\x00" * 64, b"test")

    def test_max_kid_length_ok(self):
        kid = "x" * MAX_KID_LENGTH
        encoded = encode_envelope(kid, b"\x00" * 64, b"test")
        decoded = decode_envelope(encoded)
        assert decoded.kid == kid

    def test_wrong_signature_size_raises(self):
        with pytest.raises(CryptoError, match="Signature must be"):
            encode_envelope("kid", b"short", b"test")

    def test_decode_too_short_raises(self):
        with pytest.raises(CryptoError, match="too short"):
            decode_envelope(b"")

    def test_decode_truncated_raises(self):
        with pytest.raises(CryptoError, match="too short"):
            # kid_len=5, but only 3 bytes of kid
            decode_envelope(b"\x05abc")

    def test_unicode_kid(self):
        kid = "key-\u00e9\u00e8"
        sig = b"\x00" * 64
        encoded = encode_envelope(kid, sig, b"data")
        decoded = decode_envelope(encoded)
        assert decoded.kid == kid
