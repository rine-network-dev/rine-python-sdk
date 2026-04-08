"""Tests for error hierarchy and utilities."""

from __future__ import annotations

import pytest

from rine.errors import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    AuthorizationError,
    ConfigError,
    ConflictError,
    CryptoError,
    NotFoundError,
    RateLimitError,
    RineApiError,
    RineError,
    ValidationError,
    format_error,
    raise_for_status,
)


class TestErrorHierarchy:
    def test_all_api_errors_are_rine_errors(self):
        assert issubclass(RineApiError, RineError)
        assert issubclass(AuthenticationError, RineApiError)
        assert issubclass(NotFoundError, RineApiError)

    def test_non_api_errors_are_rine_errors(self):
        assert issubclass(CryptoError, RineError)
        assert issubclass(ConfigError, RineError)
        assert issubclass(APITimeoutError, RineError)
        assert issubclass(APIConnectionError, RineError)

    def test_authentication_error_status(self):
        err = AuthenticationError("bad creds")
        assert err.status == 401
        assert err.detail == "bad creds"

    def test_rate_limit_error_retry_after(self):
        err = RateLimitError(retry_after=30.0)
        assert err.retry_after == 30.0
        assert err.status == 429


class TestRaiseForStatus:
    def test_known_status_codes(self):
        with pytest.raises(AuthenticationError):
            raise_for_status(401, "unauthorized")
        with pytest.raises(AuthorizationError):
            raise_for_status(403, "forbidden")
        with pytest.raises(NotFoundError):
            raise_for_status(404, "not found")
        with pytest.raises(ConflictError):
            raise_for_status(409, "conflict")
        with pytest.raises(ValidationError):
            raise_for_status(422, "invalid")
        with pytest.raises(RateLimitError):
            raise_for_status(429, "rate limited")

    def test_unknown_status_falls_back(self):
        with pytest.raises(RineApiError) as exc_info:
            raise_for_status(503, "service unavailable")
        assert exc_info.value.status == 503


class TestFormatError:
    def test_api_error(self):
        err = NotFoundError("Agent not found")
        assert format_error(err) == "Agent not found"

    def test_generic_error(self):
        err = ValueError("oops")
        assert format_error(err) == "oops"

    def test_crypto_error(self):
        err = CryptoError("Decryption failed")
        assert format_error(err) == "Decryption failed"
