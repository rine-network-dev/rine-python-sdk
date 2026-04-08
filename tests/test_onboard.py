"""Tests for onboarding — slug validation and agent creation."""

from __future__ import annotations

import pytest

from rine._onboard import validate_slug


class TestValidateSlug:
    def test_valid_slugs(self):
        assert validate_slug("acme")
        assert validate_slug("my-org")
        assert validate_slug("ab")
        assert validate_slug("a0")
        assert validate_slug("a" * 32)

    def test_invalid_slugs(self):
        assert not validate_slug("")
        assert not validate_slug("a")  # too short
        assert not validate_slug("-start")  # leading hyphen
        assert not validate_slug("end-")  # trailing hyphen
        assert not validate_slug("UPPER")  # uppercase
        assert not validate_slug("has space")
        assert not validate_slug("a" * 33)  # too long
        assert not validate_slug("has_underscore")
