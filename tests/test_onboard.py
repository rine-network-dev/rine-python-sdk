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


class TestTheRegisterSpelling:
    """The word the rest of the product uses is bound here too.

    ``rine.onboard`` is this SDK's name for the call; the TypeScript SDK, the
    CLI and every piece of prose about day one say *register*. A reader who
    reached for that word found nothing bound to it, and an SDK cannot be
    discovered by the name its own documentation uses everywhere else.
    """

    def test_register_when_imported_from_the_root_then_is_the_same_object_as_onboard(self):
        import rine

        # Identity, not equality: two functions would be two implementations
        # that can drift, and a caller passing one to a mock would not see the
        # other patched.
        assert rine.register is rine.onboard
        assert rine.async_register is rine.async_onboard

    def test_register_when_reading_the_public_surface_then_both_spellings_are_exported(self):
        import rine

        assert {"register", "async_register", "onboard", "async_onboard"} <= set(rine.__all__)
