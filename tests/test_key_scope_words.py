"""The key-scope sentence is one string on both stacks."""

from __future__ import annotations

import re

from rine.key_scope_words import GROUPS_KEY_SCOPE
from tests._twin import core_source


class TestGroupsKeyScopeTwin:
    def test_scope_when_read_beside_the_core_constant_then_the_text_agrees(self):
        """Byte for byte: the TypeScript literal is read from source, never from a fixture."""
        source = core_source("key-scope-words.ts")
        declaration = re.search(r"GROUPS_KEY_SCOPE =(.*?);", source, re.S)
        assert declaration, "no readable GROUPS_KEY_SCOPE in the twin's source"
        pieces = re.findall(r'"((?:[^"\\]|\\.)*)"', declaration.group(1))

        assert "".join(pieces) == GROUPS_KEY_SCOPE
