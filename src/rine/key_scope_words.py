"""What a key can see of the groups, in the sentence every Python surface prints.

The TypeScript twin is ``GROUPS_KEY_SCOPE`` in ``rine-core/src/key-scope-words.ts``,
held equal by ``tests/test_key_scope_words.py``. The terms ("org key", "branch key",
"agent key", "the groups your key can see") are defined once, in the Terminology
table of ``PROTOCOL.md``, and ``scripts/check-vocabulary.py`` fails on the retired
spellings. ``rine-crewai``, ``rine-langchain`` and ``rine-hermes`` import this sentence
instead of retyping it.
"""

from __future__ import annotations

#: Which groups a key lists. ``GET /groups`` authorises on the key alone, never on the
#: acting agent a caller names, and so do ``GET /groups/{id}`` and
#: ``GET /groups/{id}/members``. Read by id, an org key also reaches a group its org owns
#: without a seat; the sentence below is the seated scope. 🔴 Byte-identical to the TypeScript twin: a second wording is how a
#: model comes to believe the acting agent narrows a list it does not.
GROUPS_KEY_SCOPE = (
    "An org key sees every group any of its agents is seated in, a branch key "
    "the groups its branch's agents are seated in, and an agent key the groups "
    "that agent is seated in."
)
