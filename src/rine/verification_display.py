"""Rendering an agent's verification words on a surface that holds its keys.

:mod:`rine.verification_words` derives the words and compares them; this is the
half every display surface shares — where the held key comes from, and what the
four outcomes read like in a terminal. It lives here rather than in each
integration because there are ten display surfaces across the two client stacks,
and ten copies of a mismatch explanation is ten explanations that drift. The
TypeScript twin is ``rine-core/src/verification-display.ts`` and the two print
the same sentences.

🔴 The held key is loaded from the config dir, never fetched. A key read back
from ``GET /agents/{id}/keys`` is the server's own assertion, so words derived
from it agree with the server's by construction and the comparison says nothing
at all.
"""

from __future__ import annotations

from rine._crypto.keys import load_agent_keys
from rine.verification_words import (
    VerificationWordsComparison,
    compare_verification_words,
)


def compare_verification_words_for_agent(
    config_dir: str,
    agent_id: str,
    asserted_words: str | None,
) -> VerificationWordsComparison:
    """Compare an agent's asserted words against the ones its local keys derive.

    Args:
        config_dir: Config dir holding this agent's keys.
        agent_id: The agent the words belong to.
        asserted_words: The words the server named, e.g. from an agent record.

    Returns:
        Both values and why either is absent. A config dir with no usable
        signing key for the agent yields ``"not-computed"`` rather than raising:
        whether this client can recompute is a state to render, not a failure.
    """
    held_key: bytes | None
    try:
        held_key = load_agent_keys(config_dir, agent_id).signing.public_key
    except Exception:
        # Missing, corrupt, or a config dir belonging to a different agent — all
        # one state to a reader: this client cannot recompute.
        held_key = None
    return compare_verification_words(held_key, asserted_words)


def verification_words_lines(
    comparison: VerificationWordsComparison,
    label: str = "Verification words",
) -> list[str]:
    """The lines a text surface prints for a comparison, in order.

    A mismatch is a designed state: both values render, the explanation is plain
    and names what usually causes it, and nothing here gates sending. An empty
    list means there is nothing to say — no local key and no asserted words.

    Args:
        comparison: The result of :func:`compare_verification_words_for_agent`.
        label: Prefix for the words line; surfaces that align a column of labels
            pass their own.

    Returns:
        Lines to print in order, possibly empty.
    """
    if comparison.status == "match":
        return [f"{label}: {comparison.computed}"]
    if comparison.status == "mismatch":
        return [
            f"{label} (this client): {comparison.computed}",
            f"{label} (server):       {comparison.asserted}",
            "These differ. The words are derived from an agent's signing key, so the",
            "server holds a different signing key than this config dir does. A config",
            "dir copied from another machine, or a signing key republished elsewhere,",
            "both look like this. Messages still send and arrive.",
            "Publish this agent's public key again, or point RINE_CONFIG_DIR at the",
            "keys it was created with.",
        ]
    if comparison.status == "not-computed":
        if comparison.asserted is None:
            return []
        return [
            f"{label} (server): {comparison.asserted}",
            "Not recomputed here: this config dir holds no usable signing key for this",
            "agent, so these words are the server's statement rather than this client's.",
        ]
    return [
        f"{label}: {comparison.computed}",
        "The server names no words for this agent, so there is nothing to compare",
        "against.",
    ]


__all__ = [
    "compare_verification_words_for_agent",
    "verification_words_lines",
]
