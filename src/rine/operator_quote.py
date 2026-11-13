"""Third-party text a surface places inline in a larger string (a wake prompt, a transcript).

The text sits inside a per-message random delimiter, and any copy of a rine notice inside
it is replaced, so a sender cannot paste the sentence that grants authority into the body
that is being read as data. A copy still matches when Unicode format characters (category
Cf: zero-width space and joiners, soft hyphen, word joiner) are hidden anywhere inside it,
or when its final period is left off. The match ignores the case of ASCII letters and the
width and kind of whitespace; the whitespace class and the format characters are written
out and the case folding is ASCII-only, so this matches the very same characters as
``rine-core/src/operator-quote.ts``.
"""

from __future__ import annotations

import re
import secrets

from rine.control_frames import (
    OPERATOR_CONTENT_NOTICE,
    OPERATOR_HISTORY_NOTICE,
    UNTRUSTED_CONTENT_NOTICE,
)

#: What replaces a neutralised notice.
NEUTRALISED_NOTICE = "[a rine notice was removed from this text]"

#: Unicode category Cf, as ``\p{Cf}`` is in the TypeScript twin (``re`` has no property classes).
_FORMAT = (
    "\\u00ad\\u0600-\\u0605\\u061c\\u06dd\\u070f\\u0890-\\u0891\\u08e2\\u180e\\u200b-\\u200f"
    "\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u206f\\ufeff\\ufff9-\\ufffb\\U000110bd\\U000110cd"
    "\\U00013430-\\U0001343f\\U0001bca0-\\U0001bca3\\U0001d173-\\U0001d17a\\U000e0001"
    "\\U000e0020-\\U000e007f"
)
_SPACE_CHARS = " \\t\\n\\r\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000"
#: A gap between two words: whitespace, or a format character standing in for it, in any number.
_WORD_GAP = f"[{_SPACE_CHARS}{_FORMAT}]+"
_HIDDEN = f"[{_FORMAT}]*"
_RANDOM_BYTES = 16


def _char_pattern(char: str) -> str:
    """One character as a pattern: an ASCII letter in both cases, anything else as itself."""
    if char.isascii() and char.isalpha():
        return f"[{char.lower()}{char.upper()}]"
    return re.escape(char)


def _word_pattern(word: str) -> str:
    return _HIDDEN.join(_char_pattern(char) for char in word)


def _pattern_for(notice: str) -> re.Pattern[str]:
    """The notice as a pattern whose last period, when it ends in one, may be missing."""
    bare = notice.removesuffix(".")
    body = _WORD_GAP.join(_word_pattern(word) for word in bare.split(" "))
    period = "" if bare == notice else f"{_HIDDEN}\\.?"
    return re.compile(body + period)


_NOTICE_PATTERNS = tuple(
    _pattern_for(notice)
    for notice in (UNTRUSTED_CONTENT_NOTICE, OPERATOR_CONTENT_NOTICE, OPERATOR_HISTORY_NOTICE)
)


def neutralise_notices(text: str) -> str:
    """``text`` with every copy of a rine notice replaced by :data:`NEUTRALISED_NOTICE`."""
    for pattern in _NOTICE_PATTERNS:
        text = pattern.sub(lambda _match: NEUTRALISED_NOTICE, text)
    return text


def random_delimiter() -> str:
    """A fresh delimiter token of 128 random bits, so the closing line cannot be written ahead."""
    return f"rine-{secrets.token_hex(_RANDOM_BYTES)}"


def wrap_third_party_text(text: str, delimiter: str) -> str:
    """``text`` neutralised and fenced between a begin and an end line naming ``delimiter``.

    A copy of the delimiter inside the text is removed first, so the fence cannot be closed
    from within.
    """
    inner = neutralise_notices(text).replace(delimiter, "")
    return f"BEGIN {delimiter}\n{inner}\nEND {delimiter}"
