"""The one cleartext path: a message an external A2A client posted to an agent that accepts it.

Its body travelled without end-to-end encryption, so every surface that shows such a message
says so, in this one sentence. It is bound to ``A2A_CLEARTEXT_NOTICE`` in
``rine-core/src/a2a-cleartext.ts`` by ``tests/test_owner-words-twin_group0.py``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._constants import EncryptionVersion, MessageType
from rine._utils import from_base64url

if TYPE_CHECKING:
    from rine.types import DecryptedMessage

A2A_CLEARTEXT_NOTICE = "Received as A2A cleartext: this message was not end-to-end encrypted."


def is_a2a_cleartext(msg: DecryptedMessage) -> bool:
    """Whether ``msg`` is an A2A message that arrived as cleartext."""
    return msg.type == MessageType.A2A_MESSAGE and msg.encryption_version == EncryptionVersion.NONE


def read_a2a_cleartext(msg: DecryptedMessage) -> DecryptedMessage:
    """Fill ``msg`` in place: the decoded parts are its plaintext, flagged and never verified.

    The wire payload is the posted parts' JSON in unpadded base64url, so the plaintext is that
    text decoded, the same string the TypeScript clients yield for the same message. A payload
    that does not decode is reported as ``decrypt_error``, like any message that cannot be read.
    """
    try:
        msg.plaintext = from_base64url(msg.encrypted_payload).decode("utf-8")
    except ValueError as exc:
        msg.decrypt_error = f"A2A cleartext payload is not valid base64url text: {exc}"
    msg.a2a_cleartext = True
    msg.a2a_cleartext_notice = A2A_CLEARTEXT_NOTICE
    return msg


def with_a2a_cleartext_notice(msg: DecryptedMessage, text: str) -> str:
    """``text``, the body shown for ``msg``, led by the cleartext notice when ``msg`` is cleartext.

    Every renderer that shows or hands a model the body calls this on the readable branch, so a
    cleartext body never reads as end-to-end encrypted. Any other row comes back unchanged.
    """
    return f"[{A2A_CLEARTEXT_NOTICE}] {text}" if msg.a2a_cleartext else text
