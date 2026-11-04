"""When a by-id read marks its row delivered.

The server cannot tell whether a row opened: it holds no key, and a plain
``GET /messages/{id}`` marks the row before this client has tried. So every by-id
read here asks for ``X-Rine-Peek`` and marks the row itself, once it knows.

A row is *settled* when no later look could change what the reader sees of it, and
only a settled row is marked. Everything else stays ``new``, so a key fix or a
resync can still deliver it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rine._constants import EncryptionVersion
from rine._crypto._sender_verify import is_authenticity_failure
from rine._logging import logger

if TYPE_CHECKING:
    from rine.types import DecryptedMessage


def is_settled(msg: DecryptedMessage) -> bool:
    """Whether a read of ``msg`` is final, so the row may be marked delivered.

    Three kinds of row are settled:

    * one that **opened** — every outcome that did not open sets ``decrypt_error``
      (a missing key, a sender key not yet arrived, an unknown envelope, a throw),
      so its absence is the positive fact;
    * one that is **never ciphertext** — the A2A cleartext carve-out, which is
      readable as it arrived (or unreadable for good, if its payload is not text);
    * one refused for its **authenticity** — a signature that does not check out is
      a permanent property of the bytes and heals with nothing.

    ``unverifiable`` is none of these: the key lookup failed, not the message.
    """
    return (
        msg.decrypt_error is None
        or msg.encryption_version == EncryptionVersion.NONE
        or is_authenticity_failure(msg.verification_status)
    )


def is_marked(listed: dict[str, Any]) -> bool:
    """Whether a listing row already shows delivered or read, so marking it is a no-op."""
    return listed.get("status") in ("delivered", "read")


def report_ack_failure(message_id: str, error: Exception) -> None:
    """Report a mark-delivered call that failed after a successful read.

    The read still returns the message: a missing mark leaves the row ``new``, which
    a later look recovers, and a lost plaintext it cannot.
    """
    logger.warning(
        "rine: read %s but could not mark it delivered; it stays new: %s", message_id, error
    )
    logger.debug("mark-delivered failure for %s", message_id, exc_info=error)
