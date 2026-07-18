"""Cleartext payment-status marker (REQ-P02).

The optional coarse marker lives in a message's server-visible ``metadata`` under
:data:`X402_METADATA_KEY`. It carries ONLY a lifecycle ``status`` (one of four
enum values) and the ``rail`` — never amounts, assets, addresses, tx hashes, or
any economic detail (those live solely in the encrypted payload).
"""

from __future__ import annotations

from typing import Any

from rine._constants import MessageType
from rine.x402.types import X402_METADATA_KEY, X402_RAIL, X402Status

_VALID_STATUSES = frozenset(
    {X402Status.REQUIRED, X402Status.SUBMITTED, X402Status.COMPLETED, X402Status.FAILED}
)


def status_for_message_type(message_type: str, *, success: bool = True) -> str:
    """The marker ``status`` a sender sets for a given x402 message type.

    Args:
        message_type: One of the three ``rine.v1.x402_*`` types.
        success: For a receipt, whether settlement succeeded (else ``payment-failed``).

    Raises:
        ValueError: If ``message_type`` is not an x402 payment type.
    """
    if message_type == MessageType.X402_PAYMENT_REQUIRED:
        return X402Status.REQUIRED
    if message_type == MessageType.X402_PAYMENT:
        return X402Status.SUBMITTED
    if message_type == MessageType.X402_RECEIPT:
        return X402Status.COMPLETED if success else X402Status.FAILED
    raise ValueError(f"Not an x402 payment message type: {message_type}")


def build_marker(status: str) -> dict[str, str]:
    """Build the ``{status, rail}`` marker object for the given status enum."""
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid x402 marker status: {status}")
    return {"status": status, "rail": X402_RAIL}


def marker_metadata(message_type: str, *, success: bool = True) -> dict[str, Any]:
    """Build the ``metadata`` fragment carrying the marker for a message type."""
    return {
        X402_METADATA_KEY: build_marker(status_for_message_type(message_type, success=success))
    }


def read_marker(metadata: dict[str, Any] | None) -> dict[str, str] | None:
    """Extract a valid x402 marker from message metadata, or ``None``.

    Fail-closed: an entry with a status outside the four-value enum is ignored.
    """
    if not metadata:
        return None
    raw = metadata.get(X402_METADATA_KEY)
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    if status not in _VALID_STATUSES:
        return None
    return {"status": str(status), "rail": str(raw.get("rail", X402_RAIL))}
