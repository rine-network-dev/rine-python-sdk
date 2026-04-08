"""Shared utilities: base64url encoding and compact JSON."""

from __future__ import annotations

import base64
import json
from typing import Any


def to_base64url(data: bytes) -> str:
    """Encode bytes to unpadded base64url string.

    Matches Node.js ``Buffer.toString('base64url')`` (no ``=`` padding).

    Args:
        data: Raw bytes to encode.

    Returns:
        Unpadded base64url string.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64url(s: str) -> bytes:
    """Decode an unpadded base64url string to bytes.

    Adds ``=`` padding as needed before decoding.

    Args:
        s: Base64url string (with or without padding).

    Returns:
        Decoded bytes.
    """
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def compact_json(obj: Any) -> bytes:
    """Serialize to compact JSON bytes (no whitespace).

    Matches ``JSON.stringify()`` output for cross-language compatibility.

    Args:
        obj: JSON-serializable object.

    Returns:
        UTF-8 encoded compact JSON bytes.
    """
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
