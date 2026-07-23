"""How MLS blobs and MLS failures cross the wire.

MLS control-plane blobs (KeyPackages, Welcome, commit, GroupInfo, proposals)
ride the wire as **standard** base64, unlike the rest of the SDK's base64url
payloads — the server decodes them with ``base64.b64decode(..., validate=True)``,
so the two alphabets are not interchangeable. Application messages are the
exception and are handled on the message path, not here.
"""

from __future__ import annotations

import base64
import json


def mls_to_base64(blob: bytes) -> str:
    """Encode an MLS control-plane blob for the wire (standard base64)."""
    return base64.b64encode(blob).decode("ascii")


def mls_from_base64(encoded: str) -> bytes:
    """Decode an MLS control-plane blob from the wire (standard base64)."""
    return base64.b64decode(encoded, validate=True)


def api_error_code(err: BaseException) -> str | None:
    """The server's machine-readable ``error`` key for a failed request.

    The MLS flows branch on ``epoch_conflict`` and ``pending_confirmation``,
    which share a status code with every other 409 — matching on the detail
    string instead would break the moment the wording is improved.

    Returns:
        The error key, or ``None`` when the failure carries no server body.
    """
    raw = getattr(err, "raw", None)
    if not isinstance(raw, str):
        return None
    try:
        body = json.loads(raw)
    except ValueError:
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code if isinstance(code, str) else None
