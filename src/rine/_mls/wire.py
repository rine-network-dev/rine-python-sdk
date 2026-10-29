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


#: The group's newest GroupInfo is still awaiting a peer's ACK, so the server has
#: no confirmed join capability to serve. Unlike an epoch conflict this resolves
#: on its own, so it gets its own short wait rather than the single rebuild.
PENDING_CONFIRMATION = "pending_confirmation"


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


#: The server's ``error`` key when a commit named Welcome recipients it may not
#: address. The batch answers it by dropping exactly those recipients and
#: retrying once.
WELCOME_RECIPIENT_REJECTED = "welcome_recipient_rejected"


def rejected_welcome_recipients(err: BaseException) -> tuple[str, ...] | None:
    """The agent ids a 422 refused, lower-cased, or ``None`` for another failure.

    The refusal's ``detail`` is a human sentence and the ``rejected`` array is
    the machine-readable half — a batched admission must drop exactly the named
    recipients, which it cannot do by pattern-matching UUIDs out of prose. The
    array carries **every** offender, not the first, so one retry suffices
    whatever the batch contained.

    An **empty tuple is meaningful and distinct from ``None``**: the refusal was
    about recipients, but this client could not tell which — so retrying the
    same batch would fail identically and the caller records the whole batch
    rather than guessing or looping. ``None`` means the failure was something
    else entirely and belongs to the caller. Collapsing the two is how this
    stack came to abandon an admission that the TypeScript twin carries on with,
    against the rule that an admission never fails whole. Mirrors
    ``rejectedRecipients`` in ``rine-core/src/mls-admission-batch.ts``.
    """
    if api_error_code(err) != WELCOME_RECIPIENT_REJECTED:
        return None
    raw = getattr(err, "raw", None)
    if not isinstance(raw, str):
        return ()
    try:
        body = json.loads(raw)
    except ValueError:
        return ()
    rejected = body.get("rejected") if isinstance(body, dict) else None
    if not isinstance(rejected, list):
        return ()
    return tuple(
        str(entry["agent_id"]).lower()
        for entry in rejected
        if isinstance(entry, dict) and entry.get("agent_id")
    )
