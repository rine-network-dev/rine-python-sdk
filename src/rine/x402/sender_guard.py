"""The money paths' sender gate (parity with ``rine-core/src/x402/sender-guard.ts``).

A quote is acted on before an authorization is signed against it, and a payment
before it is settled; both are bodies the counterparty authored. The decrypt
reports a sender verdict instead of raising, so this is the ONE place that turns
it into a typed refusal for every money path: :func:`~rine.x402.flow.prepare_payment`,
the payee :func:`~rine.x402.payee.fulfill`, and the crewai, langchain and hermes
payers all call it.

A hostile server can forge a quote under any agent while that agent's key cannot
be read, so "payable" means ``verified`` and nothing weaker.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine.x402.errors import X402Error, X402ErrorCode

if TYPE_CHECKING:
    from rine.types import DecryptedMessage


def require_payable(message: DecryptedMessage) -> None:
    """Raise unless ``message`` was signed by the sender the server authenticated for it.

    ``unverifiable`` is refused too: the check could not run, so nothing vouches
    for the author. That refusal has its own code, because it is retryable: the same
    message passes once the sender's key can be read. Only a row that opened, has an
    authenticated sender and is not cleartext A2A gets it; a row that failed to
    decrypt, has no sender or never carried a signature cannot pass on a retry.

    Raises:
        X402Error: ``sender-unverifiable`` when the check could not run, otherwise
            ``inauthentic-sender``, with the verdict in ``details``.
    """
    status = message.verification_status
    sender = message.from_agent_id or "no authenticated sender"
    details: dict[str, object] = {"verification_status": status}
    if status == "sender-mismatch":
        raise X402Error(
            X402ErrorCode.INAUTHENTIC_SENDER,
            f"Message {message.id} was signed by another agent than {sender}, the agent the "
            "server authenticated as its sender - refusing to act on a re-sealed message",
            details,
        )
    if status == "verified" and message.decrypt_error is None and not message.a2a_cleartext:
        return
    if (
        status == "unverifiable"
        and message.from_agent_id
        and message.decrypt_error is None
        and not message.a2a_cleartext
    ):
        raise X402Error(
            X402ErrorCode.SENDER_UNVERIFIABLE,
            f"Message {message.id} cannot be checked as signed by {sender}, the agent the server "
            "authenticated as its sender (its signing key could not be looked up) - nothing was "
            "paid or settled; retry once the key lookup works",
            details,
        )
    if message.a2a_cleartext:
        why = "it was posted in cleartext and carries no signature"
    elif status == "verified" or message.decrypt_error is not None:
        why = "it did not decrypt to a signed body"
    else:
        why = "its signature does not check out"
    raise X402Error(
        X402ErrorCode.INAUTHENTIC_SENDER,
        f"Message {message.id} is not verified as signed by {sender}, the agent the server "
        f"authenticated as its sender ({why}) - refusing to act on it",
        details,
    )
