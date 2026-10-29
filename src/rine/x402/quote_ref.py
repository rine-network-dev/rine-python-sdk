"""Quote-ref resolution — load the ONE quote a payment answers (self-seal path).

Python mirror of ``rine-core/src/x402/quote-ref.ts``. The payer stamps the answered
quote's message id into the SIGNED payload ``extensions[X402_QUOTE_REF_KEY]``; here
the payee turns that id back into the payee-authored ``accepts[]`` it must reconcile
against, PROVING the referenced message is genuinely a quote THIS payee issued in
THIS conversation before trusting a byte of it.

A rine 1:1 send carries a ``self_encrypted_payload`` sealed to the sender's own key,
so the payee re-opens its earlier ``x402_payment_required`` by id — a single
``GET /messages/{id}`` (never a windowed thread scan), decrypted direction-aware via
the client's own self-seal path. Any missing / unresolvable / not-payee-issued /
cross-conversation / unopenable ref is a typed ``NO_QUOTE`` (fail closed): a payer
can neither forge nor omit its way past the binding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rine._constants import MessageType
from rine._crypto._sender_verify import is_authenticity_failure
from rine._resolve import parses_as_uuid
from rine.sender_key_words import SenderKeyRefusal
from rine.types import DecryptedMessage
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.messages import parse_x402_payload
from rine.x402.types import X402_QUOTE_REF_KEY

if TYPE_CHECKING:
    from rine._client import RineClient
    from rine.x402.types import PaymentPayload, PaymentRequirements


@dataclass(frozen=True)
class ReferencedQuote:
    """The referenced quote's message id and its payee-authored ``accepts[]``."""

    message_id: str
    accepts: list[PaymentRequirements]


async def load_referenced_quote(
    client: RineClient,
    payment: PaymentPayload,
    conversation_id: str,
    agent: str | None,
) -> ReferencedQuote:
    """Resolve ``extensions[X402_QUOTE_REF_KEY]`` to the payee's OWN issued quote.

    Fetches the referenced message by id, proves it is (a) an
    ``x402_payment_required``, (b) issued by THIS payee (``from_agent_id == payee``
    — the real binding), (c) in the SAME conversation, decrypts it via the payee
    self-seal, and returns its ``accepts[]``. Fails closed with a typed
    :class:`X402Error` (``no-quote``) on a missing/blank ref, a GET failure, a
    type/from/conversation mismatch, a missing self-seal, an invalid sender
    signature, or a decrypt/parse failure.
    """
    ref = (payment.get("extensions") or {}).get(X402_QUOTE_REF_KEY)
    if not isinstance(ref, str) or ref == "":
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Payment carries no {X402_QUOTE_REF_KEY} — cannot bind it to a "
            "payee-issued quote (fail closed; use explicit expected terms for an "
            "out-of-band quote)",
        )
    # 🔴 Before ANY network call, including the agent resolution below: ``ref`` is
    # the payer's own plaintext and it is about to be interpolated into a URL path.
    # Every other guard in this function runs on the RESPONSE, so an unchecked ref
    # decides WHICH endpoint the payee's own credentials are spent on — and the
    # server has GETs that mutate (``/agents/{id}/mls/welcomes`` consumes what it
    # returns), so a traversal here is not a read, it is a write the payee is
    # tricked into signing for. Refusing before the first request is the whole
    # point: a refusal after it has already been issued is not a refusal.
    #
    # ``parses_as_uuid`` and not the strict ``is_uuid``: the server types this path
    # parameter ``uuid.UUID`` (``GET /messages/{message_id}``), which has always
    # taken the dashless, ``urn:uuid:`` and braced spellings too. A pre-flight is
    # only ever allowed to refuse what the wire would have refused anyway, so
    # refusing one of those here would be a capability removal wearing a validation
    # fix. What it buys is the alphabet: every spelling it admits is hex digits,
    # dashes, braces and the two prefixes, so none can carry a ``/``, a ``?`` or a
    # ``#`` — the ref can no longer name an endpoint other than this one.
    if not parses_as_uuid(ref):
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced quote {ref} is not a message id — refusing to settle",
        )
    payee_agent_id = await client._resolve_agent_id(agent)
    extra = await client._agent_header(agent)
    try:
        raw = await client._http.get(f"/messages/{ref}", extra_headers=extra)
    except Exception as exc:  # noqa: BLE001 — any fetch failure is a fail-closed refusal
        raise X402Error(
            X402ErrorCode.NO_QUOTE, f"Referenced quote {ref} is unresolvable: {exc}"
        ) from exc
    msg = DecryptedMessage.from_wire(raw)
    if (
        msg.type != MessageType.X402_PAYMENT_REQUIRED
        or str(msg.from_agent_id) != payee_agent_id
        or str(msg.conversation_id) != conversation_id
    ):
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced message {ref} is not a payee-issued quote in this "
            "conversation (type/from/conversation mismatch) — refusing to settle",
            {"type": msg.type, "fromAgentId": str(msg.from_agent_id)},
        )
    if msg.self_encrypted_payload is None:
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced quote {ref} has no self-sealed copy the payee can reopen "
            "(legacy pre-self-seal) — refusing to settle",
        )
    # A one-row reopen of a 1:1 self-sealed quote — guarded above, so it cannot
    # reach the sender-key path at all — and it runs no recovery before it gives
    # up: it is handed a refusal of its own and no scan budget, rather than
    # borrowing the earned verdict. Nothing here renders the sentence: the
    # refusal below is a fail-closed boolean on ``decrypt_error``. Both
    # parameters are required precisely so this call site had to answer the
    # question — a settle path must not grow a distribution scan by inheriting a
    # default.
    row = await client._decrypt_thread_row(payee_agent_id, msg, SenderKeyRefusal(), recovery=None)
    if is_authenticity_failure(row.verification_status):
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced quote {ref} failed sender-signature verification — refusing to settle",
        )
    if row.decrypt_error is not None or row.plaintext is None:
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced quote {ref} could not be decrypted by the payee — refusing to settle",
        )
    quote = parse_x402_payload(row.plaintext)
    accepts = quote.get("accepts")
    if not isinstance(accepts, list):
        raise X402Error(
            X402ErrorCode.NO_QUOTE,
            f"Referenced quote {ref} has no accepts[] — refusing to settle",
        )
    return ReferencedQuote(message_id=ref, accepts=accepts)
