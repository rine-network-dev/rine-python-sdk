"""Payee ``fulfill`` orchestrator: quote-ref binding + settle-first + failure parity.

The payee must settle against the ONE quote the payment answers — the payer stamps
that quote's id into the signed ``extensions[X402_QUOTE_REF_KEY]`` and the payee
re-loads THAT message (proving it is a payee-issued quote in this conversation),
never the payer's echoed ``accepted``. A payment with a missing / forged /
cross-conversation ref, or one whose ``accepted`` diverges from the referenced
quote, is REFUSED before the facilitator is contacted. Everything is exercised
through the public ``fulfill`` / ``verify`` / ``settle`` interface; only externals are
faked (the facilitator HTTP via ``respx``, the client via a recording fake that
serves the referenced quote by id).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest
import respx

from rine.errors import NotFoundError
from rine.types import DecryptedMessage, MessageRead
from rine.x402 import (
    FulfillResult,
    extract_payment_payload,
    fulfill,
    send_receipt,
)
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.facilitator import FacilitatorClient
from rine.x402.payee_settle import settle, verify
from rine.x402.types import X402_QUOTE_REF_KEY

if TYPE_CHECKING:
    from rine._render_recovery import RenderRecovery
    from rine.sender_key_words import SenderKeyRefusal

FAC_URL = "https://fac.local"
PAYMENT_ID = "11111111-0000-0000-0000-000000000001"
QUOTE_ID = "66666666-0000-0000-0000-000000000006"
CONVERSATION_ID = "22222222-0000-0000-0000-000000000002"
PAYER_AGENT_ID = "33333333-0000-0000-0000-000000000003"
PAYEE_AGENT_ID = "44444444-0000-0000-0000-000000000004"
SIGNED_PAYER = "0xSignerFromAuthorization"
PAYEE_ADDR = "0xpayee"

REQUIREMENT = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "150000",
    "asset": "0xeurc",
    "payTo": PAYEE_ADDR,
    "maxTimeoutSeconds": 600,
    "extra": {"name": "EURC", "version": "2"},
}
SETTLED = {
    "success": True,
    "transaction": "0xhash",
    "network": "base-sepolia",  # PayAI echoes the v1 slug — stored verbatim
    "payer": SIGNED_PAYER,
    "amount": "150000",  # economics live in the body, never the marker
}


def _payment_payload(
    *, ref: str | None = QUOTE_ID, signed: str | None = None, **accepted_overrides: Any
) -> dict[str, Any]:
    """A signed ``PaymentPayload`` stamping a quote-ref; ``accepted`` may diverge.

    ``signed`` is the SIGNED EIP-3009 ``authorization.value`` (defaults to the named
    ``accepted.amount`` = honest payer); pass it to express overpayment on the signed
    value while ``accepted`` still names the quoted tier exactly.
    """
    accepted = {**REQUIREMENT, **accepted_overrides}
    value = signed if signed is not None else accepted["amount"]
    extensions = {X402_QUOTE_REF_KEY: ref} if ref is not None else {}
    return {
        "x402Version": 2,
        "accepted": accepted,
        "payload": {
            "signature": "0xsig",
            "authorization": {"from": SIGNED_PAYER, "to": PAYEE_ADDR, "value": value},
        },
        "extensions": extensions,
    }


def _payment_message(payload: dict[str, Any] | None = None, **overrides: Any) -> DecryptedMessage:
    """Build a decrypted ``rine.v1.x402_payment`` message (override any field)."""
    data: dict[str, Any] = {
        "id": PAYMENT_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": PAYER_AGENT_ID,
        "to_agent_id": PAYEE_AGENT_ID,
        "type": "rine.v1.x402_payment",
        "direction": "received",
        "encrypted_payload": "enc",
        "created_at": "2024-01-01T00:00:00Z",
        "plaintext": json.dumps(payload if payload is not None else _payment_payload()),
        "decrypt_error": None,
    }
    data.update(overrides)
    return DecryptedMessage.model_validate(data)


def _quote_msg(**overrides: Any) -> dict[str, Any]:
    """The raw ``GET /messages/{ref}`` server row for the payee's own issued quote."""
    data: dict[str, Any] = {
        "id": QUOTE_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": PAYEE_AGENT_ID,
        "to_agent_id": PAYER_AGENT_ID,
        "type": "rine.v1.x402_payment_required",
        "direction": "sent",
        "encrypted_payload": "enc",
        "self_encrypted_payload": "self-sealed",
        "created_at": "2024-01-01T00:00:00Z",
    }
    data.update(overrides)
    return data


class FakeRefClient:
    """Recording ``RineClient`` stand-in that serves the referenced quote by id."""

    def __init__(
        self,
        *,
        quote_msg: dict[str, Any] | None = "__default__",  # type: ignore[assignment]
        accepts: list[dict[str, Any]] | None = None,
        get_error: Exception | None = None,
        verification_status: str = "verified",
    ) -> None:
        """Seed the served quote row + its decrypted ``accepts[]`` (both faked)."""
        self.replies: list[dict[str, Any]] = []
        self._quote_msg = _quote_msg() if quote_msg == "__default__" else quote_msg
        self._accepts = accepts if accepts is not None else [REQUIREMENT]
        self._get_error = get_error
        self._verification_status = verification_status
        self._http = _FakeHttp(self)

    async def _resolve_agent_id(self, agent: str | None = None) -> str:
        """Resolve the acting payee agent id (binds the ref check)."""
        return PAYEE_AGENT_ID

    async def _agent_header(self, agent: str | None = None) -> dict[str, str]:
        """The X-Rine-Agent header the loader forwards on the by-id fetch."""
        return {"X-Rine-Agent": PAYEE_AGENT_ID}

    async def _decrypt_thread_row(
        self,
        agent_id: str,
        msg: DecryptedMessage,
        refusal: SenderKeyRefusal,
        *,
        recovery: RenderRecovery | None,
    ) -> DecryptedMessage:
        """Fake the self-seal decrypt: attach the quote plaintext + verification.

        ``refusal`` and ``recovery`` are unused here and still declared: this
        double stands in for the real signature, and a double that quietly
        accepts fewer arguments than the thing it replaces is how a caller
        drifts unnoticed. ``recovery`` has no default for the same reason it has
        none on the real method — a settle path must state that it runs no
        sender-key scan rather than inherit that answer.
        """
        assert recovery is None, "the settle path must not spend a distribution scan"
        msg.verification_status = self._verification_status  # type: ignore[assignment]
        if self._verification_status == "invalid":
            msg.decrypt_error = "forged sender signature"
            msg.plaintext = None
        else:
            msg.plaintext = json.dumps(
                {"x402Version": 2, "accepts": self._accepts, "extensions": {}}
            )
        return msg

    async def reply(
        self,
        message_id: str,
        payload: dict[str, Any],
        *,
        message_type: str,
        metadata: dict[str, Any] | None = None,
        content_type: str | None = None,
        agent: str | None = None,
    ) -> MessageRead:
        """Record the reply kwargs and return a matching ``MessageRead``."""
        self.replies.append(
            {
                "message_id": message_id,
                "payload": payload,
                "message_type": message_type,
                "metadata": metadata or {},
                "content_type": content_type,
                "agent": agent,
            }
        )
        return MessageRead.model_validate(
            {
                "id": "55555555-0000-0000-0000-000000000005",
                "conversation_id": CONVERSATION_ID,
                "type": message_type,
                "encrypted_payload": "enc",
                "content_type": content_type,
                "metadata": metadata or {},
                "created_at": "2024-01-01T00:00:05Z",
            }
        )


class _FakeHttp:
    """Serves ``GET /messages/{ref}`` from the fake client's seeded quote row."""

    def __init__(self, outer: FakeRefClient) -> None:
        self._outer = outer

    async def get(
        self, path: str, *, extra_headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        if self._outer._get_error is not None:
            raise self._outer._get_error
        if self._outer._quote_msg is None:
            raise NotFoundError(f"no message at {path}")
        return self._outer._quote_msg


# --- extract_payment_payload guards -----------------------------------------


def test_extract_payment_payload_when_valid_returns_verbatim_object() -> None:
    """A well-formed payment message yields the verbatim x402 PaymentPayload."""
    pp = extract_payment_payload(_payment_message())
    assert pp["accepted"]["asset"] == "0xeurc"
    assert pp["payload"]["authorization"]["from"] == SIGNED_PAYER
    assert pp["extensions"][X402_QUOTE_REF_KEY] == QUOTE_ID


def test_extract_payment_payload_when_wrong_type_raises_x402error() -> None:
    """A non-payment message type is a structured invalid-requirement refusal."""
    with pytest.raises(X402Error) as exc:
        extract_payment_payload(_payment_message(type="rine.v1.task_request"))
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT


def test_extract_payment_payload_when_decrypt_failed_raises_x402error() -> None:
    """A decrypt failure refuses before any facilitator work runs."""
    with pytest.raises(X402Error) as exc:
        extract_payment_payload(_payment_message(plaintext=None, decrypt_error="bad tag"))
    assert exc.value.code == X402ErrorCode.INVALID_REQUIREMENT


def test_extract_payment_payload_when_no_plaintext_raises_x402error() -> None:
    """A missing plaintext (no decrypt_error) is still refused structurally."""
    with pytest.raises(X402Error):
        extract_payment_payload(_payment_message(plaintext=None))


def test_extract_payment_payload_when_missing_accepted_raises_malformed() -> None:
    """A payment lacking the top-level accepted object is a typed refusal."""
    body = {"x402Version": 2, "payload": {"authorization": {"from": "0xa"}}}
    with pytest.raises(X402Error) as exc:
        extract_payment_payload(_payment_message(plaintext=json.dumps(body)))
    assert exc.value.code == X402ErrorCode.MALFORMED_PAYLOAD


def test_extract_payment_payload_when_missing_authorization_raises_malformed() -> None:
    """A payment whose payload lacks authorization is refused, not deref'd."""
    body = {"x402Version": 2, "accepted": REQUIREMENT, "payload": {}}
    with pytest.raises(X402Error) as exc:
        extract_payment_payload(_payment_message(plaintext=json.dumps(body)))
    assert exc.value.code == X402ErrorCode.MALFORMED_PAYLOAD


# --- fulfill: valid ref-bind branch (reconcile → verify → settle → receipt) --


@respx.mock
async def test_fulfill_when_valid_ref_settles_and_surfaces_matched_quote() -> None:
    """Payment referencing the payee's own quote: verify → settle; matched quote surfaced."""
    respx.post(f"{FAC_URL}/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True, "payer": SIGNED_PAYER})
    )
    respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json=SETTLED))
    client = FakeRefClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac, agent="payee")

    assert isinstance(result, FulfillResult)
    assert result.settlement is not None and result.settlement["transaction"] == "0xhash"
    assert result.matched_quote is not None
    assert result.matched_quote.quote_message_id == QUOTE_ID
    assert result.matched_quote.amount == "150000"
    assert result.matched_quote.asset == "0xeurc"
    assert [c.request.url.path for c in respx.calls] == ["/verify", "/settle"]
    (reply,) = client.replies
    assert reply["message_id"] == PAYMENT_ID
    assert reply["payload"]["success"] is True
    assert reply["metadata"]["rine.x402"] == {"status": "payment-completed", "rail": "x402"}


@respx.mock
async def test_fulfill_when_overpaid_settles_against_the_payee_quote() -> None:
    """An overpayment (signed value > quoted, same named terms) reconciles against the quote."""
    respx.post(f"{FAC_URL}/verify").mock(return_value=httpx.Response(200, json={"isValid": True}))
    settle_route = respx.post(f"{FAC_URL}/settle").mock(
        return_value=httpx.Response(200, json=SETTLED)
    )
    client = FakeRefClient()
    overpaid = _payment_message(_payment_payload(signed="200000"))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, overpaid, facilitator=fac)

    assert result.settlement is not None
    # The requirement forwarded to the facilitator is the PAYEE's quote, not the payer's echo.
    settle_body = json.loads(settle_route.calls.last.request.content)
    assert settle_body["paymentRequirements"]["amount"] == "150000"


@respx.mock
async def test_fulfill_with_expected_override_settles_without_a_ref() -> None:
    """An explicit ``expected`` term authorises an out-of-band quote — no ref fetched."""
    respx.post(f"{FAC_URL}/verify").mock(return_value=httpx.Response(200, json={"isValid": True}))
    respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json=SETTLED))
    # quote_msg=None → any ref fetch would 404; the override must short-circuit it.
    client = FakeRefClient(quote_msg=None)
    no_ref = _payment_message(_payment_payload(ref=None))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, no_ref, facilitator=fac, expected=REQUIREMENT)

    assert result.settlement is not None
    assert result.matched_quote is not None
    assert result.matched_quote.quote_message_id is None  # operator override, no quote id
    assert client.replies[0]["payload"]["success"] is True


@respx.mock
async def test_fulfill_when_add_marker_false_emits_no_marker() -> None:
    """The marker is opt-out: add_marker=False sends an empty metadata."""
    respx.post(f"{FAC_URL}/verify").mock(return_value=httpx.Response(200, json={"isValid": True}))
    respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json=SETTLED))
    client = FakeRefClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        await fulfill(client, _payment_message(), facilitator=fac, add_marker=False)

    assert client.replies[0]["metadata"] == {}


# --- fulfill: hostile-payer refusals (ref valid, accepted tampered) ----------


@respx.mock
async def test_fulfill_when_payto_redirected_refuses_before_facilitator() -> None:
    """A payment redirecting payTo to the attacker is refused; /verify never called."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    settle_route = respx.post(f"{FAC_URL}/settle")
    client = FakeRefClient()
    attack = _payment_message(_payment_payload(payTo="0xMALLORY"))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, attack, facilitator=fac)

    assert result.settlement is None and result.matched_quote is None
    assert not verify_route.called and not settle_route.called
    body = client.replies[0]["payload"]
    assert body["success"] is False
    assert body["errorReason"] == X402ErrorCode.REQUIREMENT_MISMATCH
    assert client.replies[0]["metadata"]["rine.x402"]["status"] == "payment-failed"


@respx.mock
async def test_fulfill_when_underpaid_refuses_before_facilitator() -> None:
    """An underpayment (1 atomic unit vs quoted 150000) is refused before /verify."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient()
    attack = _payment_message(_payment_payload(amount="1"))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, attack, facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.REQUIREMENT_MISMATCH


@respx.mock
async def test_fulfill_when_wrong_asset_refuses_before_facilitator() -> None:
    """A worthless-token asset swap is refused before /verify."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient()
    attack = _payment_message(_payment_payload(asset="0xWORTHLESS"))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, attack, facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.REQUIREMENT_MISMATCH


# --- fulfill: fail-closed on missing / forged / cross-quote ref --------------


@respx.mock
async def test_fulfill_when_no_ref_refuses_fail_closed() -> None:
    """A payment carrying no quote-ref and no override → fail closed (no-quote)."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient()
    no_ref = _payment_message(_payment_payload(ref=None))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, no_ref, facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.NO_QUOTE


@respx.mock
async def test_fulfill_when_ref_points_at_another_agents_quote_refuses() -> None:
    """A forged ref to a quote NOT issued by this payee (wrong from) → fail closed."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient(quote_msg=_quote_msg(from_agent_id=PAYER_AGENT_ID))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.NO_QUOTE


@respx.mock
async def test_fulfill_when_ref_points_at_cross_conversation_quote_refuses() -> None:
    """A ref to a payee quote in a DIFFERENT conversation → fail closed."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    other_convo = "99999999-0000-0000-0000-000000000009"
    client = FakeRefClient(quote_msg=_quote_msg(conversation_id=other_convo))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.NO_QUOTE


@respx.mock
async def test_fulfill_when_ref_unresolvable_refuses() -> None:
    """A ref whose message id 404s → fail closed (no-quote), never a crash."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient(quote_msg=None)

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.NO_QUOTE


@respx.mock
async def test_fulfill_when_referenced_quote_signature_invalid_refuses() -> None:
    """A referenced quote failing self-seal signature verification → fail closed."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient(verification_status="invalid")

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.NO_QUOTE


@respx.mock
async def test_fulfill_when_malformed_payload_threads_graceful_failure() -> None:
    """A malformed payment body yields a graceful failure receipt, never a crash."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient()
    malformed = _payment_message(plaintext=json.dumps({"payload": {}}))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, malformed, facilitator=fac)

    assert result.settlement is None
    assert not verify_route.called
    assert client.replies[0]["payload"]["errorReason"] == X402ErrorCode.MALFORMED_PAYLOAD


# --- fulfill: invalid verification (reconciled, but facilitator rejects) ------


@respx.mock
async def test_fulfill_when_invalid_skips_settle_and_attributes_payer_from_payload() -> None:
    """Reconciled but invalid verify: no settle; receipt payer is authorization.from."""
    respx.post(f"{FAC_URL}/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "isValid": False,
                "payer": "0xFACILITATOR_ECHOED",
                "invalidReason": "insufficient_funds",
            },
        )
    )
    settle_route = respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json={}))
    client = FakeRefClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not settle_route.called
    body = client.replies[0]["payload"]
    assert body["success"] is False
    assert body["network"] == REQUIREMENT["network"]
    assert body["payer"] == SIGNED_PAYER  # authorization.from, NOT the facilitator echo
    assert body["errorReason"] == "insufficient_funds"


@respx.mock
async def test_fulfill_when_invalid_without_reason_defaults_to_verification_failed() -> None:
    """A failed verify with no invalidReason defaults the reason to the TS string."""
    respx.post(f"{FAC_URL}/verify").mock(return_value=httpx.Response(200, json={"isValid": False}))
    client = FakeRefClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        await fulfill(client, _payment_message(), facilitator=fac)

    assert client.replies[0]["payload"]["errorReason"] == "verification_failed"


@respx.mock
async def test_fulfill_when_wrong_message_type_raises_before_facilitator() -> None:
    """A wrong-type payment raises without touching the facilitator or replying."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeRefClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        with pytest.raises(X402Error):
            await fulfill(client, _payment_message(type="rine.v1.dm"), facilitator=fac)

    assert not verify_route.called
    assert client.replies == []


# --- standalone verify / settle (settle-after-delivery, fail-closed) ---------


@respx.mock
async def test_standalone_verify_without_expected_fails_closed() -> None:
    """No thread context + no ``expected`` → NO_QUOTE before the facilitator."""
    verify_route = respx.post(f"{FAC_URL}/verify")

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        with pytest.raises(X402Error) as exc:
            await verify(_payment_message(), facilitator=fac)

    assert exc.value.code == X402ErrorCode.NO_QUOTE
    assert not verify_route.called


@respx.mock
async def test_standalone_settle_without_expected_fails_closed() -> None:
    """settle mirrors verify: no ``expected`` → NO_QUOTE, facilitator untouched."""
    settle_route = respx.post(f"{FAC_URL}/settle")

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        with pytest.raises(X402Error) as exc:
            await settle(_payment_message(), facilitator=fac)

    assert exc.value.code == X402ErrorCode.NO_QUOTE
    assert not settle_route.called


@respx.mock
async def test_standalone_verify_with_expected_forwards_reconciled_requirement() -> None:
    """With ``expected`` the RECONCILED payee requirement (not pp.accepted) reaches /verify."""
    verify_route = respx.post(f"{FAC_URL}/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True})
    )
    # payer overpays on the signed value; the reconciled terms are the payee's expected quote.
    tampered = _payment_message(_payment_payload(payTo=PAYEE_ADDR, signed="200000"))

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        res = await verify(tampered, facilitator=fac, expected=REQUIREMENT)

    assert res["isValid"] is True
    body = json.loads(verify_route.calls.last.request.content)
    assert body["paymentRequirements"]["amount"] == "150000"  # the payee quote, not the echo
    assert body["paymentRequirements"]["payTo"] == PAYEE_ADDR


@respx.mock
async def test_standalone_settle_with_expected_broadcasts() -> None:
    """With ``expected`` settle broadcasts the reconciled requirement and returns the receipt."""
    settle_route = respx.post(f"{FAC_URL}/settle").mock(
        return_value=httpx.Response(200, json=SETTLED)
    )

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        res = await settle(_payment_message(), facilitator=fac, expected=REQUIREMENT)

    assert res["transaction"] == "0xhash"
    assert settle_route.called


# --- send_receipt primitive --------------------------------------------------


async def test_send_receipt_threads_settlement_verbatim() -> None:
    """send_receipt wraps a SettlementResponse verbatim (unknown keys preserved)."""
    client = FakeRefClient()
    settlement = dict(SETTLED, extensions={"k": "v"})

    receipt = await send_receipt(client, _payment_message(), settlement, agent="payee")

    assert receipt.type == "rine.v1.x402_receipt"
    body = client.replies[0]["payload"]
    assert body["extensions"] == {"k": "v"}
    assert client.replies[0]["metadata"]["rine.x402"]["status"] == "payment-completed"
