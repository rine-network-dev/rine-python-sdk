"""Payee `fulfill` orchestrator: settle-first ordering + failure-branch parity.

Mirrors the TS payee contract (``rine-ts-sdk/src/resources/x402-payee.ts``): verify
runs before settle, settle is skipped on an invalid verification, the synthetic
failure receipt attributes ``payer`` from the SIGNED payload's
``authorization.from`` (not the facilitator body) with a ``"verification_failed"``
default reason, and the cleartext receipt marker stays ``{status, rail}``-only.

Externals only are mocked: the facilitator HTTP via ``respx`` and the client via a
recording fake. ``fulfill`` itself — the thing under test — is exercised through its
public interface.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from rine.types import DecryptedMessage, MessageRead
from rine.x402 import FulfillResult, extract_payment_payload, fulfill, send_receipt
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.facilitator import FacilitatorClient

FAC_URL = "https://fac.local"
PAYMENT_ID = "11111111-0000-0000-0000-000000000001"
CONVERSATION_ID = "22222222-0000-0000-0000-000000000002"
SIGNED_PAYER = "0xSignerFromAuthorization"

REQUIREMENT = {
    "scheme": "exact",
    "network": "eip155:84532",
    "amount": "150000",
    "asset": "0xeurc",
    "payTo": "0xpayee",
    "maxTimeoutSeconds": 600,
    "extra": {"name": "EURC", "version": "2"},
}
PAYMENT_PAYLOAD = {
    "x402Version": 2,
    "accepted": REQUIREMENT,
    "payload": {
        "signature": "0xsig",
        "authorization": {"from": SIGNED_PAYER, "to": "0xpayee", "value": "150000"},
    },
}
SETTLED = {
    "success": True,
    "transaction": "0xhash",
    "network": "base-sepolia",  # PayAI echoes the v1 slug — stored verbatim
    "payer": SIGNED_PAYER,
    "amount": "150000",  # economics live in the body, never the marker
}


def _payment_message(**overrides: Any) -> DecryptedMessage:
    """Build a decrypted ``rine.v1.x402_payment`` message (override any field)."""
    data: dict[str, Any] = {
        "id": PAYMENT_ID,
        "conversation_id": CONVERSATION_ID,
        "from_agent_id": "33333333-0000-0000-0000-000000000003",
        "to_agent_id": "44444444-0000-0000-0000-000000000004",
        "type": "rine.v1.x402_payment",
        "encrypted_payload": "enc",
        "created_at": "2024-01-01T00:00:00Z",
        "plaintext": json.dumps(PAYMENT_PAYLOAD),
        "decrypt_error": None,
    }
    data.update(overrides)
    return DecryptedMessage.model_validate(data)


class FakeReplyClient:
    """Recording stand-in for ``RineClient``; echoes the reply as a ``MessageRead``."""

    def __init__(self) -> None:
        """Start with no recorded replies."""
        self.replies: list[dict[str, Any]] = []

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


# --- extract_payment_payload guards -----------------------------------------


def test_extract_payment_payload_when_valid_returns_verbatim_object() -> None:
    """A well-formed payment message yields the verbatim x402 PaymentPayload."""
    pp = extract_payment_payload(_payment_message())
    assert pp["accepted"]["asset"] == "0xeurc"
    assert pp["payload"]["authorization"]["from"] == SIGNED_PAYER


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


# --- fulfill: valid branch (verify → settle → receipt) ----------------------


@respx.mock
async def test_fulfill_when_valid_settles_and_sends_completed_receipt() -> None:
    """Valid verify → settle runs, receipt is the settlement verbatim, marker done."""
    respx.post(f"{FAC_URL}/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True, "payer": SIGNED_PAYER})
    )
    respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json=SETTLED))
    client = FakeReplyClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac, agent="payee")

    assert isinstance(result, FulfillResult)
    assert result.verification["isValid"] is True
    assert result.settlement is not None and result.settlement["transaction"] == "0xhash"
    # settle-first: /verify strictly before /settle on the wire.
    assert [c.request.url.path for c in respx.calls] == ["/verify", "/settle"]
    (reply,) = client.replies
    assert reply["message_id"] == PAYMENT_ID
    assert reply["message_type"] == "rine.v1.x402_receipt"
    assert reply["agent"] == "payee"
    # Body preserves the settlement verbatim, including the v1 slug + economics.
    assert reply["payload"]["success"] is True
    assert reply["payload"]["network"] == "base-sepolia"
    assert reply["payload"]["amount"] == "150000"
    # Marker is {status, rail}-only — economics never leak into the cleartext.
    assert reply["metadata"]["rine.x402"] == {"status": "payment-completed", "rail": "x402"}


@respx.mock
async def test_fulfill_when_add_marker_false_emits_no_marker() -> None:
    """The marker is opt-out: add_marker=False sends an empty metadata."""
    respx.post(f"{FAC_URL}/verify").mock(
        return_value=httpx.Response(200, json={"isValid": True, "payer": SIGNED_PAYER})
    )
    respx.post(f"{FAC_URL}/settle").mock(return_value=httpx.Response(200, json=SETTLED))
    client = FakeReplyClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        await fulfill(client, _payment_message(), facilitator=fac, add_marker=False)

    assert client.replies[0]["metadata"] == {}


# --- fulfill: invalid branch (settle skipped, synthetic failure receipt) -----


@respx.mock
async def test_fulfill_when_invalid_skips_settle_and_attributes_payer_from_payload() -> None:
    """Invalid verify: no settle; failure receipt payer is authorization.from."""
    # The facilitator body reports a DIFFERENT payer than the signed authorization;
    # the receipt must attribute from the payload, killing the e2e's historic drift.
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
    client = FakeReplyClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        result = await fulfill(client, _payment_message(), facilitator=fac)

    assert result.settlement is None
    assert not settle_route.called  # settle skipped entirely on invalid
    body = client.replies[0]["payload"]
    assert body["success"] is False
    assert body["transaction"] == ""
    assert body["network"] == REQUIREMENT["network"]  # from pp.accepted, not the body
    assert body["payer"] == SIGNED_PAYER  # authorization.from, NOT the facilitator echo
    assert body["errorReason"] == "insufficient_funds"
    assert client.replies[0]["metadata"]["rine.x402"] == {
        "status": "payment-failed",
        "rail": "x402",
    }


@respx.mock
async def test_fulfill_when_invalid_without_reason_defaults_to_verification_failed() -> None:
    """A failed verify with no invalidReason defaults the reason to the TS string."""
    respx.post(f"{FAC_URL}/verify").mock(return_value=httpx.Response(200, json={"isValid": False}))
    client = FakeReplyClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        await fulfill(client, _payment_message(), facilitator=fac)

    assert client.replies[0]["payload"]["errorReason"] == "verification_failed"


@respx.mock
async def test_fulfill_when_wrong_message_type_raises_before_facilitator() -> None:
    """A wrong-type payment raises without touching the facilitator or replying."""
    verify_route = respx.post(f"{FAC_URL}/verify")
    client = FakeReplyClient()

    async with FacilitatorClient("x402-rs", base_url=FAC_URL) as fac:
        with pytest.raises(X402Error):
            await fulfill(client, _payment_message(type="rine.v1.dm"), facilitator=fac)

    assert not verify_route.called
    assert client.replies == []


# --- send_receipt primitive --------------------------------------------------


async def test_send_receipt_threads_settlement_verbatim() -> None:
    """send_receipt wraps a SettlementResponse verbatim (unknown keys preserved)."""
    client = FakeReplyClient()
    settlement = dict(SETTLED, extensions={"k": "v"})

    receipt = await send_receipt(client, _payment_message(), settlement, agent="payee")

    assert receipt.type == "rine.v1.x402_receipt"
    body = client.replies[0]["payload"]
    assert body["extensions"] == {"k": "v"}
    assert client.replies[0]["metadata"]["rine.x402"]["status"] == "payment-completed"
