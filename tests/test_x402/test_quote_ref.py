"""The quote ref is payer-controlled, and it names a URL.

:func:`rine.x402.quote_ref.load_referenced_quote` interpolates the payer's
``extensions[X402_QUOTE_REF_KEY]`` straight into ``GET /messages/{ref}`` with the
PAYEE's own credentials and acting-agent header on it. Every other guard in that
function reads the RESPONSE, so before this refusal existed the only thing between a
payer and any endpoint the payee can reach was ``isinstance(ref, str) and ref != ""``
— and the server has GETs that MUTATE (``/agents/{id}/mls/welcomes`` consumes the
welcomes it hands back, and its route commits), so a payer could spend the payee's
credentials on a destructive read and take the fail-closed ``NO_QUOTE`` as cover.

🔴 The load-bearing assertion in every refusal test here is ``calls.call_count == 0``,
never the raised error. A guard that refused on the way back would satisfy an
error-shape assertion and still have issued the request — the damage is done by the
request, not by the return value. The network is the only thing faked: the client is
a real :class:`~rine.RineClient` and respx counts what actually left it.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from rine import RineClient
from rine._config import save_credentials
from rine.x402.errors import X402Error, X402ErrorCode
from rine.x402.quote_ref import load_referenced_quote
from rine.x402.types import X402_QUOTE_REF_KEY

API = "https://rine.network"
PAYEE_AGENT_ID = "44444444-0000-4000-8000-000000000004"
CONVERSATION_ID = "22222222-0000-4000-8000-000000000002"
QUOTE_ID = "66666666-0000-4000-8000-000000000006"


def _payment(ref: Any) -> dict[str, Any]:
    """A signed payment carrying whatever ref the caller wants to smuggle."""
    return {
        "x402Version": 2,
        "accepted": {"scheme": "exact", "network": "eip155:84532", "amount": "1"},
        "payload": {"signature": "0xsig", "authorization": {}},
        "extensions": {X402_QUOTE_REF_KEY: ref},
    }


@pytest.fixture
def payee_client(tmp_config_dir, saved_agent_keys):
    """A real client, credentialled, whose acting agent needs no lookup.

    ``agent=`` is a UUID so the resolution rung short-circuits: any request the
    client makes on its own account would otherwise be counted against the guard
    and make a passing test meaningless.
    """
    save_credentials(tmp_config_dir, {"default": {"client_id": "cid", "client_secret": "sec"}})
    return RineClient(config_dir=tmp_config_dir, api_url=API, agent=PAYEE_AGENT_ID)


def _mock_the_whole_api() -> None:
    """Answer every route, so a leaked request is a counted request and not a crash."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": PAYEE_AGENT_ID,
                        "name": "payee",
                        "handle": "payee@myorg.rine.network",
                        "human_oversight": True,
                        "incoming_policy": "accept_all",
                        "outgoing_policy": "send_all",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ],
                "total": 1,
            },
        )
    )
    respx.route().mock(return_value=httpx.Response(404, json={"detail": "not found"}))


def _get_paths() -> list[str]:
    """Every GET path this client actually put on the wire, in order."""
    return [c.request.url.path for c in respx.calls if c.request.method == "GET"]


async def _load(client: RineClient, ref: Any) -> Any:
    return await load_referenced_quote(client, _payment(ref), CONVERSATION_ID, None)


@respx.mock
async def test_load_when_the_ref_traverses_to_a_mutating_get_then_no_request_is_issued(
    payee_client,
) -> None:
    """The audit's own reproduction: a traversal into the MLS welcome drain.

    ``GET /agents/{id}/mls/welcomes`` is "fetch and consume" — it stamps
    ``consumed_at`` on every welcome it returns and the route commits. One settle of
    a payment the payee never has to accept and the payee's pending welcomes are
    gone: every group it was mid-join on becomes un-decryptable, while the payer
    sees nothing but an ordinary ``NO_QUOTE``.
    """
    _mock_the_whole_api()

    with pytest.raises(X402Error) as exc:
        await _load(payee_client, f"../agents/{PAYEE_AGENT_ID}/mls/welcomes")

    assert exc.value.code == X402ErrorCode.NO_QUOTE
    assert respx.calls.call_count == 0


@respx.mock
async def test_load_when_the_ref_appends_a_query_string_then_no_request_is_issued(
    payee_client,
) -> None:
    """A ref that keeps the path and rewrites the query is still a different request."""
    _mock_the_whole_api()

    with pytest.raises(X402Error):
        await _load(payee_client, f"{QUOTE_ID}?limit=1000")

    assert respx.calls.call_count == 0


@respx.mock
async def test_load_when_the_ref_is_not_an_id_at_all_then_no_request_is_issued(
    payee_client,
) -> None:
    """The cheapest case, and the one a fuzzer finds first."""
    _mock_the_whole_api()

    with pytest.raises(X402Error) as exc:
        await _load(payee_client, "quote-9999")

    # A settle path must not learn a NEW error class from a hostile ref: the surfaces
    # above it branch on NO_QUOTE and would render anything else as an internal
    # failure of the payee's own.
    assert exc.value.code == X402ErrorCode.NO_QUOTE
    assert respx.calls.call_count == 0


@respx.mock
async def test_load_when_the_ref_is_a_real_id_then_the_message_is_fetched(
    payee_client,
) -> None:
    """The control, and the reason the refusals above prove anything.

    This harness DOES reach the network when the ref is a real id, so a zero call
    count above is the guard and not a broken fixture.
    """
    _mock_the_whole_api()

    with pytest.raises(X402Error):
        await _load(payee_client, QUOTE_ID)

    assert f"/messages/{QUOTE_ID}" in _get_paths()


@respx.mock
async def test_load_when_the_ref_is_dashless_then_it_is_still_fetched(payee_client) -> None:
    """🔴 A pre-flight may only refuse what the wire would have refused.

    The server types this path parameter ``uuid.UUID``, which has always read the
    dashless spelling as an id, so refusing it here would be a capability removal
    wearing a validation fix. This is the test that would catch one.
    """
    _mock_the_whole_api()
    dashless = QUOTE_ID.replace("-", "")

    with pytest.raises(X402Error):
        await _load(payee_client, dashless)

    assert f"/messages/{dashless}" in _get_paths()
