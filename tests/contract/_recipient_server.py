"""The routes a reference resolution can reach, and a log of the ones it took.

One mocked server for both halves of the recipient gate — the structural/golden
half in ``test_recipient_client_parity.py`` and the deep behavioural twin suite
in ``test_recipient_parity.py``. They used to hold a mock each, differing only in
whether webfinger was answered and whether the traffic was recorded, which is
two chances for the two halves to end up driving different servers and calling
the difference a client defect.

Only the HTTP boundary is mocked, and it behaves like the real routes:
``?handle=`` is an equality test against the stored handle, the unfiltered
listing is the org's own, and ``GET /groups/{id}`` compares PARSED uuids —
because the server types that path parameter ``group_id: uuid.UUID``, so an
upper-cased id names the same group there and a mock that compared strings
would refuse what the wire accepts.
"""

from __future__ import annotations

import contextlib
import re
import uuid
from typing import TYPE_CHECKING, Any

import httpx
import respx

if TYPE_CHECKING:
    from collections.abc import Iterator

API = "https://rine.network"

TOKEN = {"access_token": "t", "token_type": "Bearer", "expires_in": 900}


def _asked(route: str, request: httpx.Request) -> str:
    """The route and EVERY parameter it was asked with, in a stable order.

    🔴 Every parameter, not the one filter this log was written for. The claim
    under test is that the two clients spent the same wire traffic getting to the
    same answer, and a twin that pages while its twin does not agrees on the
    answer and disagrees on the request — the exact class the traffic
    comparison exists to catch. It did not catch it: a ``params={"limit": …}``
    added to one client's ``GET /groups`` and not the other's survived the
    parity suite untouched, because only ``handle`` was ever recorded.

    Today's traffic carries nothing but ``handle``, so no recorded expectation
    moves. That is the point: the widening is free now and is not free after a
    divergence has shipped.

    Sorted, because a dict order difference between two clients is a Python
    version artefact and not a behavioural divergence.
    """
    asked = "&".join(f"{name}={value}" for name, value in sorted(request.url.params.multi_items()))
    return f"{route}?{asked}" if asked else route


def _names_the_same_group(stored: str, asked: str) -> bool:
    """Whether two spellings name one group, decided the way the route decides it.

    ``uuid.UUID`` on both sides, because that is literally the server's path
    parameter type: ``11111111-…`` and ``11111111-…`` upper-cased are one id on
    the wire. A string comparison here would let a mock refuse a spelling
    production serves, and the client would be "fixed" to match the mock.
    """
    try:
        return uuid.UUID(stored) == uuid.UUID(asked)
    except ValueError:
        return stored == asked


@contextlib.contextmanager
def mocked_server(
    groups: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    refuse_by_id: dict[str, int] | None = None,
    substitute_by_id: dict[str, dict[str, Any]] | None = None,
) -> Iterator[list[str]]:
    """Serve the org's groups and agents; yield the requests that were made.

    The log is one entry per request, naming the route and the filter, and never
    the token refresh — which is the client's business and not the ladder's. A
    caller that only needs the routes to answer can ignore what is yielded.

    ``refuse_by_id`` maps a group id to the status ``GET /groups/{id}`` answers
    it with, instead of looking it up. It is how a test reaches the two answers
    the org's own listing cannot describe: a **403**, which the real route gives
    for a group this caller is neither owner of nor seated in, and a server
    fault, which is not an answer about the reference at all.

    ``substitute_by_id`` maps a group id to the ROW the route answers it with,
    however that row is identified — the one answer a well-behaved server never
    gives, and the whole subject of the substitution check. It cannot be expressed through
    ``groups``: the lookup below is by parsed uuid, so a listing can only ever
    answer about the id it was asked for.
    """
    refusals = {name.lower(): status for name, status in (refuse_by_id or {}).items()}
    substitutes = {name.lower(): row for name, row in (substitute_by_id or {}).items()}
    with respx.mock:
        taken: list[str] = []

        def groups_route(request: httpx.Request) -> httpx.Response:
            wanted = request.url.params.get("handle")
            taken.append(_asked("GET /groups", request))
            if wanted is None:
                return httpx.Response(200, json={"items": groups})
            return httpx.Response(
                200, json={"items": [g for g in groups if g["handle"] == wanted]}
            )

        def group_by_id_route(request: httpx.Request) -> httpx.Response:
            asked = request.url.path.rsplit("/", 1)[-1]
            # The caller's own spelling is logged, not a normalised one: the id
            # rung relies on the WIRE folding case, so what went out is the assertion.
            taken.append(_asked(f"GET /groups/{asked}", request))
            refused = refusals.get(asked.lower())
            if refused is not None:
                return httpx.Response(refused, json={"detail": "refused"})
            substituted = substitutes.get(asked.lower())
            if substituted is not None:
                return httpx.Response(200, json=substituted)
            for group in groups:
                if _names_the_same_group(str(group["id"]), asked):
                    return httpx.Response(200, json=group)
            return httpx.Response(404, json={"detail": "Group not found"})

        def agents_route(request: httpx.Request) -> httpx.Response:
            taken.append(_asked("GET /agents", request))
            return httpx.Response(200, json={"items": agents})

        def webfinger_route(request: httpx.Request) -> httpx.Response:
            taken.append("GET /.well-known/webfinger")
            resource = str(request.url.params.get("resource"))
            for agent in agents:
                if resource == f"acct:{agent['handle']}":
                    return httpx.Response(
                        200, json={"aliases": [f"https://rine.network/agents/{agent['id']}"]}
                    )
            return httpx.Response(404, json={})

        respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
        respx.get(f"{API}/.well-known/webfinger").mock(side_effect=webfinger_route)
        respx.get(f"{API}/agents").mock(side_effect=agents_route)
        respx.get(f"{API}/groups").mock(side_effect=groups_route)
        respx.get(url__regex=rf"{re.escape(API)}/groups/[^/?]+$").mock(
            side_effect=group_by_id_route
        )
        yield taken
