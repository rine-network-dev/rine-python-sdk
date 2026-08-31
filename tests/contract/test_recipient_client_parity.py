"""The two Python clients answer a reference identically.

The tension: a contract implemented on ONE client passes every gate in this
repo. ``RineClient`` and ``SyncRineClient`` hold twin method bodies written
apart, so a rule that reaches one of them reaches the other only because
somebody carried it across — and nothing else asserts that they agree.

Two halves, and they prove different things.

**Structural.** The resolver surface is DERIVED by scanning both classes, never
hand-listed, so a resolver added to one client tomorrow fails here on the day it
is written rather than the day somebody notices. A pinned floor of the contract
entry points sits under the scan: a scan that came back empty would otherwise
pass every assertion below it.

**Behavioural.** Both clients are driven over one mocked server and their
refusals compared byte for byte — and then compared against the SAME committed
goldens the composer gate pins (the committed refusal-vector fixture). That
second comparison is the one worth having: the composer gate proves the two
STACKS compose the same sentence, and this proves both Python CLIENTS deliver
it to a caller unaltered.
The vectors are read, not restated, so there is one copy of them.

🔴 Scope. Both halves are in this directory and therefore both are reached by
``ci.sh`` stage 4, which runs ``rine-sdk/tests/contract`` and nothing else under
``rine-sdk/tests``. The deep twin suite — every rung, every recorded round trip,
in order — is ``test_recipient_parity.py`` beside this file; what is here is the
structural half and the golden comparison. They share one mocked server
(``_recipient_server.py``) rather than holding one each.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from rine import RineClient, SyncRineClient
from rine.errors import ConfigError, NotFoundError

from ._recipient_server import mocked_server

#: The contract entry points, by spelling. A floor under the derived scan, not the
#: inventory itself: the scan is what catches a FIFTH resolver, this is what
#: catches all four being deleted.
CONTRACT_ENTRY_POINTS = ("resolve_group", "resolve_group_for_join", "resolve_recipient")


def _resolvers(client_class: type) -> set[str]:
    """Every public ``resolve_*`` this class declares itself.

    ``vars`` rather than :func:`dir`, so the answer is what this class defines
    and not what a base class contributed to both of them equally — a resolver
    that only ever existed on a shared base cannot be the drift this gate looks
    for.
    """
    return {
        name
        for name, value in vars(client_class).items()
        if name.startswith("resolve_") and not name.startswith("_") and callable(value)
    }


#: Derived, never hand-listed: the union, so a resolver present on one client
#: and missing from the other is IN the surface and fails the existence test.
RESOLVER_SURFACE = _resolvers(RineClient) | _resolvers(SyncRineClient)

#: The goldens are ONE file, read and never restated, and they live with the
#: TypeScript half of the composer gate inside ``rine-core`` — a sibling package
#: in the monorepo that ships in no sdist of this one.
#:
#: Their absence is therefore a checkout shape rather than a regression, and it
#: costs only the golden comparison: the structural half below scans the two
#: clients and runs wherever this package does.
FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "rine-core"
    / "test"
    / "fixtures"
    / "refusal-vectors.json"
)

needs_the_fixture = pytest.mark.skipif(
    not FIXTURE.exists(), reason=f"refusal vectors absent (mirror or sdist?): {FIXTURE}"
)

#: The two slots a CLIENT can be driven through end to end. The composer-only
#: slots take parts no client assembles, and the ``unknown_group`` slot is
#: reached by ``resolve_group``, which is exercised by the parity half below.
CLIENT_DRIVEN_SLOTS = ("bare_recipient_group", "bare_agent_collision")


def _vectors() -> list[dict[str, Any]]:
    if not FIXTURE.exists():
        return []
    doc = json.loads(FIXTURE.read_text())
    return [v for v in doc["vectors"] if v["slot"] in CLIENT_DRIVEN_SLOTS]


def _said(act: Any) -> tuple[type | None, str | None]:
    """The refusal a call raised as ``(type, detail)``, or ``(None, None)``.

    ``detail``, never ``str(error)``: ``RineApiError`` renders itself as
    ``"404: <detail>"``, and the status prefix is transport rather than a byte
    of the composed sentence the goldens pin.
    """
    try:
        act()
    except (ConfigError, NotFoundError) as refused:
        return type(refused), getattr(refused, "detail", str(refused))
    return None, None


async def _asked(coro_factory: Any) -> tuple[type | None, str | None]:
    try:
        await coro_factory()
    except (ConfigError, NotFoundError) as refused:
        return type(refused), getattr(refused, "detail", str(refused))
    return None, None


def test_the_resolver_surface_when_scanned_then_it_is_not_empty() -> None:
    # An empty scan passes every assertion below it, and the floor is what
    # catches the surface being renamed out from under this file wholesale.
    assert RESOLVER_SURFACE, "scanned both clients and found no resolver at all"
    assert set(CONTRACT_ENTRY_POINTS) <= RESOLVER_SURFACE, (
        f"the contract names {CONTRACT_ENTRY_POINTS}; the clients declare {RESOLVER_SURFACE}"
    )


@pytest.mark.parametrize("name", sorted(RESOLVER_SURFACE))
def test_a_resolver_when_declared_on_either_client_then_both_declare_it(name: str) -> None:
    missing = [c.__name__ for c in (RineClient, SyncRineClient) if not hasattr(c, name)]
    assert not missing, f"{name}() is a resolver {missing} does not have — the drift itself"


@pytest.mark.parametrize("name", sorted(RESOLVER_SURFACE))
def test_a_resolver_when_declared_on_both_then_the_signatures_are_identical(name: str) -> None:
    # Parameter names are part of it: these are keyword-callable, so a
    # `reference=`/`ref=` split is a caller-visible break even though both
    # clients would still answer a positional call.
    asynchronous = inspect.signature(getattr(RineClient, name))
    synchronous = inspect.signature(getattr(SyncRineClient, name))
    assert str(asynchronous) == str(synchronous), f"{name}() has drifted between the two clients"


@pytest.mark.parametrize("name", sorted(RESOLVER_SURFACE))
def test_a_resolver_when_compared_across_the_clients_then_only_awaitability_differs(
    name: str,
) -> None:
    # The whole of the intended difference. A synchronous method that quietly
    # became a coroutine returns an un-awaited object to every caller that was
    # written against the synchronous client, and nothing else in this file
    # would notice.
    assert inspect.iscoroutinefunction(getattr(RineClient, name)), f"{name}() must be awaitable"
    assert not inspect.iscoroutinefunction(getattr(SyncRineClient, name)), (
        f"{name}() must not be awaitable on the synchronous client"
    )


@needs_the_fixture
@pytest.mark.parametrize("vector", _vectors(), ids=lambda v: v["id"])
async def test_a_refusal_when_read_through_both_clients_then_it_is_the_golden_byte_for_byte(
    vector: dict[str, Any], async_client: Any, sync_client: Any
) -> None:
    """One vector, both clients, and the sentence the composer gate pinned.

    A failure here is one of three things and the message says which: the two
    clients disagree, or they agree with each other and not with the composer
    goldens — which means a client is rewriting a refusal on its way out.
    """
    spelling, groups, agents = vector["spelling"], vector["candidates"], vector["agents"]

    with mocked_server(groups, agents):
        asynchronous = await _asked(lambda: async_client.resolve_recipient(spelling))
    await async_client.close()

    with mocked_server(groups, agents):
        synchronous = _said(lambda: sync_client.resolve_recipient(spelling))

    assert asynchronous == synchronous, f"{vector['id']}: the two clients answered differently"
    assert synchronous[0] is not None, f"{vector['id']}: expected a refusal, got an answer"
    assert synchronous[1] == vector["expected"], (
        f"{vector['id']}: the client did not deliver the composer's golden"
    )
