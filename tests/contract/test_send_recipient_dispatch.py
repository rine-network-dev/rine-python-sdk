"""The PRODUCT path: which branch a ``send()`` recipient reaches, on both clients.

🔴 The tension this exists for. ``tests/contract/test_recipient_parity.py``
beside it asserts the recipient LADDER, rung by rung, and it went green for
the UUID rung while ``send()`` could not reach that rung at all: both clients
dispatched inline on ``is_bare_reference`` / ``is_sigil_group_reference`` /
``startswith("#")``, and a UUID matches none of the three, so a group's own id
fell to the 1:1 branch and the server answered the exact ``Agent not found``
the id rung exists to eliminate — while the TypeScript SDK, given the identical call,
sent to the group. A gate on the ladder cannot see that. This one drives
``send`` itself.

Two claims, and the second is not a footnote:

* a **group** UUID reaches the group branch carrying the group's own handle,
  and that handle is what ``POST /messages`` is asked with;
* **nothing else moves.** An agent UUID, an agent handle and a bare word each
  behave exactly as they did — which is what keeps the arm from being the
  widening the bare-name rule forbids. On this surface a bare word is a group send or a
  refusal, never an implicit agent send (``_group_ref.refuse_if_a_bare_agent_name``
  is what makes that safe), and this file pins that unchanged rather than
  restating the argument.

Every scenario runs on BOTH clients over one mocked server and compares the
branch, the posted body, the refusal and the wire traffic — the twin discipline
of the file beside it, for a verb rather than a resolver. The server is
``_recipient_server.py``, shared with both parity gates, so the id route's
uuid-parsing and its 403-is-a-miss behaviour are the ones production has.
"""

from __future__ import annotations

import inspect
import json
import logging
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx

from rine.errors import ConfigError, InternalServerError, RineError

from ._recipient_server import API, mocked_server

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

GROUP_UUID = "11111111-1111-1111-1111-111111111111"
KOFI_ID = "44444444-4444-4444-4444-444444444444"

OPS = {"id": GROUP_UUID, "name": "ops", "handle": "#ops@acme.rine.network"}
KOFI = {"id": KOFI_ID, "name": "kofi", "handle": "kofi@acme.rine.network"}
AN_AGENT_CALLED_OPS = {"id": KOFI_ID, "name": "ops", "handle": "ops@acme.rine.network"}

PAYLOAD = {"task": "handover"}

MESSAGE = {
    "id": "cccccccc-dddd-eeee-ffff-000000000001",
    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
    "from_agent_id": KOFI_ID,
    "type": "rine.v1.task_request",
    "encrypted_payload": "x",
    "encryption_version": "sender-key-v1",
    "sender_signing_kid": f"rine:{KOFI_ID}",
    "created_at": "2024-01-01T00:00:00Z",
}


@dataclass(frozen=True)
class Sent:
    """Everything one ``send()`` did that this gate has an opinion about.

    Compared whole between the two clients, so a divergence in the branch, in
    the body, in the refusal or in the traffic is one failed assertion and not
    four that can be added one at a time.
    """

    branches: tuple[tuple[str, str], ...]
    body: dict[str, Any] | None
    refusal: tuple[type, str] | None
    traffic: tuple[str, ...]

    @property
    def group_reads(self) -> list[str]:
        """The ``GET /groups/{id}`` reads this send paid for.

        Named because its EMPTINESS is the assertion on every recipient class
        but the UUID: that is how a widened arm — one that sent a bare word or a
        handle down the id rung — is caught, and an answer-only assertion could
        not see it.
        """
        return [asked for asked in self.traffic if asked.startswith("GET /groups/")]


def _record_the_branch(client: Any, seen: list[tuple[str, str]]) -> None:
    """Watch which of ``send()``'s two encryption branches a recipient takes.

    BOTH branches are recorded rather than one being made to fail: the claim
    under test runs in two directions — a group id must reach the group branch
    carrying the group's handle, and an agent id must still reach the 1:1
    branch carrying the id unchanged — and a recorder that raised on the 1:1
    side could only assert the first half.

    The encryption itself is not re-tested here; it is driven for real in the
    package's MLS and sender-key suites. What is replaced is the collaborator on
    the far side of the dispatch, never the dispatch, and the body each branch
    returns is the one field ``POST /messages`` routes on, so the wire assertion
    below is still about what ``send()`` addressed.
    """

    def _body(branch: str, to: str, msg_type: str) -> dict[str, Any]:
        seen.append((branch, to))
        addressed = "to_handle" if branch == "group" else "to_agent_id"
        return {addressed: to, "type": msg_type, "encrypted_payload": "x"}

    def _group(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        return SimpleNamespace(escrow_fp=None), _body("group", to, msg_type), None

    def _dm(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        return None, _body("agent", to, msg_type)

    async def _group_async(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        return _group(agent_id, to, payload, msg_type)

    async def _dm_async(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        return _dm(agent_id, to, payload, msg_type)

    asynchronous = inspect.iscoroutinefunction(type(client).send)
    client._encrypt_group = _group_async if asynchronous else _group
    client._encrypt_dm = _dm_async if asynchronous else _dm


async def _twin_send(
    async_client: Any,
    sync_client: Any,
    to: str,
    *,
    groups: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    refuse_by_id: dict[str, int] | None = None,
) -> Sent:
    """Send the same recipient on both clients, assert they agreed, answer for both.

    A failure here is never "the sync client is wrong": it is the two of them
    disagreeing, which is the defect whichever one moved. The two clients are
    driven through one code path — ``send`` is awaited only when it returns
    something awaitable — so the harness itself cannot be the asymmetry.
    """

    async def _one(client: Any) -> Sent:
        seen: list[tuple[str, str]] = []
        with mocked_server(groups, agents, refuse_by_id) as taken:
            posted = respx.post(f"{API}/messages").mock(
                return_value=httpx.Response(200, json=MESSAGE)
            )
            _record_the_branch(client, seen)
            refusal: tuple[type, str] | None = None
            try:
                answered = client.send(to, PAYLOAD)
                if inspect.isawaitable(answered):
                    await answered
            except RineError as refused:
                refusal = (type(refused), str(refused))
            body = json.loads(posted.calls[0].request.content) if posted.called else None
            return Sent(tuple(seen), body, refusal, tuple(taken))

    asynchronous = await _one(async_client)
    await async_client.close()
    synchronous = await _one(sync_client)

    assert asynchronous == synchronous, f"send({to!r}): the two clients did not agree"
    return synchronous


class TestAUuidRecipient:
    """The one spelling that reaches both namespaces, and the order that makes it safe."""

    async def test_a_group_uuid_when_sent_to_then_posts_to_that_group_s_handle(
        self, async_client, sync_client
    ):
        """The id rung, asserted on ``send`` rather than on the ladder underneath it."""
        sent = await _twin_send(async_client, sync_client, GROUP_UUID, groups=[OPS], agents=[KOFI])

        assert sent.branches == (("group", OPS["handle"]),)
        # The wire, not just the branch: ``POST /messages`` routes on
        # ``to_handle``, and there is no ``to_group_id`` to address instead.
        assert sent.body is not None
        assert sent.body["to_handle"] == OPS["handle"]
        assert "to_agent_id" not in sent.body
        # One credential-scoped read is what the widening costs, and it is the
        # ladder's — never a hand-rolled ``GET /groups/`` + id, which would drop
        # the answered-row-id check the shared read performs.
        assert sent.group_reads == [f"GET /groups/{GROUP_UUID}"]

    async def test_an_agent_uuid_when_no_group_carries_it_then_stays_a_1_to_1_send(
        self, async_client, sync_client
    ):
        """The half that must NOT move: a UUID has always been an agent id."""
        sent = await _twin_send(async_client, sync_client, KOFI_ID, groups=[OPS], agents=[KOFI])

        assert sent.branches == (("agent", KOFI_ID),)
        assert sent.body is not None
        assert sent.body["to_agent_id"] == KOFI_ID
        assert sent.refusal is None
        # The probe ran and missed. A 404 there is not an answer about the
        # recipient, and the agent rung below costs a UUID no request at all.
        assert sent.group_reads == [f"GET /groups/{KOFI_ID}"]

    async def test_a_group_uuid_when_sent_to_then_says_it_read_the_id_as_a_group(
        self, async_client, sync_client, caplog
    ):
        """No silent acceptance — the substitution is announced on both clients.

        A UUID is the one spelling that reaches both namespaces, so a caller
        who believed it held an agent id has just had a message sealed to every
        member org of a group. The CLI says so on stderr, the TS SDK on its
        warning channel, MCP on the tool result; this surface's idiom is the
        ``rine`` logger, because a library that writes to stderr behind its
        caller's back cannot be embedded.
        """
        with caplog.at_level(logging.WARNING, logger="rine"):
            await _twin_send(async_client, sync_client, GROUP_UUID, groups=[OPS], agents=[KOFI])

        said = [r.getMessage() for r in caplog.records if r.name == "rine"]
        assert len(said) == 2, "once per client, and both clients say it"
        for one in said:
            # The caller's own spelling and the handle it resolved to. A third
            # handle here, or an ``@org`` slot the caller never typed, is how
            # the template-org rule gets broken.
            assert GROUP_UUID in one
            assert OPS["handle"] in one
            assert KOFI["handle"] not in one

    async def test_an_agent_uuid_when_sent_to_then_says_nothing(
        self, async_client, sync_client, caplog
    ):
        """The arm that did not fire has nothing to announce.

        Guards the inverse of the test above: an announcement on every UUID
        would train a caller to ignore the one that matters.
        """
        with caplog.at_level(logging.WARNING, logger="rine"):
            await _twin_send(async_client, sync_client, KOFI_ID, groups=[OPS], agents=[KOFI])

        assert [r.getMessage() for r in caplog.records if r.name == "rine"] == []

    async def test_a_uuid_this_org_may_not_read_then_falls_through_to_the_agent_path(
        self, async_client, sync_client
    ):
        """A 403 is a miss, not a refusal — the disclosure rule, through ``send``.

        ``GET /groups/{id}`` 403s a group belonging to an org this caller is
        neither owner of nor seated in. Refusing the send there would both leak
        which ids exist and break every agent id that happens to collide with a
        stranger's group.
        """
        sent = await _twin_send(
            async_client,
            sync_client,
            GROUP_UUID,
            groups=[],
            agents=[KOFI],
            refuse_by_id={GROUP_UUID: 403},
        )

        assert sent.branches == (("agent", GROUP_UUID),)
        assert sent.refusal is None

    async def test_a_group_read_that_faults_then_the_fault_reaches_the_caller(
        self, async_client, sync_client
    ):
        """A 500 is not "no group of that id", and must not be swallowed into one.

        Falling through here would tell a caller their recipient was wrong about
        an outage, and would then HPKE-seal a group id to a nonexistent agent.
        """
        sent = await _twin_send(
            async_client,
            sync_client,
            GROUP_UUID,
            groups=[OPS],
            agents=[KOFI],
            refuse_by_id={GROUP_UUID: 500},
        )

        assert sent.refusal is not None
        assert sent.refusal[0] is InternalServerError
        assert sent.branches == ()
        assert sent.body is None


class TestTheOtherRecipientClassesAreUntouched:
    """The arm is UUID-only. Each class below is what a widened one would break."""

    async def test_a_bare_name_when_sent_to_then_still_takes_the_bare_arm(
        self, async_client, sync_client
    ):
        """The bare arm matches a group by NAME, and the id rung never sees the word."""
        sent = await _twin_send(async_client, sync_client, "ops", groups=[OPS], agents=[KOFI])

        assert sent.branches == (("group", OPS["handle"]),)
        assert sent.group_reads == [], "a bare word was sent down the id rung"

    async def test_a_bare_name_an_agent_carries_then_still_refuses_before_any_send(
        self, async_client, sync_client
    ):
        """A bare word is never quietly read as an agent, and the id arm does not change that.

        The refusal is the ambiguity guard's, unchanged: a caller who meant
        ``ops@acme`` and wrote ``ops`` must not silently post to a group called
        ``ops``, and equally must not silently acquire an agent send.
        """
        sent = await _twin_send(
            async_client, sync_client, "ops", groups=[OPS], agents=[AN_AGENT_CALLED_OPS]
        )

        assert sent.refusal is not None
        assert sent.refusal[0] is ConfigError
        assert sent.branches == ()
        assert sent.body is None

    async def test_an_agent_handle_when_sent_to_then_is_untouched_and_costs_no_group_read(
        self, async_client, sync_client
    ):
        """A handle is the agent namespace's, before this change and after it."""
        sent = await _twin_send(
            async_client, sync_client, str(KOFI["handle"]), groups=[OPS], agents=[KOFI]
        )

        assert sent.branches == (("agent", KOFI["handle"]),)
        assert sent.group_reads == [], "a handle was sent down the id rung"

    async def test_a_full_group_handle_when_sent_to_then_is_untouched_and_costs_no_id_read(
        self, async_client, sync_client
    ):
        """Already a group send, and still resolved by ``?handle=`` rather than by id."""
        sent = await _twin_send(
            async_client, sync_client, str(OPS["handle"]), groups=[OPS], agents=[KOFI]
        )

        assert sent.branches == (("group", OPS["handle"]),)
        assert sent.group_reads == [], "a group handle was sent down the id rung"
