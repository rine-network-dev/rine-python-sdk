"""The PRODUCT path: which ``send_and_wait`` recipients name a group, on both clients.

``POST /messages/sync`` is 1:1 only, so this verb never resolves a recipient
INTO a group the way ``send`` does — it only has to RECOGNISE one and refuse
before anything is sealed. Two holes were measured at ``691fcb53`` and are
pinned shut here:

* a **group's own UUID** matched neither client's ``to.startswith("#")`` guard,
  fell to :meth:`_encrypt_dm`, and came back the server's bare
  ``404: Agent not found`` — the exact sentence the id rung exists to eliminate, on the
  four published Python surfaces that wrap these clients (crewai, langchain,
  hermes, and the SDK itself). ``rine-mcp`` already answered the same reference
  correctly, so one product had two answers;
* the refusal is the **typed** :class:`~rine.errors.UnsupportedTargetError` and
  its wording is unchanged, which is what makes the fix free downstream: the
  three connectors catch the type, never the text
  (``tests/test_client-server-contract_group0.py`` pins the sentence they show a
  model), so widening the class that raises emits zero new published bytes.

🔴 **Half of this file is ANTI-widening, and that half is the one that can fail
quietly.** A probe that fired on an agent UUID, a handle or a bare word would
break 1:1 sending — the verb's whole purpose — so every class that must still
reach the agent namespace is driven here too, and the ``GET /groups/…``
**traffic** is asserted rather than only the outcome. An arm that asked the
group namespace about a handle would still send, and nothing but the traffic can
see it. This is ``test_send_recipient_dispatch.py``'s discipline, for the verb
that refuses a group instead of addressing it.

Every scenario runs on BOTH clients over one mocked server and compares the
branch, the posted body, the refusal and the wire traffic. The server is
``_recipient_server.py``, shared with the parity gates, so the id route's
uuid-parsing and its 403-is-a-miss behaviour are the ones production has.
"""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from typing import Any

import httpx
import respx

from rine.errors import InternalServerError, RineError, UnsupportedTargetError

from ._recipient_server import API, mocked_server

GROUP_UUID = "11111111-1111-1111-1111-111111111111"
KOFI_ID = "44444444-4444-4444-4444-444444444444"

OPS = {"id": GROUP_UUID, "name": "ops", "handle": "#ops@acme.rine.network"}
KOFI = {"id": KOFI_ID, "name": "kofi", "handle": "kofi@acme.rine.network"}

PAYLOAD = {"task": "handover"}

MESSAGE = {
    "id": "cccccccc-dddd-eeee-ffff-000000000001",
    "conversation_id": "cccccccc-dddd-eeee-ffff-000000000002",
    "from_agent_id": KOFI_ID,
    "type": "rine.v1.task_request",
    "encrypted_payload": "x",
    "encryption_version": "hpke-v1",
    "sender_signing_kid": f"rine:{KOFI_ID}",
    "created_at": "2024-01-01T00:00:00Z",
}

SYNC_RESPONSE = {"message": MESSAGE, "reply": None}

# The refusal's own bytes, restated rather than imported from the client.
#
# 🔴 What the three Python connectors catch is the TYPE, so the type is the
# first assertion below. The text is asserted second and separately because
# The founder ruled it unchanged: it still says "group handles" when a UUID was
# passed, deliberately, because zero new published bytes is worth more than the
# mild imprecision and the only reader of the difference is a developer holding
# the exception. A test that imported the string could not notice it moving.
REFUSAL = (
    "send_and_wait() does not support group handles — "
    "the /messages/sync endpoint is 1:1 only. "
    "Use send() to post to a group."
)


@dataclass(frozen=True)
class Waited:
    """Everything one ``send_and_wait()`` did that this gate has an opinion about.

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
        """The ``GET /groups/{id}`` reads this call paid for.

        Named because its EMPTINESS is the assertion on every recipient class
        but the UUID: that is how a widened probe — one that asked the group
        namespace about a handle or a bare word — is caught, and an
        answer-only assertion could not see it.
        """
        return [asked for asked in self.traffic if asked.startswith("GET /groups/")]


def _record_the_branch(client: Any, seen: list[tuple[str, str]]) -> None:
    """Watch the 1:1 branch ``send_and_wait()`` reaches, and what it addressed.

    The collaborator on the far side of the dispatch is replaced, never the
    dispatch — the same seam ``test_send_recipient_dispatch.py`` uses, for the
    same reason: the encryption is driven for real in the package's HPKE suites,
    and what this gate is about is which recipient got that far and what the
    group namespace was asked on the way.

    ⚠️ So a recipient the AGENT namespace would itself refuse — a bare word
    naming nobody, a handle naming nobody — reaches the recorder here instead
    of raising. That refusal is :func:`rine._resolve.resolve_to_uuid_async`'s
    and is not this file's claim; what is asserted about those classes is that
    the group namespace was never consulted about them.
    """

    def _dm(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        seen.append(("agent", to))
        return None, {"to_agent_id": to, "type": msg_type, "encrypted_payload": "x"}

    async def _dm_async(agent_id: str, to: str, payload: object, msg_type: str) -> Any:
        return _dm(agent_id, to, payload, msg_type)

    asynchronous = inspect.iscoroutinefunction(type(client).send_and_wait)
    client._encrypt_dm = _dm_async if asynchronous else _dm


async def _twin_wait(
    async_client: Any,
    sync_client: Any,
    to: str,
    *,
    groups: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    refuse_by_id: dict[str, int] | None = None,
) -> Waited:
    """Call the same recipient on both clients, assert they agreed, answer for both.

    A failure here is never "the sync client is wrong": it is the two of them
    disagreeing, which is the defect whichever one moved. The two clients are
    driven through one code path — the call is awaited only when it returns
    something awaitable — so the harness itself cannot be the asymmetry.
    """

    async def _one(client: Any) -> Waited:
        seen: list[tuple[str, str]] = []
        with mocked_server(groups, agents, refuse_by_id) as taken:
            posted = respx.post(f"{API}/messages/sync").mock(
                return_value=httpx.Response(200, json=SYNC_RESPONSE)
            )
            _record_the_branch(client, seen)
            refusal: tuple[type, str] | None = None
            try:
                answered = client.send_and_wait(to, PAYLOAD)
                if inspect.isawaitable(answered):
                    await answered
            except RineError as refused:
                refusal = (type(refused), str(refused))
            body = json.loads(posted.calls[0].request.content) if posted.called else None
            return Waited(tuple(seen), body, refusal, tuple(taken))

    asynchronous = await _one(async_client)
    await async_client.close()
    synchronous = await _one(sync_client)

    assert asynchronous == synchronous, f"send_and_wait({to!r}): the two clients did not agree"
    return synchronous


class TestARecipientThatNamesAGroup:
    """The three spellings this verb must refuse, and what each one costs."""

    async def test_a_group_uuid_when_waited_on_then_is_refused_before_anything_is_sealed(
        self, async_client, sync_client
    ):
        """The id class, answered by the probe rather than by the server's 404."""
        waited = await _twin_wait(
            async_client, sync_client, GROUP_UUID, groups=[OPS], agents=[KOFI]
        )

        assert waited.refusal is not None
        # The TYPE first — crewai, langchain and hermes each reach the pinned
        # model-facing sentence with `except UnsupportedTargetError`, so the
        # type is what makes this fix free on three published surfaces.
        assert waited.refusal[0] is UnsupportedTargetError
        # The ruled wording, verbatim, for the id class too.
        assert waited.refusal[1] == REFUSAL
        # Nothing was sealed and nothing was posted — the refusal is the point.
        assert waited.branches == ()
        assert waited.body is None
        # One org-scoped read is what the fix costs, and it is the shared
        # `_readable_group_by_id` — never a hand-rolled `GET /groups/` + id,
        # which would drop the answered-row-id check that read performs.
        assert waited.group_reads == [f"GET /groups/{GROUP_UUID}"]

    async def test_a_full_group_handle_when_waited_on_then_is_refused_without_any_read(
        self, async_client, sync_client
    ):
        """The class this verb always refused, unmoved — and still free."""
        waited = await _twin_wait(
            async_client, sync_client, str(OPS["handle"]), groups=[OPS], agents=[KOFI]
        )

        assert waited.refusal is not None
        assert waited.refusal[0] is UnsupportedTargetError
        assert waited.refusal[1] == REFUSAL
        assert waited.body is None
        # A sigil is a group as WRITTEN, so no read decides it.
        assert waited.group_reads == []

    async def test_the_org_less_sigil_when_waited_on_then_is_refused_as_a_group(
        self, async_client, sync_client
    ):
        """``#ops`` — the spelling the shared table reads and ``startswith("#")`` also did.

        Python refused this before the change and refuses it after; what moved
        is the reason. The guard is now
        :func:`rine._recipient.classify_reference`, the one table both stacks
        share, which is what let ``rine-ts-sdk`` — whose guard demanded a whole
        ``#name@org`` — stop answering the same string from the AGENT namespace.
        Pinned here so a future migration of this arm cannot quietly drop the
        org-less half on the stack that always had it.
        """
        waited = await _twin_wait(async_client, sync_client, "#ops", groups=[OPS], agents=[KOFI])

        assert waited.refusal is not None
        assert waited.refusal[0] is UnsupportedTargetError
        assert waited.body is None
        assert waited.group_reads == []


class TestEverythingThatDoesNotNameAGroupStillSends:
    """The probe is UUID-only. Each class below is what a widened one would break."""

    async def test_an_agent_uuid_when_waited_on_then_still_sends_1_to_1(
        self, async_client, sync_client
    ):
        """The half that must NOT move: a UUID has always been an agent id.

        The probe ran and missed. A 404 from the group route is not an answer
        about the recipient, and the 1:1 path below costs a UUID no request.
        """
        waited = await _twin_wait(async_client, sync_client, KOFI_ID, groups=[OPS], agents=[KOFI])

        assert waited.refusal is None
        assert waited.branches == (("agent", KOFI_ID),)
        assert waited.body is not None
        assert waited.body["to_agent_id"] == KOFI_ID
        assert waited.group_reads == [f"GET /groups/{KOFI_ID}"]

    async def test_a_uuid_this_org_may_not_read_then_falls_through_to_the_agent_path(
        self, async_client, sync_client
    ):
        """A 403 is a miss, not a refusal — the disclosure rule, through this verb.

        ``GET /groups/{id}`` 403s a group belonging to an org this caller is
        neither owner of nor seated in. Refusing there would both leak which
        ids exist and break every agent id that happens to collide with a
        stranger's group.
        """
        waited = await _twin_wait(
            async_client,
            sync_client,
            GROUP_UUID,
            groups=[],
            agents=[KOFI],
            refuse_by_id={GROUP_UUID: 403},
        )

        assert waited.refusal is None
        assert waited.branches == (("agent", GROUP_UUID),)

    async def test_a_group_read_that_faults_then_the_fault_reaches_the_caller(
        self, async_client, sync_client
    ):
        """A 500 is not "no group of that id", and must not be swallowed into one.

        Falling through would tell a caller their recipient was wrong about an
        outage, and would then HPKE-seal a group id to a nonexistent agent —
        the very ``Agent not found`` this arm exists to eliminate.
        """
        waited = await _twin_wait(
            async_client,
            sync_client,
            GROUP_UUID,
            groups=[OPS],
            agents=[KOFI],
            refuse_by_id={GROUP_UUID: 500},
        )

        assert waited.refusal is not None
        assert waited.refusal[0] is InternalServerError
        assert waited.branches == ()
        assert waited.body is None

    async def test_an_agent_handle_when_waited_on_then_costs_no_group_read(
        self, async_client, sync_client
    ):
        """🔴 ``[]``, not "was not refused".

        A handle is a spelling the agent namespace resolves, so it must never
        reach the group route at all. A probe widened past the id class would
        still send here, and only the traffic can see it.
        """
        waited = await _twin_wait(
            async_client, sync_client, str(KOFI["handle"]), groups=[OPS], agents=[KOFI]
        )

        assert waited.refusal is None
        assert waited.branches == (("agent", KOFI["handle"]),)
        assert waited.group_reads == []

    async def test_a_bare_word_when_waited_on_then_the_group_namespace_is_never_asked(
        self, async_client, sync_client
    ):
        """🔴 This verb deliberately does NOT read a bare word as a group, unlike ``send``.

        ``send``'s bare arm matches a group by NAME. Routing this verb through
        that door would turn a certain agent-namespace answer into a group send
        ``/messages/sync`` then rejects with a 422 — so the bare class stays the
        agent namespace's, and the assertion is that no group was consulted
        about it. A group called ``ops`` is served here precisely so a widened
        arm would have something to find.
        """
        waited = await _twin_wait(async_client, sync_client, "ops", groups=[OPS], agents=[KOFI])

        assert waited.refusal is None
        assert waited.branches == (("agent", "ops"),)
        assert waited.group_reads == [], "a bare word was sent down the id rung"
