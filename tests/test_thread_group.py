"""Naming a transcript: a group by its own reference, a conversation by its UUID.

Reading a group was the one verb in the group family that would not take the
name of the thing it reads. It demanded a *conversation* UUID — an id of a
different entity, whose only source was a column another tool rendered — so a
caller holding a group and nothing else had no way to spend it here, and the
most likely mistake (naming the group to that parameter) travelled all the way
to the server and came back a framework ``422``.

Only the rine HTTP boundary is mocked (respx); the SDK is real, so a route
asserted here is the route that would go on the wire and a refusal asserted here
is the sentence an operator reads. Both clients are exercised: the sync client
is a hand-mirror of the async one, and every defect this file pins was present
in both copies.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from rine import SyncRineClient
from rine.errors import ConfigError, NotFoundError

API = "https://rine.network"
AGENT_ID = "00000000-1111-2222-3333-444444444444"  # matches conftest fixtures
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
CONVERSATION_ID = "dddddddd-eeee-ffff-0000-111111111111"
GROUP_HANDLE = "#ops@myorg.rine.network"
TOKEN = {"access_token": "test-token", "expires_in": 900}


def _mock_org() -> None:
    respx.post(f"{API}/oauth/token").mock(return_value=httpx.Response(200, json=TOKEN))
    respx.get(f"{API}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": AGENT_ID,
                        "name": "me",
                        "handle": "me@myorg.rine.network",
                        "created_at": "2024-01-01T00:00:00Z",
                    }
                ]
            },
        )
    )


def _mock_group_lookup() -> respx.Route:
    """``GET /groups`` — both the ``?handle=`` filter and the bare listing."""
    return respx.get(f"{API}/groups").mock(
        return_value=httpx.Response(
            200, json={"items": [{"id": GROUP_ID, "handle": GROUP_HANDLE, "name": "ops"}]}
        )
    )


def _mock_group_row() -> respx.Route:
    """``GET /groups/{id}`` — the id rung, an indexed read of one row."""
    return respx.get(f"{API}/groups/{GROUP_ID}").mock(
        return_value=httpx.Response(
            200, json={"id": GROUP_ID, "handle": GROUP_HANDLE, "name": "ops"}
        )
    )


def _mock_group_messages(messages: list[dict] | None = None) -> respx.Route:
    return respx.get(f"{API}/groups/{GROUP_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": messages or [], "truncated": False})
    )


def _mock_conversation_messages() -> respx.Route:
    return respx.get(f"{API}/conversations/{CONVERSATION_ID}/messages").mock(
        return_value=httpx.Response(200, json={"messages": [], "truncated": False})
    )


def _undecryptable_group_row() -> dict:
    """One group post this reader holds no key for — enough to prove the parse.

    The rendering of a row is the same code for both routes (one
    ``_transcript_rows``), so what this asserts is that the group route's page
    is read with the same ``{messages, truncated}`` shape — not the crypto,
    which ``test_thread.py`` covers.
    """
    return {
        "id": "cccccccc-dddd-eeee-ffff-000000000101",
        "conversation_id": CONVERSATION_ID,
        "group_id": GROUP_ID,
        "type": "rine.v1.task_request",
        "encrypted_payload": "not-openable-by-this-reader",
        "encryption_version": "sender-key-v1",
        "direction": "received",
        "created_at": "2024-01-01T00:00:00Z",
    }


class TestNamingAGroup:
    """The transcript verb takes the same reference every group verb takes."""

    @respx.mock
    async def test_thread_when_named_a_group_handle_reads_the_group_route(self, async_client):
        _mock_org()
        lookup = _mock_group_lookup()
        group_route = _mock_group_messages()
        conversation_route = _mock_conversation_messages()

        await async_client.thread(group=GROUP_HANDLE)

        assert group_route.called, "a named group is read by the group's own route"
        assert lookup.call_count == 1, "resolved once, through the shared group resolver"
        assert not conversation_route.called, "no hop through a conversation id"
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_a_group_uuid_costs_the_one_indexed_read(self, async_client):
        # The resolver used to answer a UUID with no round
        # trip at all, so an id naming no group of this org reached the wire and
        # came back a bare server 404. It is checked now — against the id's own
        # row rather than a listing — and the transcript verb still inherits the
        # decision rather than re-taking it, which is the claim this test has
        # always been making.
        _mock_org()
        row = _mock_group_row()
        lookup = _mock_group_lookup()
        group_route = _mock_group_messages()

        await async_client.thread(group=GROUP_ID)

        assert group_route.called
        assert row.call_count == 1, "resolved once, through the shared group resolver"
        assert not lookup.called, "the resolved path bought a listing it does not read"
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_a_bare_group_name_resolves_it_like_every_group_verb(
        self, async_client
    ):
        # A bare name is matched against the local part of the caller's own
        # groups — the server's ``?handle=`` filter only matches a full handle.
        _mock_org()
        lookup = _mock_group_lookup()
        group_route = _mock_group_messages()

        await async_client.thread(group="ops")

        assert group_route.called
        assert lookup.called
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_an_unknown_group_refuses_before_reading_anything(
        self, async_client
    ):
        _mock_org()
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": []}))
        group_route = _mock_group_messages()

        with pytest.raises(NotFoundError) as excinfo:
            await async_client.thread(group="#ghost@myorg.rine.network")

        assert "Group not found" in str(excinfo.value)
        assert not group_route.called
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_a_group_reads_the_page_the_group_route_returns(
        self, async_client
    ):
        _mock_org()
        _mock_group_lookup()
        _mock_group_messages([_undecryptable_group_row()])

        entries = await async_client.thread(group=GROUP_HANDLE)

        assert len(entries) == 1
        assert entries[0].direction == "received"
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_a_group_with_a_limit_forwards_the_window(self, async_client):
        _mock_org()
        _mock_group_lookup()
        group_route = _mock_group_messages()

        await async_client.thread(group=GROUP_HANDLE, limit=5)

        assert b"limit=5" in group_route.calls[0].request.url.query
        await async_client.close()

    @respx.mock
    def test_thread_when_the_sync_twin_names_a_group_it_reads_the_group_route(self, sync_client):
        # The two clients are hand-mirrors; every defect in this family was
        # present in both copies, so both are pinned.
        _mock_org()
        _mock_group_lookup()
        group_route = _mock_group_messages()
        conversation_route = _mock_conversation_messages()

        sync_client.thread(group=GROUP_HANDLE)

        assert group_route.called
        assert not conversation_route.called


class TestNamingExactlyOne:
    """Both references, or neither, is one mistake and gets one sentence."""

    @respx.mock
    async def test_thread_when_named_both_references_refuses_naming_both_properties(
        self, async_client
    ):
        _mock_org()
        lookup = _mock_group_lookup()
        group_route = _mock_group_messages()
        conversation_route = _mock_conversation_messages()

        with pytest.raises(ConfigError) as excinfo:
            await async_client.thread(CONVERSATION_ID, group=GROUP_HANDLE)

        message = str(excinfo.value)
        assert "group" in message
        assert "conversation_id" in message
        assert "exactly one" in message
        # Decidable offline: a caller that made up its mind twice is not charged
        # a group lookup to be told so.
        assert not lookup.called
        assert not group_route.called
        assert not conversation_route.called
        await async_client.close()

    @respx.mock
    async def test_thread_when_named_neither_reference_refuses_naming_both_properties(
        self, async_client
    ):
        _mock_org()
        conversation_route = _mock_conversation_messages()

        with pytest.raises(ConfigError) as excinfo:
            await async_client.thread()

        message = str(excinfo.value)
        assert "group" in message
        assert "conversation_id" in message
        assert "exactly one" in message
        assert not conversation_route.called
        await async_client.close()

    @respx.mock
    def test_thread_when_the_sync_twin_names_both_references_it_refuses_the_same_way(
        self, sync_client
    ):
        _mock_org()

        with pytest.raises(ConfigError) as excinfo:
            sync_client.thread(CONVERSATION_ID, group=GROUP_HANDLE)

        assert "exactly one" in str(excinfo.value)


class TestABlankReferenceIsNoReference:
    """``""`` means *not named*, on this stack and on the TypeScript one."""

    @respx.mock
    async def test_thread_when_the_group_is_blank_reads_the_conversation_it_was_given(
        self, async_client
    ):
        # A tool-calling model routinely fills an optional parameter it did not
        # want with the empty string, so ``group=""`` beside a real
        # ``conversation_id`` is a call that named ONE reference. Reading it as
        # two made the same call succeed on mastra/eve/mcp/cli and be refused on
        # hermes/crewai/langchain — one tool name, one advertised rule, two
        # answers depending on which framework the caller was wearing.
        _mock_org()
        conversation_route = _mock_conversation_messages()

        await async_client.thread(CONVERSATION_ID, group="")

        assert conversation_route.called
        await async_client.close()

    @respx.mock
    async def test_thread_when_the_conversation_id_is_blank_reads_the_group_it_was_given(
        self, async_client
    ):
        _mock_org()
        _mock_group_lookup()
        group_route = _mock_group_messages()

        await async_client.thread("   ", group=GROUP_HANDLE)

        assert group_route.called
        await async_client.close()

    @respx.mock
    async def test_thread_when_both_references_are_blank_refuses_naming_neither(
        self, async_client
    ):
        _mock_org()

        with pytest.raises(ConfigError) as excinfo:
            await async_client.thread("", group="")

        assert "exactly one" in str(excinfo.value)
        await async_client.close()

    @respx.mock
    async def test_thread_when_a_reference_is_not_a_string_refuses_rather_than_raising(
        self, async_client
    ):
        # The surface the group-QoL harness actually drives (hermes) hands
        # ``args.get("conversation_id")`` through with no pydantic layer, so a
        # model emitting a number reaches the guard as an int. That is a
        # reference that will not resolve, not an internal error: the handler's
        # blanket ``except Exception`` would otherwise render an
        # ``AttributeError`` where the refusal belongs.
        _mock_org()
        conversation_route = respx.get(url__regex=rf"{API}/conversations/.*").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )

        with pytest.raises(ConfigError) as excinfo:
            await async_client.thread(123)  # type: ignore[arg-type]

        assert "conversation_id must be a conversation UUID" in str(excinfo.value)
        assert not conversation_route.called
        await async_client.close()

    def test_the_typescript_stack_reads_a_blank_reference_the_same_way(self):
        # 🔴 Bound by a test rather than by an import, exactly as the founder-
        # pinned vote sentence is: the two stacks
        # share no module, and a rule applied on one of them only is the drift
        # this file exists to stop. ``rine-core``'s ``referenceGiven`` trims and
        # treats the result as absent when empty; ``blank_as_absent`` is that
        # function, in Python.
        import pathlib

        from rine.thread_words import blank_as_absent

        assert blank_as_absent("") is None
        assert blank_as_absent("   ") is None
        assert blank_as_absent(None) is None
        assert blank_as_absent(" #ops@org ") == "#ops@org"

        ts = pathlib.Path(__file__).resolve().parents[2] / "rine-core/src/thread-ref.ts"
        if not ts.is_file():
            pytest.skip("rine-core not present — SDK tested outside the monorepo")
        assert "trim()" in ts.read_text(), (
            "rine-core no longer trims a reference — the two stacks now disagree "
            "about what an empty string means"
        )


class TestNamingAConversation:
    """The parameter that was always here still behaves exactly as it did."""

    @respx.mock
    async def test_thread_when_named_a_conversation_positionally_still_reads_it(
        self, async_client
    ):
        # 🔴 The no-regression pin. ``conversation_id`` stays FIRST and
        # positional, so every call site written before ``group`` existed calls
        # unchanged.
        _mock_org()
        conversation_route = _mock_conversation_messages()

        await async_client.thread(CONVERSATION_ID)

        assert conversation_route.called
        await async_client.close()

    @respx.mock
    def test_thread_when_the_sync_twin_names_a_conversation_positionally_it_still_reads_it(
        self, sync_client
    ):
        _mock_org()
        conversation_route = _mock_conversation_messages()

        sync_client.thread(CONVERSATION_ID)

        assert conversation_route.called


class TestAConversationReferenceThatCannotBeOne:
    """Refused locally, in words that name the parameter that would work."""

    @respx.mock
    async def test_thread_when_the_conversation_id_is_a_group_name_refuses_without_a_request(
        self, async_client
    ):
        # What the model actually did: it called the right verb and passed the
        # group's name. The route types that path parameter ``uuid.UUID``, so
        # this used to become a URL and come back as a pydantic error object
        # with no next step in it.
        _mock_org()
        conversation_route = respx.get(url__regex=rf"{API}/conversations/.*").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )

        with pytest.raises(ConfigError) as excinfo:
            await async_client.thread("quarterly planning group")

        message = str(excinfo.value)
        assert "conversation_id must be a conversation UUID" in message
        assert '"quarterly planning group" is not one' in message
        assert "group takes" in message, "the refusal names the parameter that takes a group"
        # 🔴 The clause used to end in a worked handle —
        # ``group=#logistics@acme.rine.network`` — and a model reads a concrete
        # address in a refusal as the answer. There is no roster on this path to
        # derive the caller's own from, so the sentence describes the shape and
        # shows nobody.
        assert "@" not in message
        assert not conversation_route.called, "refused before it became a URL"
        await async_client.close()

    @respx.mock
    def test_thread_when_the_sync_twin_is_given_a_group_name_it_refuses_the_same_way(
        self, sync_client
    ):
        _mock_org()
        conversation_route = respx.get(url__regex=rf"{API}/conversations/.*").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )

        with pytest.raises(ConfigError) as excinfo:
            sync_client.thread("quarterly planning group")

        assert "group takes" in str(excinfo.value)
        assert "@" not in str(excinfo.value)
        assert not conversation_route.called

    @pytest.mark.parametrize(
        "spelling",
        [
            "ddddddddeeeeffff0000111111111111",
            "urn:uuid:dddddddd-eeee-ffff-0000-111111111111",
            "{dddddddd-eeee-ffff-0000-111111111111}",
        ],
    )
    @respx.mock
    async def test_thread_when_the_conversation_id_is_a_uuid_the_wire_parses_still_reads_it(
        self, async_client, spelling
    ):
        # 🔴 The capability-preservation pin. The server types that parameter
        # ``uuid.UUID``, which accepts the dashless, ``urn:uuid:`` and braced
        # spellings as well as the canonical one. A pre-flight built on the
        # strict UUID regex would refuse three spellings the product has always
        # accepted — a capability removal wearing a validation fix.
        _mock_org()
        route = respx.get(url__regex=rf"{API}/conversations/.*/messages").mock(
            return_value=httpx.Response(200, json={"messages": [], "truncated": False})
        )

        await async_client.thread(spelling)

        assert route.called
        await async_client.close()

    @respx.mock
    async def test_get_conversation_messages_when_given_a_group_name_still_asks_the_server(
        self, async_client
    ):
        # 🔴 The refusal stays on ``thread`` and does not spread to the verb next
        # door. ``get_conversation_messages`` has no ``group`` parameter, so a
        # caller that obeyed *"name the group instead"* would land on a
        # ``TypeError`` — the class of defect a refusal must not create: it
        # never names a verb that cannot answer it. The guard is additive: a
        # call that reached the server before still reaches it, and the server
        # answers for the id it was handed.
        _mock_org()
        conversation_route = respx.get(url__regex=rf"{API}/conversations/.*").mock(
            return_value=httpx.Response(404, json={"detail": "Conversation not found"})
        )

        with pytest.raises(NotFoundError):
            await async_client.get_conversation_messages("quarterly planning group")

        assert conversation_route.called
        await async_client.close()

    async def test_get_conversation_messages_when_read_for_a_group_clause_has_none(self):
        # The sentence itself, not just this one call: nothing a caller of that
        # verb can trip may print a directive naming a parameter it does not
        # take. Signature and refusal are asserted together because the defect
        # was the pair disagreeing.
        import inspect

        from rine import RineClient
        from rine.thread_words import not_a_conversation_uuid

        assert "group" not in inspect.signature(RineClient.get_conversation_messages).parameters
        assert "group takes" in not_a_conversation_uuid("x"), (
            "the two-reference refusal no longer names the parameter that takes a group"
        )
        source = inspect.getsource(RineClient.get_conversation_messages)
        assert "named_conversation_uuid" not in source


class TestTheGroupRouteIsNamedOnce:
    """The two transcript routes are literals in one module, not in two clients."""

    def test_thread_words_when_asked_for_a_groups_route_answers_the_group_keyed_one(self):
        # A group transcript is keyed by ``messages.group_id``, never by
        # the group's conversation — the two reads legitimately differ on a
        # group older than the 0015 cutover, so the route must not be built from
        # a conversation id.
        from rine.thread_words import conversation_transcript_path, group_transcript_path

        assert group_transcript_path(GROUP_ID) == f"/groups/{GROUP_ID}/messages"
        assert (
            conversation_transcript_path(CONVERSATION_ID)
            == f"/conversations/{CONVERSATION_ID}/messages"
        )

    @respx.mock
    def test_the_sync_twin_when_named_the_same_group_asks_for_the_same_route(self, sync_client):
        # Two hand-mirrored clients are how the group route would come to exist
        # in one of them only. Asserted as the request that goes on the wire,
        # never as a grep for a helper's name: a rename must not be able to
        # satisfy this, and the twin drifting apart must not be able to pass it.
        _mock_org()
        _mock_group_lookup()
        group_route = _mock_group_messages()

        sync_client.thread(group=GROUP_HANDLE)

        assert group_route.called
        assert group_route.calls[0].request.url.path == f"/groups/{GROUP_ID}/messages"


class TestTheSyncTwinsGroupErrors:
    """A group the sync caller cannot see is refused before any transcript read."""

    @respx.mock
    def test_thread_when_the_sync_twin_names_an_unknown_group_it_reads_nothing(self, sync_client):
        _mock_org()
        respx.get(f"{API}/groups").mock(return_value=httpx.Response(200, json={"items": []}))
        group_route = _mock_group_messages()

        with pytest.raises(NotFoundError):
            sync_client.thread(group="#ghost@myorg.rine.network")

        assert not group_route.called


def test_sync_client_when_imported_exposes_the_same_transcript_signature():
    """Both clients take the same four parameters in the same order."""
    import inspect

    from rine import RineClient

    assert list(inspect.signature(RineClient.thread).parameters) == list(
        inspect.signature(SyncRineClient.thread).parameters
    )
