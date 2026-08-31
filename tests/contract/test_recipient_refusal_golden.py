"""The Python half of the cross-stack refusal-parity gate.

🔴 A source-parse pin cannot prove refusal parity. The join contract is the
proof: six sentences and two numbers are pinned across the two stacks by
``tests/test_client-server-contract_group0.py``, and the stacks still disagreed
about ``##ops`` for months. What a caller reads is a COMPOSED string, and the
only honest way to compare two implementations of one is to run both over the
same inputs and diff the bytes.

So: one committed fixture, replayed here and by
``rine-core/test/recipient-refusal-golden.test.ts``. Both replays are reached by
``ci.sh`` — this one at stage 4 (``rine-sdk`` contract), the other at stage 11
(``rine-core`` vitest) — which is the gap the precedent fixture
(``tests/test_verification-words-golden_group0.py``) still has and this one
closes.

It lives under ``tests/contract`` for one reason and it is not taxonomy: stage 4
runs ``tests/contract`` and nothing else of this package, so a golden replay
anywhere else in ``rine-sdk/tests`` is gated only by the publish train.

The shared vectors are pure input → sentence. No HTTP, no client, no server.

🔴 ``by_id_disclosure`` is the one section that is not, and the exception is
earned. *"A 403 is answered exactly as a 404 is"* is a mapping from
a STATUS to a sentence, so no arrangement of a roster and a spelling can express
it — that section drives the real seated resolver against a stub transport.
Both stacks already guard the rule inside their own suites
(:class:`tests.contract.test_recipient_parity.TestResolveGroup` here,
``resolve-group-handle.test.ts`` there); neither of those compares the two
stacks' BYTES, which is the class of hole a one-byte divergence in
``invalid_agent_identifier`` hides in while every per-stack suite reads green.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from rine._group_join import bare_name_join_refusal, unresolved_handle_join_refusal
from rine._group_ref import (
    compose_group_refusal,
    recipient_group_for_bare_name,
    refuse_if_a_bare_agent_name,
    unknown_group_refusal,
)
from rine._resolve import invalid_agent_identifier, resolve_to_uuid_sync
from rine.errors import GroupIdentityMismatchError, NotFoundError, RineApiError
from rine.thread_words import not_a_conversation_uuid

from ._recipient_server import mocked_server

#: The goldens are ONE file and they live with the TypeScript half of this gate,
#: inside ``rine-core``. A shared golden with two homes is two goldens, and the
#: comparison this file exists to make is only worth anything while there is one.
#:
#: ``rine-core`` is a sibling package in the monorepo and ships in no sdist of
#: this one, so the fixture's ABSENCE is a checkout shape rather than a
#: regression and the replay skips. A fixtures directory that exists WITHOUT the
#: vectors in it is the opposite — somebody deleted the goldens — and that fails
#: loudly rather than skipping.
FIXTURE_DIR = Path(__file__).resolve().parents[3] / "rine-core" / "test" / "fixtures"
FIXTURE = FIXTURE_DIR / "refusal-vectors.json"

REGENERATE = os.environ.get("RINE_REFUSAL_REGEN") == "1"

needs_the_goldens = pytest.mark.skipif(
    not FIXTURE_DIR.is_dir(),
    reason="the golden vectors are not in this checkout (published sdist or mirror)",
)


def _fixture() -> dict[str, Any]:
    if not FIXTURE.exists():
        raise AssertionError(
            f"refusal vectors missing at {FIXTURE} — restore them (git checkout) or "
            "regenerate with RINE_REFUSAL_REGEN=1 on BOTH stacks. Deleting this "
            "suite instead removes the only cross-stack comparison of composed text."
        )
    return json.loads(FIXTURE.read_text())


#: 🔴 Guarded on the DIRECTORY and never inside a test body. Collection imports
#: this module whatever the marks say, so a read that ran unconditionally here
#: would fail the file to collect on a checkout without the goldens instead of
#: skipping it — which is a broken run for anyone who has only this package.
DOC: dict[str, Any] = _fixture() if FIXTURE_DIR.is_dir() else {"vectors": [], "excluded": {}}
VECTORS: list[dict[str, Any]] = DOC.get("vectors", [])
EXCLUDED: list[dict[str, Any]] = DOC.get("excluded", {}).get("vectors", [])
DISCLOSURE: list[dict[str, Any]] = DOC.get("by_id_disclosure", {}).get("vectors", [])
SUBSTITUTION: list[dict[str, Any]] = DOC.get("by_id_substitution", {}).get("vectors", [])


def _refusal_from(act: Any) -> str | None:
    """The refusal ``act`` raised, or ``None`` if it raised none.

    ``detail`` and not ``str(exc)``: :class:`rine.errors.RineApiError` renders
    itself as ``"404: <detail>"``, and the status prefix is this stack's
    transport wrapper rather than a byte of the composed sentence. The
    TypeScript twin throws a bare ``Error``, so comparing ``str(exc)`` would
    report a divergence that exists only in the exception type.
    """
    try:
        act()
    except Exception as error:  # noqa: BLE001 - the refusal is the subject
        detail = getattr(error, "detail", None)
        return str(detail) if detail is not None else str(error)
    return None


def compose(vector: dict[str, Any]) -> str | None:
    """What this stack composes for one vector."""
    groups: list[dict[str, Any]] = vector["candidates"]
    agents: list[dict[str, Any]] = vector["agents"]
    spelling: str = vector["spelling"]
    lead = str(vector.get("lead", "")).replace("{spelling}", spelling)
    slot = vector["slot"]
    if slot == "unknown_group":
        return unknown_group_refusal(groups, spelling)
    if slot == "bare_recipient_group":
        return _refusal_from(lambda: recipient_group_for_bare_name(groups, spelling))
    if slot == "bare_agent_collision":
        return _refusal_from(lambda: refuse_if_a_bare_agent_name(agents, spelling))
    if slot == "compose_bare":
        return compose_group_refusal(lead)
    if slot == "compose_next_step_no_roster":
        return compose_group_refusal(lead, next_step=vector["next_step"])
    if slot == "compose_next_step_under_roster":
        return compose_group_refusal(lead, groups, next_step=vector["next_step"])
    if slot == "compose_next_step_empty_roster":
        return compose_group_refusal(lead, [], next_step=vector["next_step"])
    if slot == "invalid_agent_identifier":
        return invalid_agent_identifier(spelling)
    if slot == "join_bare_name":
        return bare_name_join_refusal(spelling)
    if slot == "join_unresolved_handle":
        return unresolved_handle_join_refusal(spelling, int(vector["unread"]))
    if slot == "not_a_conversation_uuid":
        # 🔴 The vector names a SURFACE and this stack implements exactly one of
        # them. TypeScript parameterises the two parameter spellings
        # (``THREAD_REF_SURFACES``) because a CLI caller types ``--group`` and a
        # tool call carries ``group``; Python's twin hardcodes the tool
        # spellings. Composing a "tool" sentence for a vector that said "cli"
        # would report byte-identity between two different surfaces.
        assert vector["surface"] == "tool", (
            f"{vector['id']}: this stack composes the tool spellings only, "
            f"and the vector names '{vector['surface']}'"
        )
        return not_a_conversation_uuid(spelling)
    raise AssertionError(f"unknown refusal slot '{slot}' in vector '{vector['id']}'")


def _refused_by_id(client: Any, vector: dict[str, Any], status: int) -> str:
    """What the seated resolver says when ``GET /groups/{id}`` answers ``status``.

    The real client and the real ladder, over a stub transport — the rule being
    pinned is a mapping from a status to a sentence, so a helper that composed
    the sentence itself would be the gate agreeing with itself.
    """
    with mocked_server(vector["candidates"], [], {vector["spelling"]: status}):
        with pytest.raises(NotFoundError) as refused:
            client.resolve_group(vector["spelling"])
    return str(refused.value.detail)


def _substituted(client: Any, vector: dict[str, Any]) -> tuple[Exception, list[str]]:
    """What the seated resolver raises when the id route answers about another group.

    The real client and the real ladder, over a stub transport, for the same
    reason :func:`_refused_by_id` is: the rule is a mapping from a BODY to a
    raise, so a helper that composed the sentence here would be the gate
    agreeing with itself. The routes taken come back too — the roster must never
    be among them.
    """
    with mocked_server(
        vector["roster"], [], substitute_by_id={vector["spelling"]: vector["answered"]}
    ) as taken:
        with pytest.raises(GroupIdentityMismatchError) as substituted:
            client.resolve_group(vector["spelling"])
        return substituted.value, list(taken)


def _identifier(vector: dict[str, Any]) -> str:
    return str(vector["id"])


@needs_the_goldens
@pytest.mark.skipif(not REGENERATE, reason="regeneration is explicit: RINE_REFUSAL_REGEN=1")
def test_the_fixture_when_regeneration_is_asked_for_then_this_stacks_half_is_rewritten(
    sync_client: Any,
) -> None:
    """Rewrite ``expected`` and every excluded vector's ``py``, and nothing else.

    Each stack writes only its own fields, in place, so the two regenerations
    commute and the file does not churn on the order they are run in. Both must
    be run: this one cannot know what TypeScript composes.

    ``by_id_disclosure``'s and ``by_id_substitution``'s ``expected`` are
    recorded by DRIVING the resolver — on the first of the statuses the
    disclosure rule says are indistinguishable, and on the substituted body —
    never by composing the sentence here, which would record what this file
    believes instead of what the product says.
    """
    for vector in VECTORS:
        vector["expected"] = compose(vector)
    for vector in EXCLUDED:
        vector["py"] = compose(vector)
    for vector in DISCLOSURE:
        vector["expected"] = _refused_by_id(sync_client, vector, vector["indistinguishable"][0])
    for vector in SUBSTITUTION:
        vector["expected"] = str(_substituted(sync_client, vector)[0])
    FIXTURE.write_text(json.dumps(DOC, indent=2, ensure_ascii=False) + "\n")
    assert VECTORS, "regenerated an empty fixture"


@needs_the_goldens
def test_the_fixture_when_loaded_then_it_holds_vectors_and_a_named_excluded_set() -> None:
    """An empty fixture passes every assertion below it.

    And a fixture that lost its excluded set has deleted a known divergence
    rather than closed one — the whole point of carrying the gap in the file is
    that it stays visible.
    """
    assert VECTORS, "the refusal fixture holds no shared vectors"
    assert EXCLUDED, "the refusal fixture holds no excluded vectors"
    assert DOC["excluded"]["reason"], "the excluded set must say why it exists"
    assert DISCLOSURE, "the refusal fixture holds no by-id disclosure vectors"
    assert DOC["by_id_disclosure"]["note"], "the disclosure set must say why it exists"
    assert SUBSTITUTION, "the refusal fixture holds no by-id substitution vectors"
    assert DOC["by_id_substitution"]["note"], "the substitution set must say why it exists"


@needs_the_goldens
@pytest.mark.parametrize("vector", VECTORS, ids=_identifier)
def test_a_refusal_when_composed_here_then_it_matches_the_typescript_stack(
    vector: dict[str, Any],
) -> None:
    """One sentence, two implementations, the same bytes."""
    assert "expected" in vector, f"{vector['id']} has no golden — regenerate"
    assert compose(vector) == vector["expected"]


def test_the_agent_resolver_when_given_a_bare_name_then_it_raises_the_gated_sentence() -> None:
    """The slot above pins a composer; this pins that the resolver still uses it.

    Without this, extracting the sentence into :func:`invalid_agent_identifier`
    would have made the golden compare a helper no caller reaches — a gate
    agreeing with itself. ``api_url`` is never touched: a spelling with no
    ``@`` is refused on syntax before any request, which is what lets the
    fixture stay pure input → sentence.
    """
    with pytest.raises(NotFoundError) as refused:
        resolve_to_uuid_sync("https://rine.network", "logistics")

    assert refused.value.detail == invalid_agent_identifier("logistics")


@needs_the_goldens
@pytest.mark.parametrize("vector", EXCLUDED, ids=_identifier)
def test_a_known_divergence_when_composed_here_then_it_is_the_recorded_one(
    vector: dict[str, Any],
) -> None:
    """The excluded set is PINNED, not skipped.

    This stack's own recorded string is asserted, so a divergence cannot drift
    while nobody is looking — and the day the two stacks agree, the vector moves
    into the shared set rather than quietly starting to pass. Unifying the two
    stacks to make one of these pass is a product change, not a fixture
    change.
    """
    assert "py" in vector, f"{vector['id']} has no recorded output — regenerate"
    assert vector["divergence"], f"{vector['id']} must state its divergence"
    assert compose(vector) == vector["py"]
    assert vector["py"] != vector["ts"], (
        f"{vector['id']} no longer diverges — move it into the shared vectors"
    )


@needs_the_goldens
@pytest.mark.parametrize("vector", DISCLOSURE, ids=_identifier)
def test_an_unreadable_id_when_read_here_then_every_status_says_the_same_thing(
    vector: dict[str, Any], sync_client: Any
) -> None:
    """The by-id disclosure rule, in bytes, against the TypeScript stack's.

    🔴 Two claims, and the second is the one no per-stack suite makes. First,
    every status in ``indistinguishable`` composes ONE sentence: ``GET
    /groups/{id}`` 404s an id no group carries and 403s one carried by a group
    of an org this caller is neither owner of nor seated in, and telling those
    apart would tell a stranger which unknown ids EXIST — the non-member lookup
    the protocol refuses to add, arrived at by reading a status code instead of
    a route. Second, that sentence is byte-for-byte what ``rine-core``
    composes, which is what makes a later "improve the 403 message" on ONE
    stack a failure here rather than a silent divergence.
    """
    assert vector["expected"], f"{vector['id']} has no golden — regenerate"
    said = {
        status: _refused_by_id(sync_client, vector, status)
        for status in vector["indistinguishable"]
    }

    assert len(set(said.values())) == 1, (
        f"{vector['id']}: the statuses are distinguishable: {said}"
    )
    assert set(said.values()) == {vector["expected"]}


@needs_the_goldens
@pytest.mark.parametrize("vector", DISCLOSURE, ids=_identifier)
def test_a_status_outside_the_rule_when_read_here_then_it_escapes_as_itself(
    vector: dict[str, Any], sync_client: Any
) -> None:
    """⚠️ The bound the rule needs, and the reason it is in the fixture.

    A blanket catch would answer a 500 with *"Group not found"* — and buy an
    unpaginated roster to say it with — sending a caller off to re-spell an id
    that was never the problem. The arm above cannot detect that: swallowing
    MORE statuses makes it greener, not redder.
    """
    for status in vector["propagated"]:
        with mocked_server(vector["candidates"], [], {vector["spelling"]: status}):
            with pytest.raises(RineApiError) as failed:
                sync_client.resolve_group(vector["spelling"])
        assert not isinstance(failed.value, NotFoundError), (
            f"{vector['id']}: {status} was answered as a missing reference"
        )
        assert failed.value.status == status


@needs_the_goldens
@pytest.mark.parametrize("vector", SUBSTITUTION, ids=_identifier)
def test_a_substituted_group_when_read_here_then_it_raises_the_typescript_sentence(
    vector: dict[str, Any], sync_client: Any
) -> None:
    """The substitution rule, in bytes and in type, against the TypeScript stack's.

    🔴 Three claims, and no per-stack suite makes the second or the third.
    First, a ``GET /groups/{id}`` body naming another group is refused at all —
    the rung reads a row rather than passing the body through, so an unchecked
    answer would put every downstream group verb on a group the caller never
    named. Second, the sentence is
    byte-for-byte what ``rine-core``'s ``readableGroupById`` throws, so
    re-wording one stack is a failure here rather than a silent divergence.
    Third, the raise is TYPED and both stacks name the same type — the contract
    is a typed raise, and a bare ``Error`` carrying the right words would satisfy
    a byte comparison alone.
    """
    assert vector["expected"], f"{vector['id']} has no golden — regenerate"
    raised, _ = _substituted(sync_client, vector)

    assert str(raised) == vector["expected"]
    assert type(raised).__name__ == vector["error"]


@needs_the_goldens
@pytest.mark.parametrize("vector", SUBSTITUTION, ids=_identifier)
def test_a_substituted_group_when_read_here_then_no_roster_is_bought_for_it(
    vector: dict[str, Any], sync_client: Any
) -> None:
    """⚠️ A server fault surfaces as a server fault, never as a missing group.

    The bound the arm above cannot state. Falling through to
    :func:`~rine._group_ref.unknown_group_refusal` would answer a substituted
    body with *"Group not found"* — bought with an unpaginated roster — and send
    a caller off to re-spell a reference that was right, while the substitution
    that caused it went unreported. The roster in each vector is deliberately
    non-empty and holds the asked-for group, so a fall-through would compose a
    perfectly plausible sentence.
    """
    _, taken = _substituted(sync_client, vector)

    assert taken == [f"GET /groups/{vector['spelling']}"], (
        f"{vector['id']}: the id route is the only one that may be asked"
    )
