"""Which reference names a transcript, in the words every surface prints.

A transcript can be named two ways and they are not interchangeable: a
**conversation** is named by its UUID, a **group** by the same reference every
other group verb takes (``#name@org``, a bare name, or a UUID). Both the
refusals that keep those two apart live here, once, because ``rine-crewai``,
``rine-langchain`` and ``rine-hermes`` each expose ``rine_thread`` and are
deliberate copies of each other — three copies of one sentence is how a model
comes to read the same refusal two ways depending on which framework it happens
to be wearing. (``INVITE_TARGET_REQUIRED`` is retyped in all three today; this
is the shape that stops the next one.)

🔴 The two path builders are **pure**: they take an id and return a route, and
they refuse nothing. The guards are separate callables
(:func:`named_conversation_uuid`, :func:`refuse_if_two_transcript_references`)
so that a caller chooses which refusals it is under. ``thread()`` takes both
guards because it is the verb that offers a choice of reference;
``get_conversation_messages`` takes neither, because it has no ``group``
parameter and a refusal that says *"name the group instead"* to a caller that
cannot pass ``group`` at all is a directive to a ``TypeError``. That verb
reached the server before and still does: what is asked for is a client-side
refusal on ``thread``, not for an existing verb to start refusing what it used
to send.

🔴 :func:`named_conversation_uuid` asks :func:`rine._resolve.parses_as_uuid`,
never :func:`rine._resolve.is_uuid`. The server types that path parameter
``uuid.UUID``, which accepts the dashless, ``urn:uuid:`` and braced spellings as
well as the canonical one, so a pre-flight that refused on the strict regex
would refuse three spellings the product has always accepted — a capability
removal wearing a validation fix. A client-side pre-flight may only refuse what
the wire would have refused anyway; its whole value is *when* it refuses, not
*what*.

The TypeScript stack holds its own copy of these strings, as it does for every
other refusal that crosses that boundary: the two stacks share no module, so
they are bound by a test rather than by an import.
"""

from __future__ import annotations

from rine._resolve import parses_as_uuid
from rine.errors import ConfigError

#: The refusal when a caller names both ways of reaching a transcript, or
#: neither. One sentence for both mistakes, because both are the same mistake:
#: the call did not say which of two things it wanted read. Structure copied
#: from the shipped ``rine_group_invite`` precedent — *"Name exactly one of
#: agent_to_invite (one invitation) or agents_to_invite (a batch)."*
TRANSCRIPT_REFERENCE_REQUIRED = (
    "Name exactly one of group (a group handle, name or UUID) or "
    "conversation_id (a conversation UUID)."
)


def not_a_conversation_uuid(value: str) -> str:
    """The refusal for a conversation reference that cannot be a conversation.

    Every other reference-taking verb resolves its argument client-side before
    it becomes a URL; this one used to hand the string straight to the path, so
    the most likely mistake — naming the *group* to the parameter that reads a
    conversation — was answered by a framework ``422`` carrying a pydantic error
    object and no next step.

    The second sentence names the parameter that does take a group, because a
    refusal that only says what is wrong leaves the caller to guess what is
    right — what the caller is missing is where to put the reference they
    already hold, not how to spell one this path cannot know.

    🔴 **The spellings are DESCRIBED and no longer shown.** This site
    used to print ``group=#logistics@acme.rine.network``, defended in this very
    docstring as *"a worked example teaches the spelling; a template invites a
    placeholder"*. The measurement landed on the opposite side: the local
    part moved with the world's subject matter while the domain did not move at
    all, so a printed domain is pasted verbatim. Deriving the caller's own org
    is unreachable here for the reason the retired argument itself gave — this
    path holds no roster — so the sentence describes the three spellings
    instead of showing one. Not an ``@org``-style slot either
    (``check-model-facing-examples.mjs``'s ``template-org`` rule).

    🔴 Only a verb that HAS a ``group`` parameter may print this. See the module
    docstring.
    """
    return (
        f'conversation_id must be a conversation UUID; "{value}" is not one. '
        "To read a group, name the group instead — group takes a group's "
        "whole handle, a bare group name, or its UUID."
    )


def blank_as_absent(value: str | None) -> str | None:
    """``""`` and whitespace mean *not named*, exactly as they do on the TS stack.

    A tool-calling model routinely emits ``""`` for an optional parameter it did
    not want, so ``group=""`` beside a real ``conversation_id`` is a call that
    named one reference, not two. Without this the same call is read as
    two-references-named here and as one-reference-named by
    ``rine-core``'s ``referenceGiven`` (``thread-ref.ts``), which is one tool
    name answering one call with two different sentences depending on which
    framework the caller is wearing.

    Applied by ``thread()`` alone. ``get_conversation_messages("")`` keeps
    reaching the server, on the same terms as every other value it forwards.

    🔴 Coerces rather than trusting the annotation. The values arriving here are
    often **tool arguments**, not typed parameters — ``rine-hermes`` hands
    ``args.get("group")`` through with no pydantic layer — so a model emitting
    ``123`` would meet ``.strip()`` with an int and raise ``AttributeError``
    inside a handler whose blanket ``except Exception`` renders it as an
    internal error instead of the refusal. A non-string reference is not a
    crash; it is a reference that will not resolve, and it should read that way.
    """
    if value is None:
        return None
    trimmed = str(value).strip()
    return trimmed or None


def refuse_if_two_transcript_references(conversation_id: str | None, group: str | None) -> None:
    """Refuse a call that named both a group and a conversation.

    Runs **before** any resolution: naming both is decidable offline, and a
    caller that has already made up its mind twice should not be charged a
    ``GET /groups`` to be told so.

    Callers pass both arguments through :func:`blank_as_absent` first, so this
    tests ``is not None`` on values that have already had the blank spelling of
    "absent" collapsed into ``None``.

    The other half of "exactly one" — naming *neither* — is refused by
    :func:`named_conversation_uuid`, in the same words, when the call falls
    through to the conversation branch with nothing to put in it. Each condition
    is decided in one place.
    """
    if conversation_id is not None and group is not None:
        raise ConfigError(TRANSCRIPT_REFERENCE_REQUIRED)


def named_conversation_uuid(conversation_id: str | None) -> str:
    """The conversation id a two-reference verb will read, or its refusal.

    Raises:
        ConfigError: Nothing was named, or what was named is not a spelling the
            wire reads as a UUID.
    """
    if conversation_id is None:
        raise ConfigError(TRANSCRIPT_REFERENCE_REQUIRED)
    if not parses_as_uuid(conversation_id):
        raise ConfigError(not_a_conversation_uuid(conversation_id))
    return conversation_id


def conversation_transcript_path(conversation_id: str) -> str:
    """The route that reads a conversation's rows. Pure — refuses nothing."""
    return f"/conversations/{conversation_id}/messages"


def group_transcript_path(group_id: str) -> str:
    """The route that reads a group's own rows, keyed by the group.

    The id is the one the caller's group resolver returned — a UUID from
    ``GET /groups`` or one the caller already held — so there is no second
    spelling to guard here.

    The server filters ``messages.group_id`` and reuses the delivery predicate
    the conversation route already applies, so this reads no row the caller
    could not read before; what it adds is the rows a group keeps outside its
    running conversation (alembic 0015 is forward-only, so a group older than
    that cutover keeps its posts in per-post conversations). The two routes
    therefore legitimately disagree on an old group.
    """
    return f"/groups/{group_id}/messages"
