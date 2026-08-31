"""What a caller means when they name a group, in one vocabulary.

The twin of ``rine-core/src/group-ref.ts``, and the sibling of :mod:`rine._actor`
— the same split, for the same reason. :mod:`rine._resolve` is already past this
project's ~200-line ceiling and holds three resolvers besides this one, so the
group-reference *contract* (the normalisation, the ladder, the refusals) lives
here and the resolvers that consume it stay there.

**The ladder.** A bare reference is matched in ordered tiers, and the first tier
with any match decides:

1. exact equality against the handle's local part,
2. normalised equality against the local part **or** the group's ``name``,
3. a unique normalised whole-segment prefix of either,
4. and, only when 1–3 matched **nothing at all**, the same three again against
   the reference with one generic classifier noun peeled off its tail (or one
   leading article off its head), one word at a time.

A tier with more than one match **refuses**; it never falls through to a looser
one, because a looser tier would then silently overrule a real ambiguity.

Tier 4 is why :data:`GENERIC_GROUP_NOUNS` exists, and its whole justification is
there: a word that names the KIND of thing a group is cannot tell two of an
org's groups apart, so dropping it and asking again is reading the reference,
not guessing at it. It can only turn a certain 404 into a resolution or into a
refusal that names candidates — never move a reference that already resolved.

🔴 **Tier 3 is an affordance, not a benchmark accommodation.** It is the rule
every reference-taking tool ships — git abbreviates a rev, docker a container,
kubectl a resource — under the same bound: a partial reference resolves only
when it is unambiguous, and otherwise names the candidates. It is strictly
widening. Every reference that resolved before this module existed resolves to
the same group through tier 1, and only a reference that was a guaranteed 404
can reach tiers 2 and 3. No group name, goal or prompt from any harness appears
here or in the tests that pin it.

**Why a bare recipient reaches a group at all.** ``send()`` decides group vs 1:1
on a leading ``#``, so a caller who names a group the way they say it out loud
lands on the 1:1 path — where :func:`rine._resolve.resolve_to_uuid_async`
refuses a bare word *syntactically, before any request*, and tells them to go
and find an **agent** handle. A bare recipient is therefore already categorically
not an agent, which is what makes :func:`recipient_group_for_bare_name` safe:
it can only turn a certain refusal into a correct group send or a better
refusal. :func:`refuse_if_a_bare_agent_name` is the one guard that matters —
a caller who meant ``ops@acme`` and wrote ``ops`` must never silently post to a
group called ``ops``.

**And why a sigiled one does.** ``#ops`` used to fall between the two: the
leading ``#`` said "already a full handle", so ``send()`` asked the server's
``?handle=`` filter, which matches ``#name@org`` and nothing shorter. Every other
group verb had meanwhile accepted the spelling for as long as the ladder has
existed. :func:`is_sigil_group_reference` claims it for
:func:`group_row_by_local_name`, the same ladder, so the two spellings of one
group resolve identically — and the bare path's agent guard is deliberately not
run for it, because a caller who typed the group sigil has already said which
namespace they meant.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from rine._recipient import REF_CLASS_BARE, REF_CLASS_GROUP, classify_reference
from rine.errors import ConfigError, NotFoundError

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The lead every "no such group" refusal opens with, byte-for-byte.
#:
#: Five published surfaces branch on it to decide which HALF of the directory a
#: model is sent to, and the server raises the same phrase as a bare literal.
#: ``tests/test_client-server-contract_group0.py`` pins the copies; this is the
#: one this package composes with.
GROUP_NOT_FOUND_LEAD = "Group not found"

#: The SECOND lead: what a BARE recipient name is refused with.
#:
#: A bare name is the one spelling that named no namespace, so a verdict about
#: groups alone was never the whole answer — by the time
#: :func:`recipient_group_for_bare_name` refuses, the agent namespace has
#: declined the spelling on syntax AND no agent of this org carries the name, so
#: both halves have already answered no. Leading with *"Group not found"* told a
#: caller only the half they had not asked about.
#:
#: 🔴 **It is the invariant TAIL of that lead sentence, not its first bytes** —
#: the caller's own spelling opens it, which is the whole point of the reword —
#: so the six surfaces that discriminate on it must use a CONTAINMENT test,
#: never ``startswith``. :data:`GROUP_NOT_FOUND_LEAD` keeps its ``startswith``
#: semantics and its value: every ``rine_group_*`` verb, the server's four
#: modules and :func:`unknown_group_refusal` still open with it, because there
#: the caller DID name a group.
#:
#: Registered in ``tests/helpers_client_paths.py`` as
#: ``NEITHER_NAMESPACE_LEAD_COPIES`` and gated the way the first lead is — with
#: one difference that is a property of the phrase rather than an omission: this
#: one has no server copy to compare against. The server never composes it; it
#: is minted on both client stacks and nowhere else.
NEITHER_NAMESPACE_LEAD = "names neither an agent nor a group you can reach"

#: The sentence that introduces the group list in a group refusal.
#:
#: Exported because the three wrapper packages branch on its presence: once a
#: refusal carries the roster, telling the caller to run the verb that prints
#: the roster is advice to fetch what they are already reading. Imported there,
#: never retyped — a fourth copy of a sentence is how the two TypeScript
#: not-a-member texts drifted.
#:
#: It says "name one of these" rather than "your groups are", because the
#: ambiguous arm passes the candidates rather than the whole roster and the
#: sentence has to stay true of a subset.
GROUP_ROSTER_LEAD = "Name one of these groups:"

#: What the tail says instead, for an org that is in no groups at all.
#:
#: The half a hand-rolled copy always drops — see
#: :func:`rine._actor._and_the_agents_there_are`, whose docstring records the
#: shipped sentence that trailed off exactly where the caller most needed to be
#: told there was nothing to choose from. Exported for the same reason
#: :data:`GROUP_ROSTER_LEAD` is: a wrapper that suppresses "run the roster verb"
#: must suppress it here too, where the roster is empty and that verb can answer
#: nothing.
NO_GROUPS_IN_ORG = "This org is in no groups yet."

#: How many groups a refusal prints before it says "and N more".
#:
#: An org's group list is unbounded — nothing on the server caps how many groups
#: it may join — and a refusal is read by a model with a context window, so the
#: whole roster is not always the kind answer.
MAX_LISTED_GROUPS = 20

#: Trailing segments that name the KIND of thing a group is, never the thing.
#:
#: A reference holds two kinds of segment. One names the group —
#: ``payroll``, ``roadmap``, ``incidents``. The other names the kind of thing
#: the group is, and carries nothing that could tell two of an org's groups
#: apart: "the ops group" and "the ops chat" are the same sentence to a person,
#: and neither word is what makes the group theirs. So a reference that matched
#: NOTHING drops a trailing one of these and asks again — reading the sentence
#: the way the person who wrote it meant it, not guessing at it.
#:
#: 🔴 ``thread`` is deliberately absent, and it is the only near-miss worth
#: naming: a conversation thread is a first-class rine entity a caller can
#: reference, and this ladder is reached FROM the thread verb, so ``thread``
#: here would peel a word inside the verb that word names. ``team`` and
#: ``list`` are absent because both are content in the domains this product
#: serves (``#platform-team``, ``pick-list``), and ``dm``/``inbox`` because
#: they name the 1:1 namespace — answering one with a group is the misdelivery
#: this ladder exists to avoid. Byte-identical to the twin's set, which
#: ``rine-core/test/group-ref.test.ts`` pins.
GENERIC_GROUP_NOUNS = frozenset(
    {"group", "groups", "channel", "channels", "chat", "chats", "room", "rooms"}
)

#: The one article a caller writes in front of a group's name.
#:
#: Leading position only — a trailing ``the`` is not a thing a person writes.
#: ``a``/``an`` are excluded: neither is natural in a recipient slot, and both
#: are two-letter tokens with a real chance of colliding with a slug segment.
LEADING_ARTICLES = frozenset({"the"})

_NON_ALNUM_RUN = re.compile(r"[\W_]+")


def normalize_group_ref(value: str) -> str:
    """The one spelling two references are compared in.

    Case-folded, every run of non-alphanumerics collapsed to ``-``, and stripped
    of leading and trailing ``-``. That makes ``Quarterly Planning``,
    ``quarterly_planning`` and ``quarterly-planning`` one string, which is the
    whole of tier 2 — a person names a group in prose and the server stores a
    handle local part in ``[a-z0-9-]``.

    Unicode-aware on purpose: ``\\W`` keeps letters and digits outside ASCII, so
    a group named ``café`` normalises to ``café`` rather than to ``caf``.

    ⚠️ ``casefold()`` is FULL case folding and the twin's ``toLowerCase()`` is
    simple case mapping, so this side resolves a handful of references the
    TypeScript stack refuses — ``Straße``, the ``ﬁ``/``ﬃ`` ligatures, ``ΣΣ``,
    ``ᾼ``. Only the caller's REFERENCE can carry one (both spellings a group
    answers to are DNS slugs), the divergence is measured rather than guessed,
    and the whole table lives with the twin in
    ``rine-core/src/group-ref.ts::normalizeGroupRef`` — one copy, so the two
    cannot disagree about how they disagree.
    """
    return _NON_ALNUM_RUN.sub("-", value.casefold()).strip("-")


def is_bare_reference(value: str) -> bool:
    """Whether a recipient spelling names neither namespace, as written.

    Not a UUID, no ``@``, no leading ``#`` — the exact set
    :func:`rine._resolve.resolve_to_uuid_async` refuses before any HTTP, which is
    why routing it to the group ladder can take nothing away.

    A blank recipient is deliberately NOT one of them. It names nothing in
    either namespace, and the agent resolver's *"expected a UUID or handle"*
    says that far better than a hunt through the org's groups ending in *"no
    group is called ''"* would.

    One reading of :func:`~rine._recipient.classify_reference`, not a fifth
    hand-rolled restatement of the same four conjuncts: this predicate and the
    table were written separately, agreed on every input, and only one of them
    can now be changed.
    """
    return classify_reference(value) == REF_CLASS_BARE


def is_sigil_group_reference(value: str) -> bool:
    """Whether a recipient spelling names a group by sigil and nothing else.

    ``#ops`` — the group sigil, and no ``@`` to make it a whole handle.
    Byte-equivalent to its TypeScript twin ``isSigilGroupReference``
    (``rine-core/src/group-ref.ts``); the two answer the same set, and a third
    conjunct on either side is drift, not defence. Deliberately
    the COMPLEMENT of :func:`is_bare_reference` on the one spelling that
    predicate excludes for a reason it does not own: ``is_bare_reference`` means
    *"neither namespace answers this as written"*, and a sigiled reference **is**
    in the group namespace as written. Widening that predicate instead would
    route this spelling through
    :func:`refuse_if_a_bare_agent_name` — a guard that exists for the ambiguity
    of an unsigiled word and can only misfire on a sigiled one.

    ``#ops@acme`` is not one of these: it carries its org and the server's
    ``?handle=`` filter answers it directly.

    A lone ``#`` or ``#   `` IS claimed, and deliberately. It names no group, so
    it cannot resolve — but :func:`group_reference_matches` already refuses an
    empty normalisation before tier 2 can prefix-match on it, so what the caller
    gets back is :func:`unknown_group_refusal`, naming the groups their org
    actually has. Excluding it here would send the raw ``#`` to the wire instead,
    for a bare 404 with no roster behind it: the very dead zone this predicate
    exists to close. Its TypeScript twin claims it for the same reason.

    The second conjunct is this predicate's own and stays here: the table says
    a sigiled reference is in the group namespace, which is true of
    ``#ops@acme.rine.network`` too, and what ``send()`` needs to know is the
    narrower thing — that no org half accompanies it, so the server's
    ``?handle=`` filter cannot answer it.
    """
    return classify_reference(value) == REF_CLASS_GROUP and "@" not in value


def group_local_part(handle: str) -> str:
    """A group handle's local part: ``#ops@acme.rine.network`` → ``ops``.

    Exported because it is also the only query that can find a group in the
    public directory by handle: ``POST /groups`` mints the handle as
    ``#{name}@{org}`` and ``name`` is a validated DNS slug, so the local part
    **is** ``Group.name`` byte for byte, and ``GET /directory/groups?q=`` — which
    searches ``name`` and ``description``, never ``handle`` — will return the row
    when asked for it. :mod:`rine._group_join` is the caller that needs that.

    🔴 ``lstrip("#")`` strips a whole RUN of sigils, and that is pinned, not
    incidental — do not "tidy" it to ``removeprefix("#")``. The twin
    (``groupLocalPart``, ``rine-core/src/group-ref.ts``) stripped one sigil for a
    while, and the two stacks disagreed on ``##ops``:
    :func:`rine._group_join.is_invitation_of_that_name` seated ``join("##ops")``
    on the three Python connectors and refused it on eve and mastra. The stacks
    converged HERE, on the forgiving spelling, because tightening this side
    would remove a spelling that already ships — and a doubled sigil can reach
    no group a single one could not, since the rung it feeds is bounded to
    groups that have already invited this agent.
    """
    return handle.split("@")[0].lstrip("#")


def sigiled_group_ref(reference: str) -> str:
    """A group reference with its ``#`` on, which is how group handles compare.

    🔴 **The sigil is not decoration on the wire.** A stored group handle always
    carries it (``POST /groups`` mints ``#{name}@{org}``), and the server's
    ``?handle=`` filter is an equality test against that stored string — so a
    caller who writes ``ops@acme.rine.network``, which every handle comparison
    in this SDK treats as the same reference, misses the lookup entirely unless
    the sigil is put back first.

    One helper rather than the eleventh inline restatement of
    ``x if x.startswith("#") else "#" + x``: the two callers that matter are the
    seated lookup on both clients and the join ladder's exactness filter
    (:mod:`rine._group_join`), and those two disagreeing is a group that
    resolves for one verb and 404s for another. Its TypeScript twin is
    ``sigiledGroupRef`` (``rine-core/src/group-ref.ts``).
    """
    return reference if reference.startswith("#") else f"#{reference}"


def _local_part(group: dict[str, Any]) -> str:
    """The local part of a group ROW's handle. See :func:`group_local_part`."""
    return group_local_part(str(group.get("handle", "")))


def _tiers_one_to_three(groups: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """The candidates the first of tiers 1–3 that matches anything produces.

    Returns every match of that tier, never the first one and never a merge of
    two tiers: the caller decides what one match, several, or none mean, and it
    must be able to tell "this tier was ambiguous" from "no tier matched".

    A group that matches by both its handle and its name is one candidate, not
    two — the tiers are evaluated per group, so the identity of a match is the
    group, never the spelling that found it.

    Private, and it stays private: tier 4 re-runs this whole body against a
    reduced reference, so a caller that reached it directly would be asking for
    the ladder minus its last rung and would drift the moment a rung moves.
    Behaviour is pinned through :func:`group_reference_matches` and the two
    entry points, never through here.

    Args:
        groups: The caller's own groups, as ``GET /groups`` returned them.
        name: The reference, with any leading ``#`` and surrounding space gone.
    """
    exact = [g for g in groups if _local_part(g) == name]
    wanted = normalize_group_ref(name)
    if exact or not wanted:
        # An empty normalisation (``"#"``, ``"---"``) would prefix-match every
        # group in the org, so tiers 2 and 3 are not reachable without one.
        return exact

    def spellings(group: dict[str, Any]) -> tuple[str, str]:
        # The handle's local part and ``name``. ⚠️ On every group this server
        # has minted those are the SAME string — ``POST /groups`` builds the
        # handle as ``#{name}@{org}`` unconditionally and ``GroupUpdate`` has no
        # ``name`` field, so a group's name is its handle's local part and is
        # immutable — which makes the second spelling inert rather than a second
        # chance to match. It is kept because ``name`` is a wire field the
        # server sends on every listing: the day it diverges from the slug, the
        # ladder must not refuse the string the product itself printed. A match
        # is identified by the GROUP, never by the spelling that found it, so it
        # can never widen a tier past what the local part already reached.
        return normalize_group_ref(_local_part(group)), normalize_group_ref(
            str(group.get("name") or "")
        )

    equal = [g for g in groups if wanted in spellings(g)]
    if equal:
        return equal
    segments = wanted.split("-")
    return [
        g
        for g in groups
        if any(
            spelled.split("-")[: len(segments)] == segments for spelled in spellings(g) if spelled
        )
    ]


def _reduced_references(wanted: str) -> Iterator[str]:
    """The shorter references tier 4 tries, shortest peel first.

    ONE segment per step, the leading article before any trailing noun, and the
    remainder yielded after each — because the caller re-runs the whole ladder
    between two steps, and only that ordering lets a longer group win. An org
    holding ``#ops-chat`` and ``#ops``, given ``ops chat room``, must resolve
    ``#ops-chat``: a single whole-run strip would yield ``ops`` and steal the
    answer from the group that answers to more of what the caller wrote.

    Peeling only ``while len(segments) > 1`` is the loop condition rather than
    a check afterwards, which makes an empty remainder unrepresentable, bounds
    the walk at ``len(segments) - 1`` steps, and is what makes ``the group``,
    ``groups`` and ``the`` refuse instead of prefix-matching the whole org.

    Args:
        wanted: The reference, already through :func:`normalize_group_ref`.
    """
    segments = wanted.split("-")
    if len(segments) > 1 and segments[0] in LEADING_ARTICLES:
        segments = segments[1:]
        yield "-".join(segments)
    while len(segments) > 1 and segments[-1] in GENERIC_GROUP_NOUNS:
        segments = segments[:-1]
        yield "-".join(segments)


def group_reference_matches(groups: list[dict[str, Any]], name: str) -> list[dict[str, Any]]:
    """The candidates the ladder produces, tier 4 included.

    Tiers 1–3 first, unchanged and unreachable-past: they decide alone whenever
    they match anything at all, so no reference that resolved before tier 4
    existed can move. Tier 4 fires ONLY on the empty result — it drops one
    generic classifier noun (or the leading article) from the reference and
    re-runs tiers 1–3 against the remainder, again and again while there is a
    remainder to try.

    🔴 That makes it strictly widening. The only transitions it can introduce
    are "no such group" → resolved, "no such group" → an ambiguity refusal that
    names the candidates, and "no such group" → "no such group". A resolution
    can neither move nor become a refusal.

    A loop over :func:`_tiers_one_to_three`, never recursion through this
    function: recursion would make the peel order depend on call depth and the
    termination bound something a reader has to derive.

    Args:
        groups: The caller's own groups, as ``GET /groups`` returned them.
        name: The reference, with any leading ``#`` and surrounding space gone.
    """
    matches = _tiers_one_to_three(groups, name)
    if matches:
        return matches
    for reduced in _reduced_references(normalize_group_ref(name)):
        matches = _tiers_one_to_three(groups, reduced)
        if matches:
            return matches
    return []


def _and_the_groups_there_are(lead: str, groups: list[dict[str, Any]]) -> str:
    """One refusal's tail: the groups worth naming, or the reason there are none.

    Every arm that refuses a group reference ends here, so neither the roster nor
    the empty-org sentence can be lost by one of them — the exact contract
    :func:`rine._actor._and_the_agents_there_are` holds for the actor refusals,
    and for the same reason: the hand-rolled copies are what kept dropping the
    empty arm.

    The handle leads each row because it is the spelling the caller can hand
    straight back; the name follows in parentheses because it is the spelling
    they started from.

    The empty-field arms are a guard against a wire that contradicts its own
    type, and are worth naming precisely so nobody reads them as a fact about
    groups: ``groups.name`` and ``groups.handle`` are both ``nullable=False``
    (``src/rine/db/models.py``) and ``GroupRead`` types them ``str``, so no row
    the server can mint reaches them. What the actor side's ``bob (None)``
    incident is a precedent for is the SHAPE of the arm — ``.get`` with a
    default does not fire on a key that is present and ``None`` — not for a
    nullability groups do not have (``agents.handle`` genuinely is nullable).
    They cost two ``or``s and they are what stands between a bad row and a
    refusal that reads ``None``, which is a refusal a caller cannot act on at
    all.
    """
    if not groups:
        return f"{lead} {NO_GROUPS_IN_ORG}"
    shown = groups[:MAX_LISTED_GROUPS]
    rows = []
    for group in shown:
        handle = str(group.get("handle") or group.get("id") or "?")
        label = str(group.get("name") or "")
        rows.append(f"  - {handle} ({label})" if label else f"  - {handle}")
    if len(groups) > len(shown):
        rows.append(f"  … and {len(groups) - len(shown)} more")
    listed = "\n".join(rows)
    return f"{lead} {GROUP_ROSTER_LEAD}\n{listed}"


def compose_group_refusal(
    detail: str,
    candidates: list[dict[str, Any]] | None = None,
    *,
    next_step: str | None = None,
) -> str:
    """Every group refusal this package says, assembled in one place.

    Three parts, and the composer's whole reason to be a function rather than a
    template is which of them it is allowed to say TOGETHER:

    1. ``detail`` — what happened, quoting the caller's own spelling. Always.
    2. ``candidates`` — the groups worth naming, through
       :func:`_and_the_groups_there_are`, which owns the
       :data:`MAX_LISTED_GROUPS` cap, the overflow row and the empty-org
       sentence. Pass ``[]`` to say *"there were none"*; pass ``None`` to say
       *"a roster is not the answer here"*.
    3. ``next_step`` — the verb to run instead.

    🔴 **A refusal that lists candidates does not also name a next step.**
    Telling a caller to run the verb whose answer they are already reading is
    the measured over-suggestion failure (``rine-hermes``' client), and a model
    reading it runs that verb rather than picking a candidate. So rule 3 is a
    suppression, not a formatting preference: ``candidates`` wins and
    ``next_step`` is dropped.

    Every part it joins ends in a ``.``, added here rather than at four call
    sites — which is the class of divergence that put a doubled period into one
    shipped sentence and none into its twin.

    🔴 **Added, never enforced by rewriting the tail.** A part that already ends
    in a stop is passed through exactly as written, because its tail is not the
    composer's: :func:`unknown_group_refusal` quotes the caller's own spelling
    there, so ``resolve_group("ops.")`` puts the period into the sentence and
    ``rstrip`` would eat it — turning the shipped ``Group not found: ops.. Name
    one of these groups:`` into ``… ops. Name …``. The TypeScript twin's
    ``joinSentences`` reads the same way.

    ⚠️ Deviates from the contract's ``{lead, spelling}`` pair, deliberately and
    with one reason: :func:`ambiguous_group_refusal` carries the spelling in the
    MIDDLE of its sentence (*"Group name 'x' is ambiguous — …"*), so a composer
    that could only append the spelling to a lead could not reproduce that
    sentence, and byte-identity is the acceptance test. The TypeScript twin
    keeps the pair. What both stacks share is rules 2–4, which is where the
    behaviour lives.
    """
    said = _terminated(detail)
    if candidates is not None:
        return _and_the_groups_there_are(said, candidates)
    if next_step:
        return f"{said} {_terminated(next_step)}"
    return said


def _terminated(part: str) -> str:
    """One sentence, ending in a stop — its own if it wrote one."""
    return part if part.endswith(".") else f"{part}."


def unknown_group_refusal(groups: list[dict[str, Any]], name: str) -> str:
    """Told to a caller whose reference answers to no group of this org."""
    return compose_group_refusal(f"{GROUP_NOT_FOUND_LEAD}: {name}.", groups)


def ambiguous_group_refusal(matches: list[dict[str, Any]], name: str) -> str:
    """Told to a caller whose reference answers to more than one group.

    Picking one would read, post to, or invite into a group the caller did not
    choose — and ``GET /groups`` has no ``ORDER BY``, so which one it picked
    could differ between two identical calls. The candidates are printed instead,
    by handle, which is the spelling that still tells two same-named groups of
    two different orgs apart.
    """
    return compose_group_refusal(
        f"Group name '{name}' is ambiguous — more than one group answers to it.", matches
    )


def _single_match_or_ambiguous(
    groups: list[dict[str, Any]], name: str, wanted: str
) -> dict[str, Any] | None:
    """The one group ``wanted`` answers to, ``None`` if none does, or a refusal.

    The ladder's shared body. Two entry points run it — the group-verb one
    (:func:`group_row_by_local_name`, which strips the sigil) and the send
    recipient one (:func:`recipient_group_for_bare_name`, which does not, because
    a bare recipient never carries one) — and they differ in nothing else but the
    sentence they say when nothing matched. The ambiguity refusal is the arm that
    must NEVER differ between them, so it lives here and is stated once.

    The zero-match arm answers ``None`` rather than raising, so each caller keeps
    its own sentence and pays for building it only on the path that shows it.

    Args:
        groups: The caller's own groups, as ``GET /groups`` returned them.
        name: The reference as the caller wrote it, for the refusal to quote.
        wanted: The same reference, prepared for the ladder.

    Raises:
        ConfigError: More than one group answers to it.
    """
    matches = group_reference_matches(groups, wanted)
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise ConfigError(ambiguous_group_refusal(matches, name))
    return None


def group_row_by_local_name(
    groups: list[dict[str, Any]], name: str, spelling: str | None = None
) -> dict[str, Any]:
    """Resolve a group reference against the caller's own groups.

    The server's ``GET /groups?handle=`` matches a *full* ``#name@org`` handle
    only, so a bare ``ops`` — or a sigiled, org-less ``#ops`` — finds nothing
    there however many groups carry that name. Listing the org's groups and
    running the ladder over them is what lets every group verb take the name a
    caller says out loud.

    🔴 The leading ``#`` is stripped **before** the ladder, never passed into it.
    Tier 1 is exact equality against the handle's local part, so ``#ops`` carried
    through would miss it and land on tier 2 by accident — the sigiled and the
    bare spelling of one group would be decided by different tiers, and an org
    holding both an ``ops`` local part and a second group whose name normalises
    onto ``ops`` would flip from a clean tier-1 match to an ambiguity refusal.

    Args:
        groups: The caller's own groups, fetched with the acting agent's header.
        name: Group reference; a leading ``#`` is ignored.
        spelling: What the CALLER wrote, when that is not ``name``. A handle
            whose org half found nothing is sent down this ladder on its local
            part, and a refusal that quoted the local part would answer a caller
            about a string they never typed — *"Group not found: heron-count"*
            said to someone who wrote ``#heron-count@acme.rine.network``. The
            ladder still runs on ``name``; only the sentence changes. Its
            TypeScript twin is ``matchGroupByName``'s third argument.

    Returns:
        The group row, so a caller that needs the handle rather than the id — the
        send path addresses ``to_handle`` — can read it without a second lookup.

    Raises:
        NotFoundError: No group answers to that reference.
        ConfigError: More than one does.
    """
    said = name if spelling is None else spelling
    match = _single_match_or_ambiguous(groups, said, name.strip().lstrip("#").strip())
    if match is None:
        raise NotFoundError(unknown_group_refusal(groups, said))
    return match


def match_group_by_local_name(
    groups: list[dict[str, Any]], name: str, spelling: str | None = None
) -> str:
    """The id of the group a reference names — :func:`group_row_by_local_name`'s id.

    🔴 A projection, never the resolution — the ladder answers with the ROW and
    this reads one column off it. No rung calls it any more: the group ladder
    (:func:`rine._recipient_ladder.group_ladder`) wants the row, and a caller
    that wants an id takes it off the :class:`~rine._recipient.GroupTarget` the
    client's ``resolve_group`` hands back. What survives here is the NAME, which
    three connector suites import as the shortest way to produce a real
    ``NotFoundError``/``ConfigError`` from a roster — and it is kept, because
    the id-only shape ceasing to be the primitive is the whole point and
    deleting the projection was not asked for.
    """
    return str(group_row_by_local_name(groups, name, spelling)["id"])


def refuse_if_a_bare_agent_name(agents: list[dict[str, Any]], name: str) -> None:
    """The whole safety argument for resolving a bare recipient as a group.

    A caller who meant ``ops@acme`` and wrote ``ops`` must not silently post to a
    group called ``ops``. The two namespaces answer to the same word, and only
    one of them can be entered by mistake here, so a bare name that is also an
    agent's name is refused outright — never a silent DM either, because
    recipient resolution requires a handle by design and widening the agent side
    is a decision nobody has taken.

    Lives beside the group ladder rather than in :mod:`rine._actor` because it is
    not part of the acting-agent contract: it exists only as the gate in front of
    :func:`recipient_group_for_bare_name`, and reads the same org agent list the
    caller has already fetched.

    ⚠️ The fold below carries the same ``casefold``/``toLowerCase`` divergence
    :func:`normalize_group_ref` records, and it is worth saying HERE because this
    is the guard the safety argument rests on: a reference the twin does not fold
    the same way is one the twin does not refuse. It is unreachable today — an
    agent's ``name`` is a DNS slug (``src/rine/api/schemas.py``), so only the
    caller's spelling can carry a folding case, and a caller who types ``STRASSE``
    at an agent named ``strasse`` is refused here and sent to the group ladder on
    the TypeScript side, where nothing answers to it either. Reachability would
    change the day an agent name stops being a slug.

    🔴 The group spelling it offers is **derived**, never a template. The
    handles this refusal already prints carry the caller's own org, so the
    sentence can name the group the caller would actually write —
    ``#ops@acme.rine.network`` — instead of ``#name@org``, a slot in exactly the
    shape a model fills in with the placeholder word rather than a value.

    🔴 A slugless org mints no handles and has nothing to derive from, and that
    arm used to print ``#logistics@acme.rine.network`` and label it an example —
    a placeholder domain inside a refusal, which is banned. It answers with the
    sigil form of the caller's own word instead. ``#ops`` is not a hedge and not
    a shape: it is a first-class recipient spelling
    (:func:`is_sigil_group_reference`), it is the one spelling this guard is
    deliberately SKIPPED for — so it turns this very refusal off — and it needs
    no org half, which is the entire content of
    "slugless". The sentence it replaces was worse than a placeholder: it
    offered a handle spelling to the one caller who provably cannot construct
    one.

    Raises:
        ConfigError: An agent of this org carries that name.
    """
    folded = name.strip().casefold()
    named = [a for a in agents if str(a.get("name") or "").casefold() == folded]
    if not named:
        return
    spellings = ", ".join(str(a.get("handle") or a.get("id") or "?") for a in named)
    raise ConfigError(
        compose_group_refusal(
            f"'{name}' is the name of an agent of your org, not a group reference. "
            f"To message that agent, name it by handle: {spellings}",
            next_step=(
                "To post to a group of that name, write it as "
                f"{_group_spelling_for(named, folded)}"
            ),
        )
    )


def _group_spelling_for(agents: list[dict[str, Any]], local_name: str) -> str:
    """How the caller's own org spells a group handle, or the sigil form alone.

    Reads the org part off the first agent handle in hand. Nothing else on this
    path knows the caller's org, and a group reference the caller can paste beats
    a shape they have to translate. When no handle carries an org half there is
    nothing to derive, and printing an example domain in a refusal is banned —
    so the answer is ``#ops``, the caller's own word under the sigil, which is
    a spelling this stack accepts and needs no org at all. The reasoning is in
    :func:`refuse_if_a_bare_agent_name`; the TypeScript twin is
    ``refuseIfABareAgentName``'s ``asAGroup``.

    🔴 ``split("@")[1]`` and not ``rpartition("@")``, because the twin is
    ``handle.split("@")[1]`` and the two disagree on a handle with no ``@`` at
    all: ``rpartition`` hands back the WHOLE string as the org half, so ``solo``
    refused with ``#solo@solo`` here and ``#solo`` there — one input, two
    sentences, in the phase whose premise is that there is one. The golden's
    slugless vector carries ``handle: null``, on which both stacks always
    agreed, so nothing could see it; ``bare-agent-collision-handle-has-no-org``
    is the vector that can.
    """
    for agent in agents:
        handle = str(agent.get("handle") or "")
        parts = handle.split("@")
        org = parts[1] if len(parts) > 1 else ""
        if org:
            return f"#{local_name}@{org}"
    return f"#{local_name}"


def recipient_group_for_bare_name(groups: list[dict[str, Any]], name: str) -> dict[str, Any]:
    """The group a bare ``send()`` recipient names, or a refusal that names both.

    Run only after :func:`refuse_if_a_bare_agent_name` has cleared the name, and
    only for a spelling :func:`is_bare_reference` claims — which the agent
    namespace has already declined on syntax.

    🔴 **The zero-match arm does not open with a GROUP verdict.** It used to
    lead with :data:`GROUP_NOT_FOUND_LEAD`, and that was half an answer
    to a question the caller had not asked in either namespace: by the time this
    arm fires the reference cannot be an agent identifier AND no agent of this
    org carries the name, so both halves have said no and only the group half
    was reported. It opens with :data:`NEITHER_NAMESPACE_LEAD` instead — the
    caller's spelling, then both verdicts at once — and still names both
    spellings, because the caller's next attempt has to pick one of them.

    🔴 The lead swap is the whole of this arm's user-visible change; the roster
    still comes last, and the six surfaces that branch on a lead were widened
    alongside it. Landing this in ``rine-sdk`` alone is the silent reroute the
    ``_client.py`` docblocks warn about.

    🔴 What it must never say is what it used to: *"a bare name is neither"*.
    A bare name **is** read as a group — that is this function — and every tool
    description on every surface now teaches a caller to write one. A refusal
    that contradicts the instruction the caller has just followed teaches them
    the product is broken rather than that this org has no such group. It says
    what was looked for and where instead, and the roster tail below names what
    there was to find.

    🔴 **The two spellings are DESCRIBED and no longer shown.** This arm used to
    print ``kofi@acme.rine.network`` and ``#logistics@acme.rine.network``, and
    both were baked into the LEAD, so the roster's own suppression rule could
    never take them back out when the roster below is appended — a placeholder
    domain in a refusal, twice, under a list of the caller's real handles.
    Measurement is what settled it: given a printed domain, a model moves the
    local part with the conversation and leaves the domain exactly where it
    found it. Deriving the caller's own org from a handle the sentence already
    prints is unreachable here — this function holds groups and no agents, and
    the arm fires precisely when NO group answered — so it describes the shape
    instead, with nothing in it to paste. Not an ``@org``-style slot either:
    ``check-model-facing-examples.mjs``'s ``template-org`` rule forbids that for
    the measured ``agent:"null"`` reason.
    The advice itself is kept, which is what separates this from dropping the
    guidance altogether — a caller is still told that the two namespaces are
    addressed differently and how each is shaped.

    Returns:
        The group row, so the caller can send to its handle down the very same
        path a ``#handle`` send takes.

    Raises:
        NotFoundError: No group answers to that reference.
        ConfigError: More than one does.
    """
    match = _single_match_or_ambiguous(groups, name, name.strip())
    if match is not None:
        return match
    raise NotFoundError(
        compose_group_refusal(
            f"'{name}' {NEITHER_NAMESPACE_LEAD}. A bare name is read as a group this "
            "org is seated in, and none of them answers to it. An agent is "
            "addressed in full — its name, an at sign, and its org's domain — "
            "and a group by its whole handle, which is a leading hash and the "
            "same three parts.",
            groups,
        )
    )


__all__ = [
    "GROUP_NOT_FOUND_LEAD",
    "GROUP_ROSTER_LEAD",
    "MAX_LISTED_GROUPS",
    "NEITHER_NAMESPACE_LEAD",
    "NO_GROUPS_IN_ORG",
    "ambiguous_group_refusal",
    "compose_group_refusal",
    "group_local_part",
    "group_reference_matches",
    "group_row_by_local_name",
    "is_bare_reference",
    "is_sigil_group_reference",
    "match_group_by_local_name",
    "normalize_group_ref",
    "recipient_group_for_bare_name",
    "refuse_if_a_bare_agent_name",
    "sigiled_group_ref",
    "unknown_group_refusal",
]
