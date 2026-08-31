"""What a group reference MEANS when the verb is join — matchers and sentences.

The pure half of the join ladder: which reference answers to which row, what the
directory is asked for and how far, and every sentence a refused join says. The
rungs themselves live on the two clients, beside the fetches they make (the same
seam ``_fetch_own_groups`` holds).

🔴 **Join is the one group verb whose target is, by definition, a group the
caller is NOT in.** Every other verb — read, send, invite, vote, leave — asks
about a group this org already holds a seat in, so the shared ladder in
:meth:`rine.RineClient._resolve_group_async` is right for them: it lists ``GET
/groups``, which is org-scoped, and a stranger's handle answering nothing there
is the server's answer rather than a defect. For join that same ladder is
exactly backwards. It searches the one set that cannot contain the target, so a
handle a caller had just read off ``discover_groups()`` came back ``Group not
found`` with the server never having refused anything.

**A handle walks three rungs.**

1. ``GET /groups?handle=`` — the group this org is already seated in. It resolves
   so the server can answer the honest ``409 Agent is already a member`` instead
   of a client-side "not found" about a group the caller is standing in.
2. ``GET /groups/invites`` — the group that invited or nominated this agent. An
   invitation mints no membership row, so rung 1 structurally cannot see it.
3. ``GET /directory/groups?q=`` — a public group with no relationship at all.

**A bare name walks one, and only one.** It is looked for among this agent's
pending invitations and nowhere else — see
:data:`BARE_NAME_IS_ONLY_AN_INVITATION`. A UUID is already the answer.

🔴 **Why the directory rung is not the widening that was refused.** The directory
filter is ``name ILIKE`` OR ``description ILIKE``, and a fuzzy match feeding an
irreversible verb is what killed bare-name resolution. Here the ILIKE is a
**candidate generator only**: every row it returns is put through
:func:`is_exact_group_handle`, and group handles are ``UNIQUE`` on the server, so
at most one row can survive and it is by definition the group the caller named.
A wrong match is not reachable. The identifier is resolved; a different group is
never joined.

🔴 **Twin of ``rine-core/src/group-join-words.ts``.** Same matchers, same bounds,
and the five sentences below are byte-identical to that module's;
``tests/test_client-server-contract_group0.py`` pins the copies against each
other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rine._group_ref import GROUP_NOT_FOUND_LEAD, group_local_part, sigiled_group_ref
from rine._resolve import normalize_handle

#: What ``GET /directory/groups`` will return in one page at most.
#:
#: The server's own ceiling (``limit`` is bounded 1–50 in
#: ``src/rine/api/directory_groups.py``); asking for it is asking for the fewest
#: round trips a join can be resolved in.
DIRECTORY_PAGE_LIMIT = 50

#: How many directory pages a single join may read before it gives up.
#:
#: A bound rather than a full walk, so a caller cannot turn one join into an
#: unbounded crawl of an IP-rate-limited public route.
#:
#: 🔴 **A bound is only honest if the refusal says it was hit.** The directory
#: orders by recency, not by match quality, and its filter is ``name ILIKE`` OR
#: ``description ILIKE`` — so a crowded substring can push the named group past
#: this budget however exact the caller's handle was. That is what
#: :data:`DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ` exists for: the shortfall is
#: stated from the ``total_estimate`` the response already carries, and the
#: exhausted sentence is never said about a search that stopped early.
DIRECTORY_PAGES_FOR_A_JOIN = 2

#: What a caller must hand ``join`` instead, named in the refusals below.
#:
#: 🔴 Twin sentence — ``JOIN_TAKES_A_HANDLE_OR_AN_ID`` in
#: ``rine-core/src/group-join-words.ts`` restates it byte for byte, and
#: ``tests/test_client-server-contract_group0.py`` pins the two copies against
#: each other. It names the two spellings and stops there: WHICH verb prints
#: them is a per-surface fact this SDK cannot know, and every wrapper appends it
#: already — the three Python connectors and both TypeScript ones key on
#: :data:`rine._group_ref.GROUP_NOT_FOUND_LEAD` and add *"Try rine_groups … or
#: rine_discover_groups …"* in that surface's own vocabulary. A verb named here
#: too would be named twice, in one of them wrongly.
#:
#: 🔴 **A refusal names no placeholder domain.** This is a REFUSAL — it is
#: spliced into :func:`bare_name_join_refusal` and
#: :func:`unresolved_handle_join_refusal` — so the example domain it used to
#: print is banned. Deriving one from the caller's own org is unreachable to a
#: module-level constant by construction: it has no client, no agent list and no
#: roster, so there is no handle to derive an org from. The handle is described
#: part by part instead. The sigil substitution that answered
#: :func:`~rine._group_ref.refuse_if_a_bare_agent_name` is not available either
#: — join genuinely needs the whole handle or the id, which is what the sentence
#: says. Only the TEXT moved: the join ladder resolves exactly as it did.
#:
#: ⚠️ :data:`JOIN_REFERENCE_RULE` below keeps its worked example and must: it is
#: a tool DESCRIPTION, which the ban exempts explicitly, and it is rendered
#: where a caller is being taught rather than corrected.
#:
#: ⚠️ Implicit concatenation only — Python folds adjacent literals into one
#: constant, which is what ``helpers_client_paths.py``'s ``py_string`` requires.
#: A ``+`` or an f-string makes it unpinnable rather than merely ugly, and the
#: TypeScript twin is under the stricter form of the same constraint.
JOIN_TAKES_A_HANDLE_OR_AN_ID = (
    "Join takes a group's whole handle — a leading hash, the group's name, an "
    "at sign, and its org's domain — or its id."
)

#: What ``join`` accepts, rendered verbatim by every surface that offers it.
#:
#: 🔴 **One sentence, not one per connector.** ``join``'s reference rules differ
#: from every other group verb's — three rungs for a handle, exactly one for a
#: bare name — so each surface had to say something the shared group-reference
#: text does not. Five hand-written copies of that is what
#: :data:`rine.vote_words.VOTE_ELECTORATE_RULE` and ``MAX_GROUP_MEMBERS`` both
#: exist to prevent, and the failure mode here is worse than drift: a surface
#: whose copy is stale advertises a spelling this ladder refuses, and the model
#: reads the refusal as the product being broken.
#:
#: Names no verb, for the reason :data:`JOIN_TAKES_A_HANDLE_OR_AN_ID` names
#: none: which tool prints a directory row is a per-surface fact, and each
#: surface's own error module already appends it.
#:
#: 🔴 Twin sentence — ``JOIN_REFERENCE_RULE`` in
#: ``rine-core/src/group-join-words.ts`` restates it byte for byte.
JOIN_REFERENCE_RULE = (
    "Join takes a group's handle or its id, and resolves either exactly: a handle "
    "answers whether your org already holds a seat, this agent holds a pending "
    "invitation, or the group is public in the directory. A bare name is read only "
    "against this agent's pending invitations, and is refused when none of them is "
    "for a group of that name — nothing wider is searched for a bare name, because "
    "a join cannot be taken back and is never aimed at a guess. Example: "
    "#logistics@acme.rine.network."
)

#: The bare-name arm, after this agent's invitations came back with no match.
#:
#: 🔴 **A bare name is looked for in ONE place and never widened.** The only rung
#: that can see a group this agent has no relationship with is a network-wide
#: ILIKE over name-or-description, and a bare name has no exactness filter to put
#: behind it — a wrong match would seat this agent in a group nobody named, and a
#: join cannot be taken back. Widening it was refused, and stays refused. The
#: invitations list is different in kind: it is bounded to groups that have
#: already asked for this agent, so a match there cannot be a group the caller
#: has no business in.
#:
#: It says what the reference WAS read as rather than that it was meaningless:
#: every group verb on every surface teaches a caller to write a bare name, and a
#: refusal that contradicts the instruction the caller just followed teaches them
#: the product is broken.
BARE_NAME_IS_ONLY_AN_INVITATION = (
    "A bare name is read as one of this agent's pending invitations, and none of them "
    "is for a group of that name. Nothing wider is searched for a bare name: a join "
    "cannot be taken back, so it is never aimed at a guess."
)

#: The bare-name arm when the invitations answer more than once.
#:
#: Two orgs may both invite this agent to a group called ``ops``, and the
#: invitations list is the one rung with no org in the reference to tell them
#: apart. Picking either would be the guess the arm above refuses; the candidates
#: are printed instead, by handle, which is the spelling that still tells two
#: same-named groups of two different orgs apart.
#:
#: Ends on a colon: the composer appends the handles, so the sentence and the
#: list cannot drift into two different orderings of the same idea.
TWO_INVITATIONS_OF_THAT_NAME = (
    "More than one of this agent's pending invitations is for a group of that name, "
    "and a join cannot be taken back, so none of them is guessed at. Name the one you "
    "mean by its whole handle:"
)

#: The handle arm, after all three rungs were searched to the end.
#:
#: Says which three places were looked in, so a caller can tell "I typed it
#: wrong" from "this group is in none of the three places a handle can be
#: resolved from" — the second is not a spelling mistake and no amount of
#: re-reading the directory will fix it.
#:
#: 🔴 It names the invitations rung as *"one this agent's pending invitations
#: name"* rather than "one this agent was invited to", and the two are not the
#: same claim: an OPEN group's invite mints no voucher and no request row
#: (``src/rine/api/groups.py``), so an agent genuinely invited to an open,
#: private-visibility group has nothing on that list. The wider sentence would be
#: false to the one caller most likely to read it.
NO_SUCH_GROUP_TO_JOIN = (
    "No group of that handle is one this org is seated in, one this agent's pending "
    "invitations name, or a public group in the directory. A group in none of those "
    "three is not reachable by handle at all, and its id is the only reference that "
    "reaches it."
)

#: The handle arm when the directory search hit its page budget.
#:
#: 🔴 **A bounded search must never report itself as an exhaustive one.** With the
#: budget spent there are matching rows this join did not look at, so "no public
#: group of that handle" is a claim the client has not earned — and the sentence
#: it would otherwise say goes further and tells the caller the group is
#: unreachable by handle, which for a public group is false and unrecoverable
#: advice.
#:
#: ``{unread}`` is replaced with the exact shortfall — ``total_estimate`` minus
#: the rows this pass read, both off the responses it already has, so stating it
#: costs no extra request. Same substitution on both stacks, which is what keeps
#: one literal pinnable against its TypeScript twin.
DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ = (
    "No group of that handle is one this org is seated in or one this agent's pending "
    "invitations name, and the public directory holds {unread} more groups matching "
    "that name than this join read — so this is not a report that the group is absent "
    "from it. The id the directory prints beside a handle reaches the group in one "
    "step."
)


def is_exact_group_handle(candidate: str | None, reference: str) -> bool:
    """Whether ``candidate`` is the very handle ``reference`` names.

    🔴 **The exactness filter the directory rung depends on.** Equality, never a
    prefix, a substring or a case fold — a group handle is ``UNIQUE`` on the
    server, so an equality test over any set of rows can return at most one
    group, and that is what makes a fuzzy candidate list safe to feed an
    irreversible verb. Loosen this and the directory rung becomes the widening
    that was refused.

    Both sides are normalised the way every other handle comparison in this SDK
    normalises: the sigil is optional (``ops@acme`` and ``#ops@acme`` name the
    same group) and a domain with no dot gets ``.rine.network`` appended, so the
    short handle a directory row is quoted by matches the full one it stores.

    ``candidate`` is optional because the rows this runs over carry it that way:
    ``JoinRequestRead.group_handle`` is enriched by the server and absent on a
    row from an older one. A row with no handle answers to nothing.
    """
    if not candidate:
        return False
    return normalize_handle(sigiled_group_ref(candidate)) == normalize_handle(
        sigiled_group_ref(reference)
    )


def is_invitation_of_that_name(
    group_handle: str | None, group_name: str | None, name: str
) -> bool:
    """Whether a pending invitation is for the group a BARE name calls.

    The two spellings an invitation row can be called by: the local part of its
    handle, which is what the wire takes, and ``group_name``, which is what the
    creator typed and what every listing prints back. On every group this server
    has minted they are the same string — ``POST /groups`` builds the handle as
    ``#{name}@{org}`` — so the second arm matches nothing the first did not,
    except on a row whose handle the server did not enrich.

    The reference is stripped of its leading ``#``\\ s before either comparison,
    because a sigiled, org-less ``#ops`` has no ``@`` and so arrives here too: it
    says which namespace the caller means and nothing more, and the name it
    carries is the same name. A whole RUN of them goes, not one —
    :func:`rine._group_ref.group_local_part` carries why, and that it is the
    spelling both stacks agreed on.

    🔴 There is no org in a bare name, so this can answer for two invitations at
    once. The caller must treat two matches as
    :data:`TWO_INVITATIONS_OF_THAT_NAME` and not as a pick.
    """
    want = group_local_part(name)
    if not want:
        return False
    if group_handle and group_local_part(group_handle) == want:
        return True
    return group_name == want


def directory_query_for_handle(handle: str) -> str:
    """The ``?q=`` that will surface ``handle``'s row in the public directory.

    The local part, because that is the column the directory actually searches —
    see :func:`rine._group_ref.group_local_part` for why the two are the same
    string. Never widened past it: a broader query cannot find more (the filter
    is a substring match either way) and would only spend the page budget on rows
    :func:`is_exact_group_handle` is going to reject.
    """
    return group_local_part(handle)


def bare_name_join_refusal(name: str) -> str:
    """Refuse a bare name no invitation of this agent's answers to."""
    return (
        f"{GROUP_NOT_FOUND_LEAD}: {name}. {BARE_NAME_IS_ONLY_AN_INVITATION} "
        f"{JOIN_TAKES_A_HANDLE_OR_AN_ID}"
    )


def ambiguous_invitation_join_refusal(name: str, handles: list[str]) -> str:
    """Refuse a bare name two of this agent's invitations both answer to."""
    return f"{GROUP_NOT_FOUND_LEAD}: {name}. {TWO_INVITATIONS_OF_THAT_NAME} {', '.join(handles)}."


def unresolved_handle_join_refusal(handle: str, unread: int = 0) -> str:
    """Refuse a handle no rung resolved, saying where it was looked for.

    ``unread`` is how many matching public directory rows the search never read —
    ``0`` when it ran to the end, which is the only case the exhaustive sentence
    is true of.
    """
    searched = (
        DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ.replace("{unread}", str(unread))
        if unread > 0
        else NO_SUCH_GROUP_TO_JOIN
    )
    return f"{GROUP_NOT_FOUND_LEAD}: {handle}. {searched} {JOIN_TAKES_A_HANDLE_OR_AN_ID}"


@dataclass
class DirectoryHandleScan:
    """The deciding half of the directory rung — what to ask, and what answered.

    🔴 **One copy of this decision, not two.** ``rine-sdk`` keeps a hand-written
    sync client and a hand-written async one, and the exactness filter that makes
    a fuzzy candidate list safe to feed an irreversible verb was written into
    both. Two copies of a load-bearing invariant is one copy that can be
    "simplified" to ``items[0]`` while every suite that covers the other stays
    green — so the clients keep the fetch (the one thing ``await`` genuinely
    changes) and this keeps the deciding. Its TypeScript twin is inline in
    ``searchPublicDirectory`` (``rine-core/src/resolve-group-join.ts``), which
    has a single copy of it already.

    Used as::

        scan = DirectoryHandleScan(handle)
        while (query := scan.next_query()) is not None:
            if scan.offer(client._directory_groups_page(**query, authenticated=True)):
                break

    and then read for :attr:`found` and :attr:`unread`.

    🔴 The fetch is the clients' AUTHENTICATED page reader, never the public
    ``discover_groups`` verb: this rung sends the org's bearer token, as its
    TypeScript twin always has. The route takes no identity, so the header
    changes nothing this class computes — but the two stacks now disclose the
    same thing on the same read, which no gate can see and this line records.
    """

    handle: str
    #: The id of the group whose handle is exactly :attr:`handle`, once a page
    #: has carried it.
    found: str | None = None
    _cursor: str | None = field(default=None, repr=False)
    _pages: int = field(default=0, repr=False)
    _read: int = field(default=0, repr=False)
    _total: int | None = field(default=None, repr=False)

    def next_query(self) -> dict[str, Any] | None:
        """The ``q``/``limit``/``cursor`` for the next page, or ``None``.

        ``None`` at the page budget, when the last page carried no cursor, and
        once the handle has been found — the three ways a bounded search ends.
        """
        if self.found is not None or self._pages >= DIRECTORY_PAGES_FOR_A_JOIN:
            return None
        if self._pages and not self._cursor:
            return None
        return {
            "q": directory_query_for_handle(self.handle),
            "limit": DIRECTORY_PAGE_LIMIT,
            "cursor": self._cursor,
        }

    def offer(self, page: Any) -> str | None:
        """Give the scan one page; answer with the id if that page carried it.

        🔴 The exactness test is here and nowhere else. ``?q=`` is a substring
        match over ``name`` and ``description``, so a page is a list of
        candidates: ``#warehouse-restock-archive`` and every group whose
        description merely mentions the phrase come back beside the one that was
        named.
        """
        self._pages += 1
        self._read += len(page.items)
        if isinstance(getattr(page, "total", None), int):
            self._total = page.total
        self._cursor = page.next_cursor
        for row in page.items:
            if is_exact_group_handle(row.handle, self.handle):
                self.found = str(row.id)
                return self.found
        return None

    @property
    def unread(self) -> int:
        """Matching directory rows this scan never looked at.

        ``0`` when the search ran to the end — and ``0`` again when the server
        sent no total to subtract from, because a shortfall invented out of a
        missing field is worse than none. Read by
        :func:`unresolved_handle_join_refusal`, which is the only reason the
        number is carried at all.
        """
        if self._total is None:
            return 0
        return max(0, self._total - self._read)


__all__ = [
    "BARE_NAME_IS_ONLY_AN_INVITATION",
    "DIRECTORY_HELD_MORE_THAN_THIS_JOIN_READ",
    "DIRECTORY_PAGES_FOR_A_JOIN",
    "DIRECTORY_PAGE_LIMIT",
    "JOIN_REFERENCE_RULE",
    "JOIN_TAKES_A_HANDLE_OR_AN_ID",
    "NO_SUCH_GROUP_TO_JOIN",
    "TWO_INVITATIONS_OF_THAT_NAME",
    "DirectoryHandleScan",
    "ambiguous_invitation_join_refusal",
    "bare_name_join_refusal",
    "directory_query_for_handle",
    "is_exact_group_handle",
    "is_invitation_of_that_name",
    "unresolved_handle_join_refusal",
]
