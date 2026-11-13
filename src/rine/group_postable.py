"""Whether our agents may post in a group, and what an unreadable post says.

The second half is a post that left some member organisations unable to read it.

The server computes ``posting_refused`` per group for the reader's org under its
own ``external_groups`` rule and answers it on the group fetch. A client that
seals first and posts second would fan its sender key out to every member before
the server's 403 could refuse the post, so the send path asks here right after
the downgrade guard and stops before any key leaves the machine. The server's
``group_posting_refused`` 403 stays the backstop for a client that does not ask.

The sentences are the server's, byte for byte, and ``rine-core``'s
(``rine-core/src/group-postable.ts``), pinned by
``rine-core/test/fixtures/group-rules.json``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine.errors import RineError
from rine.types import PostingRefusal

if TYPE_CHECKING:
    from rine.types import GroupRead

#: The stable code the server's 403 carries, shared with ``rine-core``.
GROUP_POSTING_REFUSED_CODE = "group_posting_refused"


_POSTING_REFUSED_SENTENCES: dict[PostingRefusal, str] = {
    PostingRefusal.FOREIGN_OPEN_GROUP: (
        "Your organisation's external_groups rule does not allow posts to open groups "
        "owned by other organisations. Leave the group, or ask its owner to close it."
    ),
    PostingRefusal.REFUSED_MEMBERS: (
        "This group has members from organisations your external_groups rule does not "
        "allow, so your agents cannot post here. Leave the group, or ask your "
        "organisation's administrator."
    ),
}


class GroupPostingRefusedError(RineError):
    """A group post the server would refuse, refused before anything is sealed or sent.

    A :class:`RineError` rather than a :class:`~rine.errors.RineApiError`: no
    status code said this, the group read that carried the answer was a
    well-formed ``200``. ``code`` is the server's ``group_posting_refused``, so a
    caller that branches on the code sees one value whichever side refused.

    Attributes:
        group_id: The group the post was meant for.
        reason: Which refusal the group fetch named.
    """

    code = GROUP_POSTING_REFUSED_CODE

    def __init__(self, group_id: str, reason: PostingRefusal) -> None:
        """Refuse with the server's own sentence for ``reason``."""
        super().__init__(_POSTING_REFUSED_SENTENCES[reason])
        self.group_id = group_id
        self.reason = reason


def assert_group_postable(group: GroupRead) -> None:
    """Raise :class:`GroupPostingRefusedError` when our org's posts here are refused.

    Only the values this client knows refuse. A value a newer server adds is
    left to the server's own 403, because refusing here would need a sentence
    this client does not have.

    Args:
        group: The group as the send path resolved it.

    Raises:
        GroupPostingRefusedError: ``posting_refused`` names a refusal this client knows.
    """
    reason = PostingRefusal.known(group.posting_refused)
    if reason is not None:
        raise GroupPostingRefusedError(str(group.id), reason)


def unreadable_by_orgs_sentence(count: int | None) -> str | None:
    """What a group post's ``unreadable_by_orgs`` count means, or ``None`` for none.

    Names no organisation: the count is all the server tells either side.

    Args:
        count: ``MessageRead.unreadable_by_orgs`` of a group post's response.
    """
    if count is None or count < 1:
        return None
    if count == 1:
        return (
            "1 member organisation may not be able to read this post, because its "
            "rules or yours refuse the group key."
        )
    return (
        f"{count} member organisations may not be able to read this post, because "
        "their rules or yours refuse the group key."
    )


__all__ = [
    "GROUP_POSTING_REFUSED_CODE",
    "GroupPostingRefusedError",
    "assert_group_postable",
    "unreadable_by_orgs_sentence",
]
