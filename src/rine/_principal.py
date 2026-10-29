"""The four kinds of principal a token request can name.

A closed enum and a small value type, so no caller compares a principal against
a bare string: ``str(principal)`` is the wire spelling, :func:`parse_principal`
is its inverse, and the kind is always read off the enum.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from rine._crypto.derive import BRANCH_NAME_RE, UUID_RE
from rine.errors import ConfigError


class PrincipalKind(StrEnum):
    """What a principal string's prefix says it is."""

    ORG = "org"
    BRANCH = "branch"
    AGENT = "agent"
    READER = "reader"


@dataclass(frozen=True, slots=True)
class Principal:
    """One principal: the org, a branch, an agent, or a reader of the org or a branch.

    ``ident`` is the org id for every kind but ``AGENT``, where it is the agent id.
    ``branch`` names the branch for ``BRANCH`` and for a branch reader, and is
    ``None`` for the org reader.
    """

    kind: PrincipalKind
    ident: str
    branch: str | None = None

    def __str__(self) -> str:
        """The wire spelling: ``org:<id>``, ``branch:<org>:<name>``, ``agent:<id>``, ..."""
        parts = [self.kind.value, self.ident]
        if self.branch is not None:
            parts.append(self.branch)
        return ":".join(parts)


def org_principal(org_id: str) -> Principal:
    """The org itself."""
    return Principal(PrincipalKind.ORG, org_id)


def branch_principal(org_id: str, name: str) -> Principal:
    """One named branch of an org."""
    return Principal(PrincipalKind.BRANCH, org_id, name)


def agent_principal(agent_id: str) -> Principal:
    """One agent, acting as itself."""
    return Principal(PrincipalKind.AGENT, agent_id)


def reader_principal(org_id: str, name: str | None = None) -> Principal:
    """The org reader, or the reader of one branch when ``name`` is given."""
    return Principal(PrincipalKind.READER, org_id, name)


def _invalid() -> ConfigError:
    return ConfigError("invalid principal")


def _uuid(text: str | None) -> str:
    if text is None or not UUID_RE.fullmatch(text):
        raise _invalid()
    return text


def _branch_name(text: str | None) -> str:
    if text is None or not BRANCH_NAME_RE.fullmatch(text):
        raise _invalid()
    return text


def parse_principal(text: str) -> Principal:
    """Read a principal string back into a :class:`Principal`.

    Raises:
        ConfigError: The text is any other shape.
    """
    kind_text, _, rest = text.partition(":")
    first, _, second = rest.partition(":")
    try:
        kind = PrincipalKind(kind_text)
    except ValueError:
        raise _invalid() from None
    if kind in (PrincipalKind.ORG, PrincipalKind.AGENT):
        if second or ":" in rest:
            raise _invalid()
        return Principal(kind, _uuid(first))
    if kind is PrincipalKind.BRANCH:
        return Principal(kind, _uuid(first), _branch_name(second or None))
    return Principal(kind, _uuid(first), _branch_name(second) if second else None)
