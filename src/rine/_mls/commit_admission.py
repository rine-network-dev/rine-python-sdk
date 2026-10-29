"""Admitting the peer a commit names, when the core refuses it only for being new.

A member that missed commits meets leaves it has never seen: the peers those
commits added, who are in neither the roster nor the allowed set any more if they
were removed again before it caught up. The core refuses such a leaf with
``PeerNotAdmittedError`` and records which agent it was. This module reads that
agent, puts it through the same chain verification as every other peer, and
retries the same input.

Nothing enters the allowed set here except through
:func:`rine._mls.allowed.admit_peers`: the refused id is a candidate for
verification, never a reason to trust a leaf. A refusal that verification cannot
change — an agent that does not verify, or a leaf whose key differs from the
verified one — is final and reaches the caller as the native refusal: the second
refusal of an agent is the bound, whether or not the verification inserted
anything (an agent whose keys live on this device inserts nothing and is retried
all the same).

Sync, resync and reseat read a tree or a commit another member built, so a leaf in it
can be refused for real. The removal and orphan commit builds are wrapped the same
way, but a core refuses a commit build only over the committer's own leaf, so there
the retry is a guard that no honest setup reaches.

The id is authenticated on a commit (the core checks the sender's signature before it
looks at a leaf), but not on a Welcome: tree validation runs before any signature, so
anyone who can encrypt to one of this agent's key packages can name any agent. The
Welcome open therefore passes a ``limit``, which caps the work a single input can cost.

The TypeScript twin is ``admitRefusedPeers`` (``rine-core/src/mls-commit-admission.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeVar

from rine._crypto.derive import canonical_uuid
from rine._mls.allowed import admit_peers
from rine._mls.binding import PeerNotAdmittedError
from rine.errors import CryptoError

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._mls.actor import MlsActor

_T = TypeVar("_T")


class RefusalSource(Protocol):
    """A client or group handle that records the agent its last call refused."""

    def refused_peer(self) -> bytes | None:
        """The credential identity the last call on this handle refused, if any."""
        ...


def admit_refused_peers(
    actor: MlsActor,
    source: RefusalSource,
    attempt: Callable[[], _T],
    limit: int | None = None,
) -> _T:
    """Run ``attempt``, verifying each peer the core refuses and retrying the same call.

    Each pass either returns, raises, or verifies an agent not yet verified in this
    call, and a refused agent is always a leaf the input carries — so the attempts
    are bounded by the distinct agents the input names, plus one.

    Args:
        actor: Who is acting, and through which client.
        source: The handle ``attempt`` calls on; read right after a refusal.
        attempt: The core call. It must leave its handle unchanged when refused.
        limit: The most verifications one call performs; the refusal after that many
            is final too, so an input naming more agents is unusable rather than a
            bill of unbounded reads. ``None`` leaves it unbounded.

    Returns:
        Whatever ``attempt`` returns once the core accepts the input.

    Raises:
        PeerNotAdmittedError: When the refused agent is unnamed, is refused again
            after being verified in this call, or would be the verification past
            ``limit``.
        Exception: Anything else ``attempt`` raises, and any failure of the
            verification reads (a transport failure is not a refusal).
    """
    verified: set[str] = set()
    while True:
        try:
            return attempt()
        except PeerNotAdmittedError:
            agent_id = refused_agent(source)
            if agent_id is None or agent_id in verified or len(verified) == limit:
                raise
            verified.add(agent_id)
            admit_peers(actor, [agent_id])


def agent_id_of_identity(raw: bytes) -> str | None:
    """The canonical agent id a credential identity spells, or ``None`` when it spells none."""
    try:
        return canonical_uuid(raw.decode("ascii"), "agent id")
    except (UnicodeDecodeError, CryptoError):
        return None


def refused_agent(source: RefusalSource) -> str | None:
    """The refused agent's canonical id, or ``None`` when it is absent or malformed."""
    raw = source.refused_peer()
    return None if raw is None else agent_id_of_identity(raw)


__all__ = ["RefusalSource", "admit_refused_peers", "agent_id_of_identity", "refused_agent"]
