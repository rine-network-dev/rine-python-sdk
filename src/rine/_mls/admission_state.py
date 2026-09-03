"""An admission's state: what it carries, what it publishes, what it undoes.

Publishing one commit and undoing one the server refused.

The two halves of local MLS state that the loop must never get wrong. A commit
is built in memory, published, and only **then** saved — so a refused commit
leaves nothing behind for the retry to build on, and the retry rebuilds from the
last state the server actually accepted.

Split from :mod:`rine._mls.admission_loop` so the loop reads as the loop: what
each batch does, in order, without the store handling in the middle of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rine._mls.admission import (
    MlsAdmissionOutcome,
    MlsAdmissionResult,
    MlsAdmissionSkipReason,
)
from rine._mls.api import MlsCommit, MlsWelcome
from rine._mls.binding import MlsGroup, UnreadableKeyPackageError, open_mls_client
from rine._mls.commit import post_mls_commit
from rine._mls.group_access import (
    mls_group_id_bytes,
    note_mls_state_changed,
    open_mls_group,
)
from rine._mls.heartbeat import MlsActor
from rine.errors import CryptoError

_UNREADABLE_KEY_PACKAGE = (
    "A member's published MLS KeyPackage cannot be read by this MLS core "
    "({named}). They are running an older rine release: MLS groups need every "
    "participant on the current one. Ask them to upgrade and republish their "
    "KeyPackages, then try again."
)


@dataclass
class Admission:
    """Everything the loop needs, and the state it carries between batches."""

    client: Any
    config_dir: str
    agent_id: str
    group_id: str
    extra_headers: dict[str, str]
    cipher_suite: int | None = None

    group: MlsGroup | None = None
    """``None`` until the founding commit creates it; the group thereafter."""

    saved: bool = False
    """Whether the local store holds state for this group to reload from.

    It is what tells a retry where to rebuild from: a founding has saved
    nothing before its first accepted commit, so the retry re-founds rather
    than reopening a store that holds no state for this group yet. An add path
    sets it at the start, because its state is already on disk.
    """

    epoch: int = 0
    commits: int = 0
    outcomes: list[MlsAdmissionOutcome] = field(default_factory=list)

    order: list[str] = field(default_factory=list)
    """The requested ids, lower-cased, in the order the caller named them.

    Outcomes are recorded as they happen — every skip the caller decided before
    the loop ran, then each batch — which is not the order anyone asked in. The
    report promises one outcome per requested id **in request order**, so the
    order is kept here and applied once, at the end.
    """

    def skip(self, agent_id: str, reason: MlsAdmissionSkipReason) -> None:
        """Record a requested agent that did not get a leaf, and why."""
        self.outcomes.append(
            MlsAdmissionOutcome(agent_id=agent_id, status="skipped", reason=reason)
        )

    def result(self) -> MlsAdmissionResult:
        """What this admission achieved, for the caller."""
        rank = {agent_id: i for i, agent_id in enumerate(self.order)}
        ordered = sorted(self.outcomes, key=lambda o: rank.get(o.agent_id.lower(), len(rank)))
        return MlsAdmissionResult(
            epoch=self.epoch,
            commits=self.commits,
            added=sum(1 for o in ordered if o.status == "added"),
            outcomes=tuple(ordered),
        )


def commit_batch(admission: Admission, joiners: list[str], key_packages: list[bytes]) -> None:
    """Build one commit, publish it, and only then persist the local advance."""
    group = admission.group
    try:
        if group is None:
            group = open_mls_client(
                admission.config_dir, admission.agent_id
            ).create_group_with_members(mls_group_id_bytes(admission.group_id), key_packages)
            bundle = group.last_commit()
            if bundle is None:  # pragma: no cover - a fresh group carries its commit
                raise CryptoError("MLS group was founded without an init commit")
        else:
            bundle = group.add_members(key_packages)
    except UnreadableKeyPackageError as exc:
        raise CryptoError(_UNREADABLE_KEY_PACKAGE.format(named=", ".join(joiners))) from exc

    admission.epoch = post_mls_commit(
        MlsActor(
            client=admission.client,
            config_dir=admission.config_dir,
            agent_id=admission.agent_id,
        ),
        admission.group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=group.cipher_suite(),
            welcomes=tuple(
                MlsWelcome(agent_id=a, welcome=w)
                for a, w in zip(joiners, bundle.welcomes, strict=True)
            ),
        ),
        admission.extra_headers,
    )
    # Only now: a commit the server refused must leave no local state, so the
    # retry starts from the same place this attempt did.
    group.save()
    admission.group = group
    admission.saved = True
    admission.commits += 1
    # Admission is an establishment: invalidate here, at the mutation, so a
    # "this agent holds no MLS state" answer taken before it cannot survive it.
    note_mls_state_changed(admission.config_dir, admission.agent_id, admission.group_id)


def discard_uncommitted(admission: Admission) -> None:
    """Throw away the in-memory commit the server refused.

    The refused commit advanced the local handle and was never saved, so the
    retry builds from the last *accepted* state — reloaded from disk, or from
    nothing at all when this admission has not landed one yet.
    """
    admission.group = (
        open_mls_group(
            admission.config_dir,
            admission.agent_id,
            admission.group_id,
            cipher_suite=admission.cipher_suite,
        )
        if admission.saved
        else None
    )


__all__ = ["Admission", "commit_batch", "discard_uncommitted"]
