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
from rine._mls.binding import (
    DEFAULT_CIPHER_SUITE,
    MlsGroup,
    UnreadableKeyPackageError,
    open_mls_client,
)
from rine._mls.commit import post_mls_commit
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_report import EscrowReport
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
    escrow: EscrowReport = field(default_factory=EscrowReport)
    """The merged report of every batch's escrow drain."""

    outcomes: list[MlsAdmissionOutcome] = field(default_factory=list)

    order: list[str] = field(default_factory=list)
    """The requested ids, lower-cased, in the order the caller named them.

    Outcomes are recorded as they happen — every skip the caller decided before
    the loop ran, then each batch — which is not the order anyone asked in. The
    report promises one outcome per requested id **in request order**, so the
    order is kept here and applied once, at the end.
    """

    @property
    def actor(self) -> MlsActor:
        """The agent this admission acts as, and the client it acts through."""
        return MlsActor(client=self.client, config_dir=self.config_dir, agent_id=self.agent_id)

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
            escrow=self.escrow,
        )


def commit_batch(admission: Admission, joiners: list[str], key_packages: list[bytes]) -> None:
    """Build one commit, publish it, and only then persist the local advance."""
    install_batch(admission, publish_batch(admission, joiners, key_packages))


def publish_batch(admission: Admission, joiners: list[str], key_packages: list[bytes]) -> MlsGroup:
    """Build one commit and post it; the group it advanced is returned, not yet installed.

    A failure here is the server refusing the batch (or never receiving it), so
    nothing local has changed. :func:`install_batch` is the other half: an error
    there comes after the server seated the joiners, which is not a refusal.
    """
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

    actor = admission.actor
    admission.epoch = post_mls_commit(
        actor,
        admission.group_id,
        MlsCommit(
            commit=bundle.commit,
            group_info=bundle.group_info,
            epoch=bundle.epoch,
            cipher_suite=DEFAULT_CIPHER_SUITE,
            welcomes=tuple(
                MlsWelcome(agent_id=a, welcome=w)
                for a, w in zip(joiners, bundle.welcomes, strict=True)
            ),
        ),
        admission.extra_headers,
    )
    return group


def install_batch(admission: Admission, group: MlsGroup) -> None:
    """Persist the advance of a commit the server accepted, escrow first."""
    actor = admission.actor
    # Only now: a commit the server refused must leave no local state, so the
    # retry starts from the same place this attempt did.
    admission.escrow = admission.escrow.advance(
        drain_escrow(actor, admission.group_id, group, carry_unreported=True).report()
    )
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
        )
        if admission.saved
        else None
    )


__all__ = ["Admission", "commit_batch", "discard_uncommitted"]
