"""Which refusal a Welcome pass raises, out of the ones it earned."""

from __future__ import annotations

from dataclasses import dataclass

from rine._mls.welcome_guard import MlsWelcomeRefusedError


@dataclass(frozen=True)
class PassRefusal:
    """One refusal a pass earned, and whether its bytes arrived in that pass."""

    refusal: MlsWelcomeRefusedError
    is_new: bool


def pick_refusal(
    refusals: list[PassRefusal], for_group: str | None
) -> MlsWelcomeRefusedError | None:
    """Which refusal a pass raises, out of the ones it earned.

    🔴 Never ``refusals[0]``. The queue used to be ordered by file name, which is
    the server-chosen delivery id, so a server that wanted a refusal suppressed
    minted a decoy that sorted first and the caller's own group's refusal became
    a log line — measured, not hypothetical.

    ``for_group`` answers about exactly that group and nothing else, in both
    directions. Its refusal is raised whether or not the bytes arrived in this
    pass — the caller asked about that group, and a refusal is the answer to the
    question. Every other group's refusal is withheld from this caller, because
    a substituted Welcome for one group must not fail a legitimate install, send
    or read of another. Both halves live here rather than at the caller: leaving
    the second one to the caller is precisely how the TypeScript read path ended
    up aborting unrelated decrypts while this one did not.

    With no ``for_group`` the pass answers about the whole queue and the arrival
    rule decides: reported once, when its bytes arrive, then quiet, because a
    retained refusal that raised on every later pass would let one unusable
    Welcome fail every future join, send and read. ``peer_not_admitted`` is the
    exception: it names a member's own seat, so only a call scoped to the group
    hears it, and an unscoped pass logs it and counts the discarded Welcome.

    Nothing withheld here is lost. A withheld refusal keeps its Welcome on the
    spool (:func:`~rine._mls.welcome_guard.refusal_is_retryable`) and is raised
    by the first call scoped to its own group — which is the call that needed to
    hear it. On this stack it is also logged once, on the pass its bytes arrive
    in; the TypeScript twin cannot, because rine-core has no logging facility.
    """
    if for_group is not None:
        wanted = for_group.lower()
        return next((e.refusal for e in refusals if e.refusal.group_id.lower() == wanted), None)
    return next(
        (e.refusal for e in refusals if e.is_new and e.refusal.reason != "peer_not_admitted"),
        None,
    )
