"""A revoked agent or branch ends every pending escrow's hope, however the server says so."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from rine._mls.escrow_answer import EscrowCode
from rine._mls.escrow_drain import drain_escrow
from rine._mls.escrow_gap import EscrowLoss
from rine._mls.escrow_keys import cached_escrow_key
from rine._mls.escrow_markers import read_gap
from rine._mls.escrow_report import EscrowDeferral
from rine._mls.escrow_revoked import revoked_loss
from rine._mls.escrow_settle import settle_escrow
from rine._mls.escrow_snapshots import list_snapshots
from rine._mls.escrow_sweep import reset_escrow_sweep_gate, sweep_pending_escrow
from rine._principal import branch_principal, org_principal
from rine.errors import PrincipalRevokedError, RevokedScope, RineApiError, revoked_code
from tests.test_mls_escrow_drain import AGENT, GROUP, WORLD, _fresh_group
from tests.test_mls_escrow_sweep import (
    NO_FORK_FP,
    STRAY,
    STRAY_FP,
    _deferred_group,
    _stray,
    _uploaded_groups,
    marked_fork_gap,
)
from tests.test_mls_escrow_sweep import _cold_state as _cold_state  # the autouse fixture
from tests.test_mls_escrow_sweep import actor as actor  # the fixture

if TYPE_CHECKING:
    from rine._mls.heartbeat import MlsActor
    from rine._principal import Principal

REVOCATIONS = [
    (RevokedScope.AGENT, EscrowLoss.AGENT_REVOKED, EscrowDeferral.AGENT_REVOKED),
    (RevokedScope.BRANCH, EscrowLoss.BRANCH_REVOKED, EscrowDeferral.BRANCH_REVOKED),
]


@pytest.mark.parametrize(("scope", "loss", "_deferral"), REVOCATIONS)
def test_sweep_when_the_key_read_names_a_revoked_principal_then_the_file_is_given_up(
    actor: MlsActor, scope: RevokedScope, loss: EscrowLoss, _deferral: EscrowDeferral
) -> None:
    """Retrying cannot help: the loss is recorded and the file goes, with no upload tried."""
    actor.client.escrow_error = PrincipalRevokedError(scope)

    outcome = sweep_pending_escrow(actor)

    assert outcome is not None
    assert _stray(actor) == []
    assert _uploaded_groups(actor) == []
    assert [(g.epoch, g.reason) for g in outcome.report().gaps] == [(3, loss)]
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, STRAY_FP) is loss


@pytest.mark.parametrize(("scope", "loss", "_deferral"), REVOCATIONS)
def test_sweep_when_the_key_read_names_a_revoked_principal_then_parked_state_is_given_up(
    actor: MlsActor, scope: RevokedScope, loss: EscrowLoss, _deferral: EscrowDeferral
) -> None:
    """A parked snapshot is deleted with a marker for its epochs, under the same loss."""
    _deferred_group(actor)
    settle_escrow(actor, GROUP)
    assert len(list_snapshots(actor.config_dir, AGENT)) == 1
    actor.client.escrow_error = PrincipalRevokedError(scope)

    sweep_pending_escrow(actor)

    assert list_snapshots(actor.config_dir, AGENT) == []
    assert marked_fork_gap(actor, GROUP, 0) is loss


@pytest.mark.parametrize(("scope", "loss", "_deferral"), REVOCATIONS)
def test_sweep_when_an_upload_names_a_revoked_principal_then_the_file_is_given_up(
    actor: MlsActor, scope: RevokedScope, loss: EscrowLoss, _deferral: EscrowDeferral
) -> None:
    """A 401 on the upload carries no escrow code, and is still final."""
    actor.client.put_error = PrincipalRevokedError(scope)

    sweep_pending_escrow(actor)
    reset_escrow_sweep_gate()
    sweep_pending_escrow(actor)

    assert _stray(actor) == []
    assert _uploaded_groups(actor) == [STRAY]
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, STRAY_FP) is loss


def test_sweep_when_an_upload_names_a_revoked_branch_then_the_cached_key_is_dropped(
    actor: MlsActor,
) -> None:
    """A revoked branch ends trust in the cached escrow key, as its 422 answer does."""
    actor.client.put_error = PrincipalRevokedError(RevokedScope.BRANCH)

    sweep_pending_escrow(actor)

    assert cached_escrow_key(actor) is None


@pytest.mark.parametrize(("scope", "_loss", "deferral"), REVOCATIONS)
def test_drain_escrow_when_the_key_read_names_a_revoked_principal_then_it_defers_with_the_scope(
    actor: MlsActor, scope: RevokedScope, _loss: EscrowLoss, deferral: EscrowDeferral
) -> None:
    """The exports stay queued for the sweep to give up; the drain never discards them."""
    actor.client.escrow_error = PrincipalRevokedError(scope)

    outcome = drain_escrow(actor, GROUP, _fresh_group(actor))

    assert isinstance(outcome.deferred, PrincipalRevokedError)
    assert outcome.report().deferral is deferral
    assert outcome.backlog is not None
    assert outcome.backlog.queued >= 1


@pytest.mark.parametrize(
    "principal", [org_principal(WORLD.org_id), branch_principal(WORLD.org_id, "main")]
)
@pytest.mark.parametrize("scope", list(RevokedScope))
def test_sweep_when_a_branch_or_org_bearer_is_revoked_then_this_agents_files_wait(
    actor: MlsActor, principal: Principal, scope: RevokedScope
) -> None:
    """A 401 names the bearer, not this agent: nothing is deleted and no loss is recorded."""
    actor.client.principal = principal
    actor.client.escrow_error = PrincipalRevokedError(scope)

    outcome = sweep_pending_escrow(actor)

    assert outcome is None
    assert len(_stray(actor)) == 1
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, NO_FORK_FP) is None


def test_sweep_when_an_upload_names_another_principal_revoked_then_the_file_stays(
    actor: MlsActor,
) -> None:
    """The same holds on the upload path: the pass backs off and keeps the file and its budget."""
    actor.client.principal = org_principal(WORLD.org_id)
    actor.client.put_error = PrincipalRevokedError(RevokedScope.BRANCH)

    sweep_pending_escrow(actor)

    assert len(_stray(actor)) == 1
    assert read_gap(actor.config_dir, AGENT, STRAY, 3, NO_FORK_FP) is None


@pytest.mark.parametrize(
    ("status", "code", "loss"),
    [
        (422, EscrowCode.AGENT_REVOKED, EscrowLoss.AGENT_REVOKED),
        (422, EscrowCode.BRANCH_REVOKED, EscrowLoss.BRANCH_REVOKED),
        (500, EscrowCode.BRANCH_REVOKED, None),
        (502, EscrowCode.AGENT_REVOKED, None),
        (403, EscrowCode.BRANCH_REVOKED, None),
    ],
)
def test_revoked_loss_when_a_code_arrives_then_only_its_own_status_is_a_loss(
    status: int, code: EscrowCode, loss: EscrowLoss | None
) -> None:
    """A revoked code on a status the server does not give it is an ordinary refusal."""
    exc = RineApiError(status, "refused", json.dumps({"error": code.value}))

    assert revoked_loss(exc) is loss


@pytest.mark.parametrize(
    ("scope", "code"),
    [
        (RevokedScope.AGENT, EscrowCode.AGENT_REVOKED),
        (RevokedScope.BRANCH, EscrowCode.BRANCH_REVOKED),
    ],
)
def test_revoked_code_when_a_scope_is_named_then_the_escrow_layer_spells_it_the_same(
    scope: RevokedScope, code: EscrowCode
) -> None:
    """The escrow codes and the token and bearer codes are one wire spelling, not two."""
    assert revoked_code(scope) == code.value
