"""The group-substitution guard, driven against the real ``rine-mls`` core.

The adversary here is the server itself, and it is played by a second real MLS
client: it founds its own group under the victim's rine group UUID, seals a real
Welcome to the victim's own published KeyPackage, and serves it from ``GET
/agents/{id}/mls/welcomes`` — exactly the shape of the attack, with real crypto
on both sides. Only the HTTP surface is mocked.

The two tests that matter most are the two directions: a substituted Welcome must
be refused, and an honest one must still install. A guard that refuses an honest
Welcome is worse for every honest user than the attack it prevents. The sharpest
case of the second direction is the removed-then-re-invited member, who holds
live local state and whose new Welcome is the only way back in.

The TypeScript twin is ``rine-core/test/mls-welcome-guard.test.ts``, test for
test.
"""

from __future__ import annotations

import base64
import os

import httpx
import pytest
import respx

from rine._crypto.keys import generate_agent_keys, save_agent_keys, signing_public_key_to_jwk
from rine._mls import (
    DEFAULT_CIPHER_SUITE,
    load_mls_group,
    mls_group_id_bytes,
    open_mls_client,
    process_mls_welcomes,
)
from rine._mls.join import join_mls_state
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcome_spool import WelcomeSpool

API = "https://rine.network"
GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OTHER_GROUP_ID = "cccccccc-dddd-eeee-ffff-000000000000"
FOUNDER_ID = "11111111-2222-3333-4444-555555555555"
OTHER_FOUNDER_ID = "22222222-3333-4444-5555-666666666666"
IMPOSTOR_ID = "99999999-8888-7777-6666-555555555555"

_GROUP_PAYLOAD = {
    "id": GROUP_ID,
    "name": "test-group",
    "handle": "#test-group@myorg.rine.network",
    "enrollment_policy": "closed",
    "visibility": "private",
    "created_at": "2024-01-01T00:00:00Z",
    "mls_enabled": True,
    "mls_group_id": "99999999-0000-1111-2222-333333333333",
    "mls_pending": False,
    "mls_cipher_suite": DEFAULT_CIPHER_SUITE,
}


def _peer_client(tmp_path, agent: str):
    """This peer's MLS client, minting its keys once and reopening them after.

    Reopening matters: a peer whose keys were regenerated has a different MLS
    identity, and the guard under test compares identities for a living.
    """
    peer_dir = str(tmp_path / f"peer-{agent}")
    if not os.path.isdir(peer_dir):
        save_agent_keys(peer_dir, agent, generate_agent_keys())
    return open_mls_client(peer_dir, agent)


def _honest_welcome(
    tmp_config_dir, agent_id, tmp_path, group_id=GROUP_ID, founder_id=FOUNDER_ID
) -> bytes:
    """A founder seats the victim in ``group_id`` and hands over its Welcome."""
    founder = _peer_client(tmp_path, founder_id)
    victim = open_mls_client(tmp_config_dir, agent_id)
    group = founder.create_group_with_members(
        mls_group_id_bytes(group_id), [victim.generate_key_package()]
    )
    group.save()
    bundle = group.last_commit()
    assert bundle is not None
    return bundle.welcomes[0]


def _substituted_welcome(tmp_config_dir, agent_id, tmp_path, group_id=GROUP_ID) -> bytes:
    """The server founds its OWN group under ``group_id`` and seals a Welcome."""
    impostor = _peer_client(tmp_path, IMPOSTOR_ID)
    victim = open_mls_client(tmp_config_dir, agent_id)
    group = impostor.create_group_with_members(
        mls_group_id_bytes(group_id), [victim.generate_key_package()]
    )
    group.save()
    bundle = group.last_commit()
    assert bundle is not None
    return bundle.welcomes[0]


def _mock_server(
    agent_id: str,
    deliveries: list[tuple[str, bytes]],
    *,
    roster: dict[str, list[str]] | None = None,
    identities: dict[str, bytes] | None = None,
    roster_readable: bool = True,
) -> None:
    """The welcome fetch, the roster reads and the key map a join makes."""
    respx.post(f"{API}/oauth/token").mock(
        return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
    )
    respx.get(f"{API}/agents/{agent_id}/mls/welcomes").mock(
        return_value=httpx.Response(
            200,
            json={
                "welcomes": [
                    {
                        "id": f"welcome-{index}",
                        "group_id": group_id,
                        "blob": base64.b64encode(blob).decode(),
                    }
                    for index, (group_id, blob) in enumerate(deliveries)
                ]
            },
        )
    )
    respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(200, json={"stored": 1})
    )
    respx.get(f"{API}/agents/{agent_id}/mls/key-packages").mock(
        return_value=httpx.Response(200, json={"available": 20})
    )
    status = 200 if roster_readable else 403
    for group_id, members in (roster or {}).items():
        respx.get(f"{API}/groups/{group_id}").mock(
            return_value=httpx.Response(200, json={**_GROUP_PAYLOAD, "id": group_id})
        )
        respx.get(f"{API}/groups/{group_id}/members").mock(
            return_value=httpx.Response(
                status,
                json=(
                    {"items": [{"agent_id": m} for m in members]}
                    if roster_readable
                    else {"detail": "Membership required"}
                ),
            )
        )
        respx.get(f"{API}/groups/{group_id}/requests").mock(
            return_value=httpx.Response(status, json={"items": []})
        )

    def _keys(request: httpx.Request) -> httpx.Response:
        wanted = (request.url.params.get("ids") or "").split(",")
        return httpx.Response(
            200,
            json={
                "keys": {
                    agent: {"signing_public_key": signing_public_key_to_jwk(identity)}
                    for agent, identity in (identities or {}).items()
                    if agent in wanted
                }
            },
        )

    respx.get(f"{API}/agents/keys").mock(side_effect=_keys)


def _reinvitation_welcome(tmp_config_dir, agent_id, tmp_path) -> bytes:
    """The founder evicts the victim with a real Remove commit, then re-invites it.

    This is the flow the guard used to wedge: the victim still holds live state
    for the group, and this second Welcome is the only way back into it.
    """
    founder = _peer_client(tmp_path, FOUNDER_ID)
    group = founder.load_group(mls_group_id_bytes(GROUP_ID))
    victim = open_mls_client(tmp_config_dir, agent_id)
    group.remove_member(group.member_index(victim.public_key()))
    group.save()
    bundle = group.add_member(victim.generate_key_package())
    group.save()
    return bundle.welcomes[0]


def _held(tmp_config_dir, agent_id, group_id=GROUP_ID):
    return load_mls_group(open_mls_client(tmp_config_dir, agent_id), group_id)


def _spooled(tmp_config_dir, agent_id) -> int:
    return len(WelcomeSpool(tmp_config_dir, agent_id).pending())


def _founder_identity(tmp_path, founder_id=FOUNDER_ID) -> bytes:
    return _peer_client(tmp_path, founder_id).public_key()


class TestProcessMlsWelcomes:
    @staticmethod
    def _install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path, group_id=GROUP_ID):
        """Seat the victim honestly, so a later Welcome has state to contend with."""
        _mock_server(
            agent_id,
            [(group_id, _honest_welcome(tmp_config_dir, agent_id, tmp_path, group_id))],
            roster={group_id: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )
        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    @respx.mock
    def test_install_when_a_member_of_the_named_group_minted_it_then_state_is_held(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        welcome = _honest_welcome(tmp_config_dir, agent_id, tmp_path)
        _mock_server(
            agent_id,
            [(GROUP_ID, welcome)],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert _held(tmp_config_dir, agent_id) is not None

    @respx.mock
    def test_install_when_the_roster_names_nobody_in_the_tree_then_it_is_refused(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # The rine roster is honest and names a founder and the victim. The tree
        # this Welcome seats the victim in holds the server's own identity
        # instead, so nothing in it corroborates the roster.
        welcome = _substituted_welcome(tmp_config_dir, agent_id, tmp_path)
        _mock_server(
            agent_id,
            [(GROUP_ID, welcome)],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert excinfo.value.reason == "roster_uncorroborated"
        assert _held(tmp_config_dir, agent_id) is None

    @respx.mock
    def test_install_when_state_is_held_and_the_roster_contradicts_it_then_it_is_refused(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        self._install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path)
        epoch = _held(tmp_config_dir, agent_id).epoch()
        respx.clear()
        _mock_server(
            agent_id,
            [(GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path))],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert excinfo.value.reason == "roster_uncorroborated"
        # The state that was already there is what a substitution destroys, so
        # the assertion is on the state and not merely on the refusal.
        held = _held(tmp_config_dir, agent_id)
        assert held.epoch() == epoch
        assert len(held.member_identities()) == 2

    @respx.mock
    def test_install_when_state_is_held_and_the_roster_cannot_be_read_then_it_is_refused(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # The same unreadable roster that ACCEPTS for an agent holding nothing
        # REFUSES here: with state to lose, corroboration has to be positive.
        self._install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path)
        epoch = _held(tmp_config_dir, agent_id).epoch()
        respx.clear()
        _mock_server(
            agent_id,
            [(GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path))],
            roster={GROUP_ID: []},
            roster_readable=False,
        )

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert excinfo.value.reason == "state_would_be_overwritten"
        assert _held(tmp_config_dir, agent_id).epoch() == epoch

    @respx.mock
    def test_install_when_a_removed_member_is_re_invited_then_the_new_welcome_installs(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # The case the guard used to wedge permanently. The victim holds live
        # state — and holds it as ACTIVE, because eviction is not persisted, so
        # a reloaded handle says nothing useful about whether its leaf survives.
        # The roster is what settles it, and here the roster corroborates.
        self._install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path)
        first_epoch = _held(tmp_config_dir, agent_id).epoch()
        welcome = _reinvitation_welcome(tmp_config_dir, agent_id, tmp_path)
        respx.clear()
        _mock_server(
            agent_id,
            [(GROUP_ID, welcome)],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        # The new state really replaced the old: the epoch moved and the victim
        # can read the group again.
        held = _held(tmp_config_dir, agent_id)
        assert held.epoch() > first_epoch
        assert len(held.member_identities()) == 2
        assert _spooled(tmp_config_dir, agent_id) == 0

    @respx.mock
    def test_install_when_a_refusal_can_clear_then_the_welcome_is_kept_and_retried(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # A refused Welcome that is dropped is dropped forever: the fetch marks
        # it consumed, so no second read and no peer can produce it again. The
        # first attempt refuses with an unreadable roster; the second, once the
        # invitation is accepted and the roster answers, installs the SAME bytes.
        # An honest re-invitation arriving while the roster read is down: state
        # is held, so it refuses — and this is exactly the Welcome that must
        # survive the refusal.
        self._install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path)
        first_epoch = _held(tmp_config_dir, agent_id).epoch()
        welcome = _reinvitation_welcome(tmp_config_dir, agent_id, tmp_path)
        respx.clear()
        _mock_server(agent_id, [(GROUP_ID, welcome)], roster={GROUP_ID: []}, roster_readable=False)

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
        assert excinfo.value.reason == "state_would_be_overwritten"
        assert _spooled(tmp_config_dir, agent_id) == 1

        # Second pass: the fetch is empty (the server already handed the bytes
        # over), the roster now answers, and the spooled copy is what installs.
        respx.clear()
        _mock_server(
            agent_id,
            [],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)
        assert _held(tmp_config_dir, agent_id).epoch() > first_epoch
        assert _spooled(tmp_config_dir, agent_id) == 0

    @respx.mock
    def test_install_when_a_retained_refusal_is_retried_then_it_does_not_raise_again(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # A retained refusal must not fail every later call. It was reported
        # once, when its bytes arrived; after that it is a quiet retry, or one
        # unusable Welcome would break every future join on this agent.
        self._install_first_welcome(sync_client, tmp_config_dir, agent_id, tmp_path)
        respx.clear()
        _mock_server(
            agent_id,
            [(GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path))],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )
        with pytest.raises(MlsWelcomeRefusedError):
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        respx.clear()
        _mock_server(
            agent_id,
            [],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == ()
        assert _spooled(tmp_config_dir, agent_id) == 1

    @respx.mock
    def test_install_when_the_welcome_joins_another_group_then_it_is_discarded(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        welcome = _honest_welcome(tmp_config_dir, agent_id, tmp_path)
        _mock_server(
            agent_id,
            [(OTHER_GROUP_ID, welcome)],
            roster={OTHER_GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert excinfo.value.reason == "group_id_mismatch"
        # Deterministic, so it is the one refusal that keeps nothing: the
        # welcome joins a group it was not filed under, on every attempt.
        assert _spooled(tmp_config_dir, agent_id) == 0


class TestInstallMlsStateScopesTheRefusal:
    """A refusal names ONE group, and only that group's install may abort.

    ``install_mls_state`` runs the whole Welcome batch before it does anything
    else, so without the scoping a refusal for group X would abort a perfectly
    legitimate install of group Y — and on the SDK's own ``groups.join()`` the
    surrounding ``except Exception`` would then swallow the refusal entirely.
    Python must throw where TypeScript throws.
    """

    @staticmethod
    def _batch(sync_client, tmp_config_dir, agent_id, tmp_path):
        """One refused Welcome for GROUP_ID, one honest one for OTHER_GROUP_ID."""
        _mock_server(
            agent_id,
            [
                (GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path)),
                (
                    OTHER_GROUP_ID,
                    _honest_welcome(
                        tmp_config_dir, agent_id, tmp_path, OTHER_GROUP_ID, OTHER_FOUNDER_ID
                    ),
                ),
            ],
            roster={
                GROUP_ID: [FOUNDER_ID, agent_id],
                OTHER_GROUP_ID: [OTHER_FOUNDER_ID, agent_id],
            },
            identities={
                FOUNDER_ID: _founder_identity(tmp_path),
                OTHER_FOUNDER_ID: _founder_identity(tmp_path, OTHER_FOUNDER_ID),
            },
        )

    @respx.mock
    def test_install_when_the_refusal_names_this_group_then_it_propagates(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        self._batch(sync_client, tmp_config_dir, agent_id, tmp_path)

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            join_mls_state(sync_client, GROUP_ID, agent_id)

        assert excinfo.value.group_id == GROUP_ID

    @respx.mock
    def test_install_when_the_refusal_names_another_group_then_this_one_installs(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        self._batch(sync_client, tmp_config_dir, agent_id, tmp_path)

        join_mls_state(sync_client, OTHER_GROUP_ID, agent_id)

        assert _held(tmp_config_dir, agent_id, OTHER_GROUP_ID) is not None

    @respx.mock
    def test_install_when_a_batch_carries_a_refusal_then_the_honest_one_lands(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # The fetch is destructive, so a refusal that abandoned the batch would
        # lose every Welcome behind it — permanently, since no peer can mint
        # another without noticing the first went unused.
        _mock_server(
            agent_id,
            [
                (GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path)),
                (
                    OTHER_GROUP_ID,
                    _honest_welcome(
                        tmp_config_dir, agent_id, tmp_path, OTHER_GROUP_ID, OTHER_FOUNDER_ID
                    ),
                ),
            ],
            roster={
                GROUP_ID: [FOUNDER_ID, agent_id],
                OTHER_GROUP_ID: [OTHER_FOUNDER_ID, agent_id],
            },
            identities={
                FOUNDER_ID: _founder_identity(tmp_path),
                OTHER_FOUNDER_ID: _founder_identity(tmp_path, OTHER_FOUNDER_ID),
            },
        )

        with pytest.raises(MlsWelcomeRefusedError):
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert _held(tmp_config_dir, agent_id, OTHER_GROUP_ID) is not None

    @respx.mock
    def test_install_when_two_welcomes_are_refused_then_this_group_is_still_raised(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # MEASURED before the fix: a batch with two refusals raised only
        # ``refusals[0]``, and ``install_mls_state`` downgraded a non-match to a
        # log line — so ``groups.join()`` returned a normal JoinedResult for a
        # group whose Welcome had just been refused as a substitution, and then
        # fell through to the external-join fallback for it. The SERVER picked
        # which refusal survived, because the queue was ordered by the delivery
        # ids the server chose.
        _mock_server(
            agent_id,
            [
                (GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path)),
                (
                    OTHER_GROUP_ID,
                    _substituted_welcome(tmp_config_dir, agent_id, tmp_path, OTHER_GROUP_ID),
                ),
            ],
            roster={
                GROUP_ID: [FOUNDER_ID, agent_id],
                OTHER_GROUP_ID: [OTHER_FOUNDER_ID, agent_id],
            },
            identities={
                FOUNDER_ID: _founder_identity(tmp_path),
                OTHER_FOUNDER_ID: _founder_identity(tmp_path, OTHER_FOUNDER_ID),
            },
        )

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            join_mls_state(sync_client, OTHER_GROUP_ID, agent_id)

        assert excinfo.value.group_id == OTHER_GROUP_ID
        assert _held(tmp_config_dir, agent_id, OTHER_GROUP_ID) is None

    @respx.mock
    def test_install_when_a_retained_refusal_names_this_group_then_it_is_raised_again(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # Quiet on a pass that is not about this group — that is what keeps one
        # unusable Welcome from failing every future call. Loud for a caller
        # establishing this very group: it asked, and a refusal is the answer.
        _mock_server(
            agent_id,
            [(GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path))],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )
        with pytest.raises(MlsWelcomeRefusedError):
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        # The fetch is empty from here on — the server already handed the bytes
        # over — so everything below is about the RETAINED copy.
        respx.clear()
        _mock_server(
            agent_id,
            [],
            roster={GROUP_ID: [FOUNDER_ID, agent_id]},
            identities={FOUNDER_ID: _founder_identity(tmp_path)},
        )
        assert process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id).group_ids == ()

        with pytest.raises(MlsWelcomeRefusedError) as excinfo:
            process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id, for_group=GROUP_ID)

        assert excinfo.value.group_id == GROUP_ID

    @respx.mock
    def test_install_when_the_roster_cannot_be_read_then_it_still_installs(
        self, sync_client, tmp_config_dir, agent_id, tmp_path
    ):
        # An agent that has been invited and has not accepted yet reads 403 from
        # every group-scoped route, so an unreadable roster has to accept. This
        # is the residual: a server that refuses the roster read defeats the
        # corroboration check, which is why no surface may call the attack
        # closed.
        _mock_server(
            agent_id,
            [(GROUP_ID, _substituted_welcome(tmp_config_dir, agent_id, tmp_path))],
            roster={GROUP_ID: []},
            roster_readable=False,
        )

        outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

        assert outcome.group_ids == (GROUP_ID,)


class TestTheRefusalIsCatchableByType:
    """Recognising a refusal without matching its message is the point of it.

    The TypeScript twin exports ``MlsWelcomeRefusedError`` from
    ``@rine-network/core``; this side had it reachable only through the private
    ``rine._mls`` package, so a consumer could catch nothing narrower than
    :class:`~rine.errors.CryptoError`. An asymmetry there is a defect a user
    only ever meets on the closed stack.
    """

    def test_the_refusal_class_is_public_at_the_package_root(self):
        import rine

        assert rine.MlsWelcomeRefusedError is MlsWelcomeRefusedError
        assert "MlsWelcomeRefusedError" in rine.__all__
        assert "WELCOME_REFUSED_CODE" in rine.__all__
        assert "WelcomeRefusalReason" in rine.__all__

    def test_the_public_class_is_the_one_the_guard_raises(self):
        from rine import MlsWelcomeRefusedError as Public
        from rine.errors import CryptoError

        refusal = Public(GROUP_ID, "roster_uncorroborated", "detail")

        # One class, three import paths, so `except` works wherever it is
        # written — and still a CryptoError, so every path that already refuses
        # unreadable content keeps refusing this.
        assert isinstance(refusal, MlsWelcomeRefusedError)
        assert isinstance(refusal, CryptoError)
        assert refusal.code == "RINE_WELCOME_REFUSED"
        assert refusal.reason == "roster_uncorroborated"
