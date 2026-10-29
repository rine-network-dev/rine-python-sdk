"""The roster read that decides whether a spooled Welcome is opened at all.

Before a Welcome is opened, the pass reads the group's roster
(``GET /groups/{id}/members``, then ``/requests``) and classifies the answer: a
403 keeps the bytes unopened (an invitation not yet accepted), a 404 drops them
(the group is gone), and anything else is transient and keeps them for a later
pass.

A Welcome set aside unopened still holds the private half of the KeyPackage it
was sealed to, so the local mirror reads a full pool while the server may hold
none. Only the server's own count can see that, and only a pass that set
something aside pays for asking: it reads
``GET /agents/{id}/mls/key-packages/count`` and publishes the shortfall against
``KEY_PACKAGE_TARGET``. A healthy pass makes no extra request at all.

A Welcome dropped without being opened (the group is gone, the Welcome is unusable or
finally refused, or it aged out of the spool) releases the private half it was sealed to, so
the local pool count stays honest; an installed or retained Welcome never does.

The TypeScript twin is ``rine-core/test/mls-welcome-admission.test.ts``.
"""

from __future__ import annotations

import base64
import json
import os

import httpx
import pytest
import respx

from rine._mls import load_mls_group, open_mls_client, process_mls_welcomes
from rine._mls import welcomes as welcomes_module
from rine._mls.api import MlsWelcomeDelivery
from rine._mls.binding import KEY_PACKAGE_LOW_WATER, KEY_PACKAGE_TARGET
from rine._mls.key_packages import ensure_mls_key_packages
from rine._mls.welcome_guard import MlsWelcomeRefusedError
from rine._mls.welcome_spool import WelcomeSpool, welcome_spool_dir
from rine.testing import WORLD
from tests.mls_peers import (
    FOUNDER_ID,
    GROUP_ID,
    foreign_suite_welcome,
    honest_welcome,
    refused_flags,
)

pytestmark = pytest.mark.usefixtures("real_roster_read")

API = "https://rine.network"


def _serve(
    agent_id: str,
    deliveries: list[tuple[str, bytes]],
    *,
    members_response: httpx.Response | Exception,
    held: int | None = 0,
):
    """The welcome fetch, the roster reads, the key map and the pool routes.

    ``members_response`` is what ``GET /groups/{id}/members`` answers — a
    response, or an exception instance for a network failure. ``held`` is what the
    count route reports, or ``None`` for a server that has no such route. Returns the count
    route and the upload route so a test can read their call counts and bodies.
    """
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
    if isinstance(members_response, Exception):
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(side_effect=members_response)
    else:
        respx.get(f"{API}/groups/{GROUP_ID}/members").mock(return_value=members_response)
    respx.get(f"{API}/groups/{GROUP_ID}/requests").mock(
        return_value=httpx.Response(200, json={"items": []})
    )
    count_response = (
        httpx.Response(404, json={"detail": "Not Found"})
        if held is None
        else httpx.Response(200, json={"available": held})
    )
    count = respx.get(f"{API}/agents/{agent_id}/mls/key-packages/count").mock(
        return_value=count_response
    )

    def _store(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(200, json={"stored": len(body["packages"])})

    upload = respx.post(f"{API}/agents/{agent_id}/mls/key-packages").mock(side_effect=_store)

    def _keys(request: httpx.Request) -> httpx.Response:
        wanted = (request.url.params.get("ids") or "").split(",")
        return httpx.Response(
            200,
            json={"keys": {agent: WORLD.keys_response(agent) for agent in wanted if agent}},
        )

    respx.get(f"{API}/agents/keys").mock(side_effect=_keys)
    return count, upload


def _members(*agent_ids: str) -> httpx.Response:
    return httpx.Response(200, json={"items": [{"agent_id": a} for a in agent_ids]})


def _fill_local_pool(tmp_config_dir, agent_id) -> None:
    """Give the victim a full local mirror, so the forced heartbeat publishes nothing."""
    open_mls_client(tmp_config_dir, agent_id).generate_key_packages(KEY_PACKAGE_TARGET)


def _uploaded(route) -> int:
    """How many key packages the upload route was handed, across every call."""
    return sum(len(json.loads(call.request.content)["packages"]) for call in route.calls)


def _held(tmp_config_dir, agent_id, group_id=GROUP_ID):
    return load_mls_group(open_mls_client(tmp_config_dir, agent_id), group_id)


def _spooled(tmp_config_dir, agent_id) -> int:
    return len(WelcomeSpool(tmp_config_dir, agent_id).pending())


@respx.mock
def test_welcome_pass_when_roster_answers_403_then_kept_unopened_and_shortfall_published(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """An unaccepted invitation keeps its Welcome unopened; the server's gap is published."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
        held=0,
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert _spooled(tmp_config_dir, agent_id) == 1
    assert _held(tmp_config_dir, agent_id) is None
    assert outcome.discarded == 0
    assert count.call_count == 1
    assert _uploaded(upload) == KEY_PACKAGE_TARGET


@respx.mock
def test_welcome_pass_when_server_holds_some_then_only_the_gap_is_published(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """The top-up publishes only what the server's own count is short of."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
        held=4,
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert count.call_count == 1
    assert _uploaded(upload) == KEY_PACKAGE_TARGET - 4


@respx.mock
def test_welcome_pass_when_roster_answers_404_then_dropped_and_shortfall_published(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """A gone group's Welcome is dropped; the server's gap is published."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(404, json={"detail": "No such group"}),
        held=0,
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert _spooled(tmp_config_dir, agent_id) == 0
    assert _held(tmp_config_dir, agent_id) is None
    assert outcome.discarded == 1
    assert count.call_count == 1
    assert _uploaded(upload) == KEY_PACKAGE_TARGET


@pytest.mark.parametrize(
    "members_response",
    [
        httpx.Response(503, json={"detail": "Service unavailable"}),
        httpx.ConnectError("boom"),
    ],
)
@respx.mock
def test_welcome_pass_when_roster_read_fails_transiently_then_kept_and_nothing_published(
    sync_client, tmp_config_dir, agent_id, tmp_path, members_response
):
    """A transient roster failure keeps the Welcome and asks the server nothing more."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id, [(GROUP_ID, welcome)], members_response=members_response, held=0
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert outcome.discarded == 0
    assert _spooled(tmp_config_dir, agent_id) == 1
    assert _held(tmp_config_dir, agent_id) is None
    assert count.call_count == 0
    assert upload.call_count == 0


@respx.mock
def test_welcome_pass_when_roster_readable_then_installed_without_a_count_read(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """A healthy pass installs and makes no count request."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=_members(FOUNDER_ID, agent_id),
        held=0,
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert outcome.group_ids == (GROUP_ID,)
    assert count.call_count == 0
    assert upload.call_count == 0


@respx.mock
def test_welcome_pass_when_roster_answers_403_then_the_kept_welcome_is_flagged_refused(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """A kept invitation sits under the spool's refused bound, not outside it."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert refused_flags(tmp_config_dir, agent_id) == [True]


@respx.mock
def test_welcome_pass_when_an_invitation_is_kept_then_the_next_pass_reads_the_count_again(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """The kept Welcome is why the pool is short, so every pass that holds it looks."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    refused = httpx.Response(403, json={"detail": "Membership required"})
    count, upload = _serve(agent_id, [(GROUP_ID, welcome)], members_response=refused, held=0)
    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
    uploaded_first = _uploaded(upload)

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert count.call_count == 2
    assert uploaded_first == KEY_PACKAGE_TARGET
    assert _spooled(tmp_config_dir, agent_id) == 1


@respx.mock
def test_welcome_pass_when_the_server_will_not_say_what_it_holds_then_nothing_is_published(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """No count is no known shortfall: the welcome pass guesses nothing."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    count, upload = _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
        held=None,
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert count.call_count == 1
    assert upload.call_count == 0
    assert _spooled(tmp_config_dir, agent_id) == 1


@respx.mock
def test_welcome_pass_when_the_agent_is_seated_later_then_the_kept_welcome_installs(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """Accepting an invitation later needs the very bytes the first pass kept."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
    )
    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
    respx.get(f"{API}/groups/{GROUP_ID}/members").mock(return_value=_members(FOUNDER_ID, agent_id))

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert outcome.group_ids == (GROUP_ID,)
    assert _held(tmp_config_dir, agent_id) is not None
    assert _spooled(tmp_config_dir, agent_id) == 0


@pytest.fixture
def released(monkeypatch) -> list[bytes]:
    """Every blob the pass hands its releaser; the releaser itself is replaced."""
    blobs: list[bytes] = []
    monkeypatch.setattr(welcomes_module, "welcome_releaser", lambda _client: blobs.append)
    return blobs


@respx.mock
def test_welcome_pass_when_roster_answers_404_then_the_welcome_is_released(
    sync_client, tmp_config_dir, agent_id, tmp_path, released
):
    """A gone group's Welcome is dropped, and so is the half it was sealed to."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(404, json={"detail": "No such group"}),
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert released == [welcome]


@respx.mock
def test_welcome_pass_when_roster_answers_404_then_the_local_pool_count_falls_by_one(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """The native core really lets go of the half: nothing is mocked but the network."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _fill_local_pool(tmp_config_dir, agent_id)
    before = open_mls_client(tmp_config_dir, agent_id).key_package_count()
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(404, json={"detail": "No such group"}),
        held=None,
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert open_mls_client(tmp_config_dir, agent_id).key_package_count() == before - 1


@respx.mock
def test_welcome_pass_when_the_welcome_is_unusable_then_it_is_released(
    sync_client, tmp_config_dir, agent_id, released
):
    """A Welcome that cannot be joined will never use its half either."""
    blob = b"\x00\x01not a welcome"
    _serve(
        agent_id,
        [(GROUP_ID, blob)],
        members_response=_members(FOUNDER_ID, agent_id),
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert outcome.discarded == 1
    assert released == [blob]


@respx.mock
def test_welcome_pass_when_the_welcome_is_for_another_suite_then_it_is_dropped_and_the_pass_ends(
    sync_client, tmp_config_dir, agent_id
):
    """The real releaser meets the core's ciphersuite refusal and does not wedge the pass."""
    _serve(
        agent_id,
        [(GROUP_ID, foreign_suite_welcome())],
        members_response=_members(FOUNDER_ID, agent_id),
    )

    first = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)
    second = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert (first.discarded, second.discarded) == (1, 1)
    assert _spooled(tmp_config_dir, agent_id) == 0


@respx.mock
def test_welcome_pass_when_the_welcome_is_installed_then_nothing_is_released(
    sync_client, tmp_config_dir, agent_id, tmp_path, released
):
    """The install consumed the half already."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=_members(FOUNDER_ID, agent_id),
    )

    outcome = process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert outcome.group_ids == (GROUP_ID,)
    assert released == []


@respx.mock
def test_welcome_pass_when_an_invitation_is_kept_then_nothing_is_released(
    sync_client, tmp_config_dir, agent_id, tmp_path, released
):
    """A retained Welcome keeps its half: accepting later opens it."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    _serve(
        agent_id,
        [(GROUP_ID, welcome)],
        members_response=httpx.Response(403, json={"detail": "Membership required"}),
    )

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert released == []


@respx.mock
def test_welcome_pass_when_the_welcome_is_refused_for_good_then_it_is_released(
    sync_client, tmp_config_dir, agent_id, tmp_path, released
):
    """A Welcome delivered under the wrong group is dropped, and its half with it."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    other_group = "cccccccc-dddd-eeee-ffff-000000000000"
    _serve(agent_id, [(other_group, welcome)], members_response=_members(FOUNDER_ID, agent_id))
    respx.get(f"{API}/groups/{other_group}/members").mock(
        return_value=_members(FOUNDER_ID, agent_id)
    )
    respx.get(f"{API}/groups/{other_group}/requests").mock(
        return_value=httpx.Response(200, json={"items": []})
    )

    with pytest.raises(MlsWelcomeRefusedError):
        process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    assert released == [welcome]


@respx.mock
def test_welcome_pass_when_a_retained_welcome_ages_out_then_the_pool_publishes_again(
    sync_client, tmp_config_dir, agent_id, tmp_path
):
    """The aged-out half stops counting, so the ordinary top-up sees the shortage."""
    welcome = honest_welcome(tmp_config_dir, agent_id, tmp_path)
    open_mls_client(tmp_config_dir, agent_id).generate_key_packages(KEY_PACKAGE_LOW_WATER - 1)
    _count, upload = _serve(agent_id, [], members_response=httpx.Response(403), held=0)
    assert ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id).published == 0
    spool = WelcomeSpool(tmp_config_dir, agent_id)
    spool.store(MlsWelcomeDelivery(id="aged", group_id=GROUP_ID, welcome=welcome))
    path = os.path.join(welcome_spool_dir(tmp_config_dir, agent_id), "aged.json")
    spool.mark_refused(path)
    os.utime(path, (1.0, 1.0))

    process_mls_welcomes(sync_client._http, tmp_config_dir, agent_id)

    status = ensure_mls_key_packages(sync_client._http, tmp_config_dir, agent_id)
    assert status.published == KEY_PACKAGE_TARGET - (KEY_PACKAGE_LOW_WATER - 1)
    assert _uploaded(upload) == status.published
