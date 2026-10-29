"""The rescue's bound: how many private halves a LOOP of syncs may mint.

The twin of ``rine-core/test/mls-keypackage-topup.test.ts``, and it asks the same
question on the stack that is MORE exposed to it. A ``python script.py`` that
opens a client, syncs and exits is the ordinary shape for this SDK, where the
TypeScript one is usually embedded in a long-lived host — so the process-local
floor that used to be the only brake was worth even less here.

``test_group_sync_topup_contract.py`` is the other half of this subject and stays
the other half: its question is whether the top-up runs at all, and where in the
recovery it runs. This file's question is what it costs when it runs again, and
again — and it drives :func:`~rine._mls.topup.top_up_key_packages` directly,
because the defect is inside the top-up and nothing about the ladder changes it.

🔴 **Why the process boundary is the whole test.** ``rine group sync`` is a
one-shot process, so the module-level rescue gate is fresh on every invocation,
and a suite that loops inside one process measures the gate rather than the
bound. :func:`reset_mls_heartbeat_gate` between iterations IS the simulated
process exit, and it is the only thing here standing in for real life. Every
other participant is real: a real native core opening a real store under a real
temp dir, and ``key_package_count()`` read off the disk it wrote.

The harm the bound is for is not disk. The core's shortfall is 0 at or above the
low-water mark, so after *k* unbounded rescues the local mirror reads ``C + 10k``
and low-water replenishment cannot fire again until ``C + 10k - 2`` Welcomes have
been processed. Each loop pushes the heartbeat's automatic maintenance path ten
Welcomes further out of reach, monotonically and permanently — so "the count
stopped growing" is the assertion that matters, not "the uploads stopped".

Lives in ``tests/contract/`` because that is the directory ``ci.sh`` runs for
this package (stage ``[4/8] rine-sdk contract``): ``rine-sdk/tests/`` at large is
gated only by the publish train.
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from rine._mls import KEY_PACKAGE_TARGET, open_mls_client, reset_mls_heartbeat_gate
from rine._mls.heartbeat import MlsActor
from rine._mls.topup import top_up_key_packages

API = "https://rine.network"
COUNT_PATH = "/mls/key-packages/count"


@pytest.fixture(autouse=True)
def _fresh_rescue_gate():
    """Per process by design, so a test must not inherit the last one's rescue."""
    reset_mls_heartbeat_gate()
    yield
    reset_mls_heartbeat_gate()


class FakeServer:
    """A stand-in server that HOLDS a pool, rather than a stub answering a number.

    The bound is arithmetic against what the server holds, so a fixture whose
    count does not move when an upload lands cannot tell a bounded rescue from an
    unbounded one: both would read the same number forever.
    """

    def __init__(self, agent_id: str, available: int = 0) -> None:
        """Start holding *available* unconsumed packages for *agent_id*."""
        self.available = available
        self.agent_id = agent_id
        self.batches: list[int] = []
        self.count_reads = 0
        self.serves_count_route = True
        self.count_body: dict[str, object] = {}

    def install(self) -> None:
        """Route the token, the upload and the count read at this fake."""
        respx.post(f"{API}/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        respx.post(f"{API}/agents/{self.agent_id}/mls/key-packages").mock(side_effect=self._upload)
        respx.get(f"{API}/agents/{self.agent_id}{COUNT_PATH}").mock(side_effect=self._count)

    def _upload(self, request: httpx.Request) -> httpx.Response:
        stored = len(json.loads(request.content)["packages"])
        self.batches.append(stored)
        self.available += stored
        return httpx.Response(201, json={"stored": stored})

    def _count(self, _request: httpx.Request) -> httpx.Response:
        self.count_reads += 1
        if not self.serves_count_route:
            return httpx.Response(404, json={"detail": "Not Found"})
        body = self.count_body or {"available": self.available}
        return httpx.Response(200, json=body)

    def drained_by_peers(self) -> None:
        """Peers claimed the whole published pool; the private halves stay on disk."""
        self.available = 0


def _actor(sync_client, tmp_config_dir, agent_id) -> MlsActor:
    return MlsActor(client=sync_client._http, config_dir=tmp_config_dir, agent_id=agent_id)


def _local_halves(tmp_config_dir: str, agent_id: str) -> int:
    """Private halves this agent is holding on disk, read from the real store."""
    return open_mls_client(tmp_config_dir, agent_id).key_package_count()


class TestTheRescueIsBoundedByTheServerCount:
    @respx.mock
    def test_when_syncs_loop_across_processes_then_one_pool_is_minted(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The shape the defect lives in: six ``rine group sync`` invocations, each
        # its own process, each starting with a fresh module-level gate. Before
        # the server count they cost ten private halves apiece, forever.
        server = FakeServer(agent_id)
        server.install()
        actor = _actor(sync_client, tmp_config_dir, agent_id)

        outcomes = []
        for _ in range(6):
            reset_mls_heartbeat_gate()  # the process boundary, the only fake here
            outcomes.append(top_up_key_packages(actor))

        # One upload, and it is the low-water replenishment of an empty pool.
        assert server.batches == [KEY_PACKAGE_TARGET]
        assert outcomes[0].outcome == "topped-up"
        assert [o.outcome for o in outcomes[1:]] == ["healthy"] * 5
        # The assertion the harm is stated in: the mirror stopped growing, so the
        # low-water heartbeat is still one Welcome away from firing, not fifty.
        assert _local_halves(tmp_config_dir, agent_id) == KEY_PACKAGE_TARGET

    @respx.mock
    def test_when_the_mirror_reads_full_then_the_server_is_asked(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # Named rather than implied. A fix that computes the bound from anything
        # local passes every count assertion above by accident on a fixture whose
        # pool happens to be full, and this is the one thing that cannot.
        server = FakeServer(agent_id, available=KEY_PACKAGE_TARGET)
        server.install()
        open_mls_client(tmp_config_dir, agent_id).replenish_key_packages()

        result = top_up_key_packages(_actor(sync_client, tmp_config_dir, agent_id))

        assert server.count_reads == 1
        assert server.batches == []
        assert result.outcome == "healthy"

    @respx.mock
    def test_when_the_mirror_is_full_and_the_server_is_empty_then_it_rescues_once(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The wedged agent, exactly, and the reason a local ceiling was rejected:
        # its mirror reads ten while the server holds none, because every peer
        # claimed a package to mint a Welcome that never arrived. It is un-addable
        # and only the server can say so.
        server = FakeServer(agent_id)
        server.install()
        actor = _actor(sync_client, tmp_config_dir, agent_id)
        top_up_key_packages(actor)  # first sync fills both
        server.drained_by_peers()

        reset_mls_heartbeat_gate()
        rescued = top_up_key_packages(actor)
        reset_mls_heartbeat_gate()
        after = top_up_key_packages(actor)

        assert rescued.outcome == "topped-up"
        assert rescued.published == KEY_PACKAGE_TARGET
        # And then it STOPS — which is the whole residual. The old code rescued
        # this agent again on every invocation for as long as the loop ran.
        assert after.outcome == "healthy"
        assert _local_halves(tmp_config_dir, agent_id) == 2 * KEY_PACKAGE_TARGET

    @respx.mock
    def test_when_the_server_holds_some_then_only_the_shortfall_is_minted(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # Three, not ten. The server holding seven is the ordinary case after a
        # few peers have added this agent to groups.
        server = FakeServer(agent_id, available=KEY_PACKAGE_TARGET - 3)
        server.install()
        open_mls_client(tmp_config_dir, agent_id).replenish_key_packages()

        result = top_up_key_packages(_actor(sync_client, tmp_config_dir, agent_id))

        assert server.batches == [3]
        assert result.outcome == "topped-up"
        assert result.published == 3


class TestAServerThatWillNotSayWhatItHolds:
    """🔴 Every server deployed when this shipped is in this state.

    The count route is a server change, and the release order deploys it before
    the clients are published. These tests are what makes the client publishable
    against the server that is running right now.
    """

    def _mirror_at_target(self, tmp_config_dir, agent_id, server: FakeServer) -> None:
        open_mls_client(tmp_config_dir, agent_id).replenish_key_packages()
        server.batches.clear()

    @respx.mock
    def test_when_the_route_is_absent_then_a_full_batch_still_goes_up(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The first wrong reading of a missing answer: treat it as a zero
        # SHORTFALL. The rescue would then be a no-op against the whole installed
        # base, and the agent it exists for — seated by a vote, holding no
        # claimable key package — would stay un-addable while the sync reported
        # success.
        server = FakeServer(agent_id)
        server.install()
        self._mirror_at_target(tmp_config_dir, agent_id, server)
        server.serves_count_route = False

        result = top_up_key_packages(_actor(sync_client, tmp_config_dir, agent_id))

        assert server.batches == [KEY_PACKAGE_TARGET]
        assert result.outcome == "topped-up"

    @respx.mock
    def test_when_the_route_is_absent_then_the_per_process_floor_still_holds(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # The second wrong reading: treat the missing answer as a zero POOL. The
        # arithmetic then says "mint a full batch" on every single call, with
        # nothing in front of it — the unbounded loop, restored by the fix meant
        # to close it. The floor is what the fallback must route through.
        server = FakeServer(agent_id)
        server.install()
        self._mirror_at_target(tmp_config_dir, agent_id, server)
        server.serves_count_route = False
        actor = _actor(sync_client, tmp_config_dir, agent_id)

        outcomes = [top_up_key_packages(actor) for _ in range(3)]

        assert server.batches == [KEY_PACKAGE_TARGET]
        assert [o.outcome for o in outcomes] == ["topped-up", "healthy", "healthy"]

    @respx.mock
    def test_when_the_answer_carries_no_count_then_it_is_no_answer_at_all(
        self, sync_client, tmp_config_dir, agent_id
    ):
        # A 200 is not an answer either. A body without the field reaches the
        # arithmetic as ``None``, and ``TARGET - None`` is a TypeError inside a
        # function that promises to raise nothing — so it would surface as a
        # ``failed`` top-up rather than as the rescue the operator asked for.
        server = FakeServer(agent_id)
        server.install()
        self._mirror_at_target(tmp_config_dir, agent_id, server)
        server.count_body = {"stored": 0}

        result = top_up_key_packages(_actor(sync_client, tmp_config_dir, agent_id))

        assert server.batches == [KEY_PACKAGE_TARGET]
        assert result.outcome == "topped-up"
