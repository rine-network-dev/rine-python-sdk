"""A **drained** key-package pool, Python side, through to a real decrypt.

The twin of ``rine-core/test/mls-vote-decrypt.test.ts``. Both stacks share the same
hole and both carry this gate: a heartbeat that shipped on one stack alone would
leave the other's agents un-addable while every suite read green.

This is the shape the fix shipped and the one no other suite reaches. Peers claim one
of an agent's published key packages per add, and every claim they turn into a
Welcome consumes the matching private half locally — so an agent that only ever
gets added, and never publishes again, ends at zero on BOTH sides. At zero it is
**un-addable**: no member can mint it a Welcome, so a carried vote seats it on the
roster with no leaf in the ratchet tree, and it reads nothing the group says. Zero
is absorbing precisely because the repairs are conditioned on events that can no
longer happen to it.

The chain each test drives, end to end, against the REAL ``rine-mls`` core::

    drained to 0/0 -> a peer's admission is refused (no_key_package)
                   -> the agent's own next operation beats and refills
                   -> the peer's admission now mints a real Welcome
                   -> the welcomed member DECRYPTS REAL CIPHERTEXT

Only the server is mocked, and it is mocked **statefully**: the pool is a queue
:class:`_Server` pops from, so "drained" is representable at all and a claim
against an empty pool answers the way the server does — an empty ``packages``
array, not an error. Every KeyPackage, Welcome, commit and ciphertext is genuine.

🔴 The drain installs its Welcomes through ``open_mls_client(...).join_from_welcome``
rather than through :func:`rine._mls.process_mls_welcomes`, and that is not a
shortcut around the unit under test — it is the only way to BUILD the
precondition. Every product path that consumes a private half now publishes a
replacement, which is the fix; driving the drain through the product would refill
the pool as fast as it emptied it and the wedged state would be unreachable. So
the install is fixture construction, standing in for the shipped build that
created these agents, and the assertions start where it ends.

Deliberately NOT covered here: a LOCAL mirror that still reads full while the
server holds none (an upload that failed after the private halves were minted
over-counts). The beat cannot see that and is not what rescues it — the additive
top-up is, and that arm is gated with the top-up.

No fixture, no golden value: the drain runs until the pool is empty and the
refilled count is compared against ``KEY_PACKAGE_TARGET``, so a policy change
moves this file's expectations with it.

Lives in ``tests/contract/`` because that is the directory ``ci.sh`` runs for this
package (stage ``[4/8] rine-sdk contract``); ``rine-sdk/tests/`` at large is gated
only by the publish train.
"""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import httpx
import pytest
import respx

from rine._actor import AGENT_HEADER
from rine._crypto.keys import save_agent_keys
from rine._mls import (
    KEY_PACKAGE_TARGET,
    add_mls_group_members,
    decrypt_mls_group_message,
    encrypt_mls_group_message,
    init_mls_group,
    mls_from_base64,
    open_mls_client,
    process_mls_welcomes,
    publish_mls_key_packages,
    reset_mls_heartbeat_gate,
    sync_mls_group,
)
from rine.testing import WORLD
from rine.types import GroupRead

pytestmark = pytest.mark.usefixtures("mls_escrow_stub")

API = "https://rine.network"
HOST = "rine.network"


@pytest.fixture(autouse=True)
def _fresh_gate():
    """The floor is per process, so a test must not inherit the last one's stamp."""
    reset_mls_heartbeat_gate()
    yield
    reset_mls_heartbeat_gate()


class _Server:
    """The MLS routes, holding the state that makes a pool drainable.

    Agent ids are minted per instance rather than fixed: the SDK caches published
    signing keys per agent id for the life of the process, so two tests reusing an
    id would verify the second's envelope against the first's key.
    """

    def __init__(self, config_dir: str) -> None:
        self.config_dir = config_dir
        #: The admitter: founds groups and carries the vote.
        self.admin = str(uuid4())
        #: The agent whose pool is drained to zero.
        self.bob = str(uuid4())
        #: The healthy peer, seated wherever Bob is dropped.
        self.carl = str(uuid4())
        #: Unclaimed key packages the server holds, per agent, in publish order.
        self.pool: dict[str, list[str]] = {}
        #: Welcomes the server holds for an agent, delivered once.
        self.inbox: dict[str, list[dict[str, Any]]] = {}
        #: Whom ``POST /groups/{id}/mls/init`` reports as the founding roster.
        self.founding_roster: list[str] = []
        self.welcome_seq = 0
        for agent_id in self.agents:
            save_agent_keys(config_dir, agent_id, WORLD.keys(agent_id))

    @property
    def agents(self) -> tuple[str, str, str]:
        return (self.admin, self.bob, self.carl)

    def held(self, agent_id: str) -> int:
        """Unclaimed key packages the server holds for this agent."""
        return len(self.pool.setdefault(agent_id, []))

    def local_count(self, agent_id: str) -> int:
        """The private halves this agent still holds, read from the real core."""
        return open_mls_client(self.config_dir, agent_id).key_package_count()

    def take_inbox(self, agent_id: str) -> list[dict[str, Any]]:
        """Deliver an agent's Welcomes and clear them, as a one-shot fetch does."""
        waiting = self.inbox.get(agent_id, [])
        self.inbox[agent_id] = []
        return waiting

    def acting(self, agent_id: str) -> dict[str, str]:
        return {AGENT_HEADER: agent_id}

    def _published(self, agent_id: str) -> dict[str, Any]:
        # The chain-valid published body of one agent's keys, minted from the
        # same derived world the agent's own keys came from.
        return WORLD.keys_response(agent_id)

    # -- routes ----------------------------------------------------------------

    def upload(self, request: httpx.Request) -> httpx.Response:
        agent_id = request.url.path.split("/")[2]
        packages = json.loads(request.content)["packages"]
        self.pool.setdefault(agent_id, []).extend(packages)
        return httpx.Response(200, json={"stored": len(packages)})

    def claim(self, request: httpx.Request) -> httpx.Response:
        agent_id = request.url.path.split("/")[2]
        count = int(request.url.params.get("count", 1))
        return httpx.Response(200, json={"packages": self._take(agent_id, count)})

    def batch_claim(self, request: httpx.Request) -> httpx.Response:
        ids = json.loads(request.content)["agent_ids"]
        claims = [{"agent_id": a, "packages": self._take(a, 1)} for a in ids]
        return httpx.Response(200, json={"claims": claims})

    def _take(self, agent_id: str, count: int) -> list[str]:
        holding = self.pool.setdefault(agent_id, [])
        taken = holding[:count]
        del holding[:count]
        return taken

    def welcomes(self, request: httpx.Request) -> httpx.Response:
        agent_id = request.url.path.split("/")[2]
        return httpx.Response(200, json={"welcomes": self.take_inbox(agent_id)})

    def batch_keys(self, request: httpx.Request) -> httpx.Response:
        wanted = (request.url.params.get("ids") or "").split(",")
        keys = {a: self._published(a) for a in wanted if a in self.agents}
        return httpx.Response(200, json={"keys": keys})

    def agent_keys(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=self._published(request.url.path.split("/")[2]))

    def init(self, request: httpx.Request) -> httpx.Response:
        members = [
            {"agent_id": a, "has_key_package": self.held(a) > 0} for a in self.founding_roster
        ]
        return httpx.Response(200, json={"mls_pending": True, "members": members})

    def commit(self, request: httpx.Request) -> httpx.Response:
        group_id = request.url.path.split("/")[2]
        body = json.loads(request.content)
        for welcome in body.get("welcomes") or []:
            self.welcome_seq += 1
            self.inbox.setdefault(welcome["agent_id"], []).append(
                {
                    "id": f"{self.welcome_seq:08d}-1111-2222-3333-444444444444",
                    "group_id": group_id,
                    "blob": welcome["welcome"],
                    "created_at": "2026-01-01T00:00:00Z",
                }
            )
        return httpx.Response(200, json={"epoch": body["epoch"], "delivered_to": 1})

    def members(self, _request: httpx.Request) -> httpx.Response:
        """The roster the Welcome guard corroborates a Welcome against.

        It names the founder and the healthy peer, never Bob: the whole point of
        the drained state is that he is entitled to a seat the tree does not
        give him.
        """
        return httpx.Response(
            200, json={"items": [{"agent_id": self.admin}, {"agent_id": self.carl}]}
        )

    def group(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=self.group_row(request.url.path.split("/")[2]))

    def group_row(self, group_id: str) -> dict[str, Any]:
        return {
            "id": group_id,
            "name": "carried",
            "handle": f"#carried@{HOST}",
            "created_at": "2026-01-01T00:00:00Z",
            "mls_enabled": True,
            "mls_group_id": group_id,
        }

    def install(self) -> None:
        """Register every route this chain touches."""
        respx.post(f"{API}/oauth/token").mock(
            return_value=httpx.Response(200, json={"access_token": "t", "expires_in": 900})
        )
        respx.post(f"{API}/agents/mls/key-packages/claim").mock(side_effect=self.batch_claim)
        respx.get(f"{API}/agents/keys").mock(side_effect=self.batch_keys)
        agent = r"^/agents/[0-9a-fA-F-]+"
        group = r"^/groups/[0-9a-fA-F-]+"
        routes = [
            ("POST", rf"{agent}/mls/key-packages$", self.upload),
            ("GET", rf"{agent}/mls/key-packages$", self.claim),
            ("GET", rf"{agent}/mls/welcomes$", self.welcomes),
            ("GET", rf"{agent}/keys$", self.agent_keys),
            ("POST", rf"{group}/mls/init$", self.init),
            ("POST", rf"{group}/mls/commit$", self.commit),
            ("GET", rf"{group}/mls/handshakes$", _empty({"handshakes": []})),
            ("GET", rf"{group}/mls/group-info$", _empty({"group_info": None, "epoch": None})),
            ("GET", rf"{group}/requests$", _empty({"items": []})),
            ("GET", rf"{group}/members$", self.members),
            ("GET", rf"{group}$", self.group),
        ]
        for method, path, handler in routes:
            respx.route(method=method, host=HOST, path__regex=path).mock(side_effect=handler)


def _empty(body: dict[str, Any]):
    """A route whose answer never depends on the request."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    return handler


def _serving(config_dir: str) -> _Server:
    """Build the server and register its routes.

    Called from inside the test body rather than from a fixture on purpose:
    ``@respx.mock`` snapshots the router on entry and rolls back to that
    snapshot on exit, so routes registered in a fixture — which pytest resolves
    BEFORE the decorated body runs — outlive their test and are matched, in
    registration order, ahead of the next test's own.
    """
    server = _Server(config_dir)
    server.install()
    return server


def _spend_one_key_package(http: Any, srv: _Server, member_id: str) -> str:
    """Spend exactly one of ``member_id``'s published key packages.

    A peer founds a group naming them, and they install the Welcome it minted —
    through the core rather than :func:`process_mls_welcomes`, for the reason in
    this module's header. Returns the group they now genuinely hold state for.
    """
    group_id = str(uuid4())
    srv.founding_roster = [member_id]
    init_mls_group(http, srv.config_dir, srv.admin, group_id, srv.acting(srv.admin))
    delivered = srv.take_inbox(member_id)
    assert delivered, f"no Welcome minted for {member_id}"
    blob = mls_from_base64(delivered[0]["blob"])
    open_mls_client(srv.config_dir, member_id).join_from_welcome(blob).save()
    return group_id


def _drain_bob(http: Any, srv: _Server) -> str:
    """Drain Bob to zero on both sides; return a group he genuinely holds."""
    publish_mls_key_packages(http, srv.config_dir, srv.bob)
    assert srv.held(srv.bob) == KEY_PACKAGE_TARGET

    groups: list[str] = []
    # Derived from the pool, never from a literal round count: the policy owns
    # how many packages a publish mints.
    while srv.held(srv.bob) > 0:
        groups.append(_spend_one_key_package(http, srv, srv.bob))

    # The absorbing state, asserted on both sides. Either half alone is a
    # different population with a different repair.
    assert srv.held(srv.bob) == 0
    assert srv.local_count(srv.bob) == 0
    return groups[0]


class TestADrainedKeyPackagePool:
    @respx.mock
    def test_admission_when_the_pool_is_drained_then_the_members_own_read_unblocks_the_decrypt(
        self, sync_client, tmp_config_dir
    ):
        server = _serving(tmp_config_dir)
        http = sync_client._http
        bobs_first_group = _drain_bob(http, server)
        voted = str(uuid4())
        server.founding_roster = [server.carl]
        publish_mls_key_packages(http, server.config_dir, server.carl)
        init_mls_group(http, server.config_dir, server.admin, voted, server.acting(server.admin))

        def admit_bob():
            return add_mls_group_members(
                http,
                server.config_dir,
                server.admin,
                voted,
                [server.bob],
                server.acting(server.admin),
            )

        # The drained-pool signature: the carried vote arrives and the admission cannot
        # mint a Welcome. Nothing fails loudly — Bob is skipped, which is how he
        # ends up on a roster holding no leaf.
        refused = admit_bob()
        assert refused.outcomes[0].reason == "no_key_package"
        assert refused.added == 0
        assert server.inbox.get(server.bob, []) == []

        # Bob's own next operation. A plain read posts no commit and spends
        # nothing, so nothing about it prompts a top-up — which is exactly why the
        # beat has to ride on it rather than on the paths that spend.
        sync_mls_group(http, server.config_dir, server.bob, bobs_first_group)
        assert server.held(server.bob) == KEY_PACKAGE_TARGET
        assert server.local_count(server.bob) == KEY_PACKAGE_TARGET

        # The same vote, re-run: now it has a key package to spend.
        seated = admit_bob()
        assert seated.added == 1
        installed = process_mls_welcomes(http, server.config_dir, server.bob)
        assert voted in installed.group_ids

        # The only assertion that proves the seat is real. A roster row, an
        # outcome and an epoch are all things the shipped defect also produced.
        group = GroupRead.model_validate(server.group_row(voted))
        sent = encrypt_mls_group_message(
            http, server.config_dir, server.admin, group, {"carried": "the vote"}
        )
        read = decrypt_mls_group_message(
            http,
            server.config_dir,
            server.bob,
            voted,
            sent.encrypted_payload,
            server.admin,
        )
        assert json.loads(read.plaintext) == {"carried": "the vote"}
        assert read.verified is True

    @respx.mock
    def test_founding_when_the_pool_is_drained_then_the_member_is_dropped_without_a_word(
        self, sync_client, tmp_config_dir
    ):
        server = _serving(tmp_config_dir)
        http = sync_client._http
        bobs_first_group = _drain_bob(http, server)
        publish_mls_key_packages(http, server.config_dir, server.carl)

        # The founding entry point, which fails differently from an add: the
        # server reports ``has_key_package: false`` and the founder simply founds
        # without him. The group exists, the other member is seated, and nothing
        # anywhere says Bob is missing — this is the "silently" in the defect.
        server.founding_roster = [server.bob, server.carl]
        partial = init_mls_group(
            http, server.config_dir, server.admin, str(uuid4()), server.acting(server.admin)
        )
        assert partial.outcomes[0].agent_id == server.bob
        assert partial.outcomes[0].reason == "no_key_package"
        assert partial.added == 1
        assert server.inbox.get(server.bob, []) == []
        assert len(server.inbox.get(server.carl, [])) == 1

        sync_mls_group(http, server.config_dir, server.bob, bobs_first_group)

        refounded = str(uuid4())
        server.founding_roster = [server.bob, server.carl]
        whole = init_mls_group(
            http, server.config_dir, server.admin, refounded, server.acting(server.admin)
        )
        assert whole.outcomes[0].reason is None
        assert whole.added == 2
        installed = process_mls_welcomes(http, server.config_dir, server.bob)
        assert refounded in installed.group_ids
