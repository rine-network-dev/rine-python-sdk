"""A group whose members share one config dir, and one of them rotates its key.

The real ``rine-mls`` core runs; only the server is a stub. ``A`` and ``B`` are
agents of one device (config dir ``d1``), ``R`` founds the group from another
device, and ``C`` is a remote joiner. A fresh process is emulated by clearing the
process-wide allowed sets, which is all a new process lacks.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from rine._crypto.keys import save_agent_keys
from rine._mls import binding
from rine._mls.binding import allowed_for, credential_identity, open_mls_client
from rine._mls.group_access import mls_group_id_bytes, open_mls_group
from rine._mls.wire import mls_to_base64
from rine.testing import WORLD
from tests.test_crypto.world import KeyServer

A = "a1a1a1a1-0000-4000-8000-000000000001"
B = "b2b2b2b2-0000-4000-8000-000000000002"
R = "c3c3c3c3-0000-4000-8000-000000000003"
C = "d4d4d4d4-0000-4000-8000-000000000004"
G1 = "11111111-0000-4000-8000-0000000000a1"
G2 = "22222222-0000-4000-8000-0000000000a2"


class Server:
    """Every read and write the flows under test make; the core is real."""

    def __init__(self) -> None:
        """Start with no groups, no handshakes and no rotated agent."""
        self.keys = KeyServer(WORLD)
        self.key_pins = self.keys.key_pins
        self.calls: list[str] = []
        self.gen: dict[str, int] = {}
        self.handshakes: dict[str, list[dict[str, Any]]] = {}
        self.group_info: dict[str, tuple[bytes, int]] = {}
        self.welcomes: dict[str, list[dict[str, Any]]] = {}
        self.rosters: dict[str, list[str]] = {}
        self.kps: dict[str, list[bytes]] = {}
        self.nacks: list[Any] = []
        self.unknown: list[str] = []
        self.absent: set[str] = set()

    @property
    def _keys_cache(self) -> Any:
        """The key cache an envelope check and a history admission read through."""
        return self.keys._keys_cache

    def publish(self, agent: str, gen: int) -> None:
        """Publish ``agent`` at key generation ``gen``."""
        self.gen[agent] = gen
        self.keys.publish(agent, gen)

    def post_commit(self, gid: str, bundle: Any) -> None:
        """File a commit a member built locally, with its GroupInfo."""
        hs = self.handshakes.setdefault(gid, [])
        hs.append(
            {
                "id": f"{gid}-h{bundle.epoch}-{len(hs)}",
                "epoch": bundle.epoch,
                "blob": mls_to_base64(bundle.commit),
                "created_at": "2024-01-01T00:00:00Z",
            }
        )
        self.group_info[gid] = (bundle.group_info, bundle.epoch)

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Answer a read; ``absent`` agents are left out of the batch key read."""
        params = kwargs.get("params") or {}
        self.calls.append(f"GET {path} {params}")
        if m := re.fullmatch(r"/groups/([^/]+)/mls/handshakes", path):
            since = int(params.get("since_epoch", 0) or 0)
            return {"handshakes": [h for h in self.handshakes.get(m[1], []) if h["epoch"] > since]}
        if m := re.fullmatch(r"/groups/([^/]+)/mls/group-info", path):
            blob, epoch = self.group_info[m[1]]
            return {"group_info": mls_to_base64(blob), "epoch": epoch}
        if m := re.fullmatch(r"/groups/([^/]+)/members", path):
            return {"items": [{"agent_id": a} for a in self.rosters.get(m[1], [])]}
        if re.fullmatch(r"/groups/[^/]+/requests", path):
            return {"items": []}
        if m := re.fullmatch(r"/groups/([^/]+)", path):
            return self._row(m[1])
        if path == "/groups":
            return {"items": [self._row(g) for g in self.rosters]}
        if m := re.fullmatch(r"/agents/([^/]+)/mls/welcomes", path):
            return {"welcomes": self.welcomes.get(m[1], [])}
        if re.fullmatch(r"/agents/[^/]+/mls/key-packages/count", path):
            return {"count": 50}
        if m := re.fullmatch(r"/agents/([^/]+)/mls/key-packages", path):
            return {"packages": [mls_to_base64(self.kps[m[1]].pop(0))]}
        if path == "/agents/keys":
            ids = [i for i in str(params["ids"]).split(",") if i]
            return {
                "keys": {
                    i: WORLD.keys_response(i, self.gen.get(i, 0))
                    for i in ids
                    if i not in self.absent
                }
            }
        if re.fullmatch(r"/agents/[^/]+/keys", path):
            return self.keys.get(path, **kwargs)
        self.unknown.append(path)
        return {"items": []}

    def _row(self, gid: str) -> dict[str, Any]:
        return {
            "id": gid,
            "name": gid[:4],
            "handle": f"#{gid[:4]}@acme",
            "created_at": "2024-01-01T00:00:00Z",
            "mls_enabled": True,
            "mls_group_id": "latched",
            "member_agent_ids": self.rosters.get(gid, []),
        }

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Accept a commit, ack, nack or key-package upload, recording what it needs."""
        body = kwargs.get("json_body") or {}
        if m := re.fullmatch(r"/groups/([^/]+)/mls/commit", path):
            hs = self.handshakes.setdefault(m[1], [])
            hs.append(
                {
                    "id": f"{m[1]}-h{body['epoch']}-{len(hs)}",
                    "epoch": body["epoch"],
                    "blob": body["commit"],
                    "created_at": "2024-01-01T00:00:00Z",
                }
            )
            if body.get("group_info"):
                self.group_info[m[1]] = (base64.b64decode(body["group_info"]), body["epoch"])
            for w in body.get("welcomes") or []:
                self.welcomes.setdefault(w["agent_id"], []).append(
                    {"id": f"w{len(hs)}", "group_id": m[1], "blob": w["welcome"]}
                )
            return {"epoch": body["epoch"], "delivered_to": 1}
        if path.endswith("/mls/ack"):
            return {"confirmed": True}
        if path.endswith("/mls/nack"):
            self.nacks.append(body)
            return {"quarantined": True}
        if path.endswith("/mls/key-packages"):
            return {"stored": len(body.get("packages", []))}
        self.unknown.append(f"POST {path}")
        return {}


def fresh_process() -> None:
    """Forget every allowed set, as a new process would."""
    with binding._allowed_lock:
        binding._allowed_by_actor.clear()


def admit(config_dir: str, actor: str, *pairs: tuple[str, int]) -> None:
    """Put ``(agent, generation)`` pairs into ``actor``'s allowed set."""
    allowed = allowed_for(config_dir, actor)
    for agent, gen in pairs:
        allowed.insert(credential_identity(agent), WORLD.keys(agent, gen).mls.public_key, gen)


def tree(config_dir: str, agent: str, gid: str) -> str:
    """The sorted 8-character id prefixes of the leaves in ``agent``'s tree."""
    g = open_mls_group(config_dir, agent, gid)
    return ",".join(sorted(m.identity.decode()[:8] for m in g.member_identities()))


def world(
    tmp_path: Any, gid: str, members: list[str], server: Server | None = None
) -> tuple[Server, str, str, str]:
    """R founds ``gid`` holding ``members`` (all on device d1) at gen 0."""
    d1, dr, dc = (str(tmp_path / n) for n in ("d1", "r", "c"))
    for agent in (A, B):
        save_agent_keys(d1, agent, WORLD.keys(agent, 0))
    save_agent_keys(dr, R, WORLD.keys(R, 0))
    save_agent_keys(dc, C, WORLD.keys(C, 0))
    server = server or Server()
    server.rosters[gid] = [R, *members]
    admit(dr, R, (A, 0), (B, 0), (C, 0))
    kps = [
        open_mls_client(d1, m, allowed=allowed_for(d1, m)).generate_key_package() for m in members
    ]
    group = open_mls_client(dr, R, allowed=allowed_for(dr, R)).create_group_with_members(
        mls_group_id_bytes(gid), kps
    )
    bundle = group.last_commit()
    group.save()
    server.group_info[gid] = (bundle.group_info, bundle.epoch)
    for m, w in zip(members, bundle.welcomes, strict=True):
        admit(d1, m, (R, 0), *[(o, 0) for o in members])
        open_mls_client(d1, m, allowed=allowed_for(d1, m)).join_from_welcome(w).save()
    return server, d1, dr, dc


def rotate(server: Server, d1: str, agent: str) -> None:
    """Rotate ``agent`` to generation 1: new keys on disk, published to the server."""
    save_agent_keys(d1, agent, WORLD.keys(agent, 1))
    server.publish(agent, 1)
