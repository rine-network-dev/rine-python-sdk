"""Peers for the Welcome tests: a real MLS founder that seats the agent under test."""

from __future__ import annotations

import json
import os
import struct

from rine._crypto.keys import save_agent_keys
from rine._mls import mls_group_id_bytes, open_mls_client
from rine._mls.binding import PeerNotAdmittedError, credential_identity
from rine._mls.welcome_spool import welcome_spool_dir
from rine.testing import WORLD

GROUP_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
FOUNDER_ID = "11111111-2222-3333-4444-555555555555"


def peer_client(tmp_path, agent: str, *also: str):
    """This peer's MLS client, minting its keys once and reopening them after.

    Reopening matters: a peer whose keys were regenerated has a different MLS
    identity, and the guard compares identities for a living. The extra ids are
    agents this peer will seat: the core refuses a leaf whose
    ``(agent id, leaf key)`` pair is outside the client's allowed set, which is
    every agent whose keys live in its config dir.
    """
    peer_dir = str(tmp_path / f"peer-{agent}")
    if not os.path.isdir(peer_dir):
        save_agent_keys(peer_dir, agent, WORLD.keys(agent))
        for other in also:
            save_agent_keys(peer_dir, other, WORLD.keys(other))
    return open_mls_client(peer_dir, agent)


def honest_welcome(
    tmp_config_dir, agent_id, tmp_path, group_id=GROUP_ID, founder_id=FOUNDER_ID
) -> bytes:
    """A founder seats the victim in ``group_id`` and hands over its Welcome."""
    founder = peer_client(tmp_path, founder_id, agent_id)
    # The victim's client has to know the founder's leaf key to adopt the tree.
    save_agent_keys(tmp_config_dir, founder_id, WORLD.keys(founder_id))
    victim = open_mls_client(tmp_config_dir, agent_id)
    group = founder.create_group_with_members(
        mls_group_id_bytes(group_id), [victim.generate_key_package()]
    )
    group.save()
    bundle = group.last_commit()
    assert bundle is not None
    return bundle.welcomes[0]


def refused_flags(config_dir: str, agent_id: str) -> list[bool]:
    """The ``refused`` bit of every spooled Welcome, read off the spool files."""
    spool_dir = welcome_spool_dir(config_dir, agent_id)
    flags = []
    for name in sorted(os.listdir(spool_dir)):
        with open(os.path.join(spool_dir, name), encoding="utf-8") as handle:
            flags.append(json.load(handle)["refused"])
    return flags


def foreign_suite_welcome() -> bytes:
    """A well-framed Welcome sealed for the classical ciphersuite, which this core refuses.

    Version 1, the Welcome wire format, ciphersuite 1 and no secrets: it parses, so
    the refusal is the core's own ciphersuite check and not a framing error.
    """
    version, welcome_format, classical_suite = 1, 3, 1
    return struct.pack(">HHH", version, welcome_format, classical_suite) + b"\x00\x00"


class RefusesOnce:
    """A real group handle whose first commit build is refused, naming ``agent_id``.

    The core only refuses a commit build over the committer's own leaf, which no
    honest setup produces, so the refusal is raised here exactly as the core
    raises it: the typed error, with the refused identity readable afterwards and
    the handle left unchanged.
    """

    def __init__(self, group, agent_id: str) -> None:
        """Wrap ``group``, arming one refusal that names ``agent_id``."""
        self._group = group
        self._named = credential_identity(agent_id)
        self._armed = True
        self.refused: bytes | None = None

    def refused_peer(self) -> bytes | None:
        """The identity the last build refused, or ``None``."""
        return self.refused

    def _build(self, build):
        self.refused = None
        if self._armed:
            self._armed = False
            self.refused = self._named
            raise PeerNotAdmittedError("the commit carries a leaf this member has not admitted")
        return build()

    def remove_member(self, leaf: int):
        """Build a Remove commit, refused the first time."""
        return self._build(lambda: self._group.remove_member(leaf))

    def add_members(self, key_packages: list[bytes]):
        """Build an Add commit, refused the first time."""
        return self._build(lambda: self._group.add_members(key_packages))

    def __getattr__(self, name: str):
        """Everything else is the real group."""
        return getattr(self._group, name)
