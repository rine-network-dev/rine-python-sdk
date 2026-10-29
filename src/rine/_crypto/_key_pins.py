"""What a client pins about other agents' keys.

A valid chain stops nothing on its own: a malicious server can re-sign a fresh
org it controls. So a client remembers, per agent, the org that vouched for it
and the highest ``key_gen`` it has seen, and refuses an answer that contradicts
either. The handle-to-org pin is warn-only in this phase: it reports a move and
never refuses, because re-onboarding legitimately moves a reclaimed handle.
"""

from __future__ import annotations

from threading import Lock

from rine._crypto.certs import ChainError, VerifiedAgentKeys


class KeyPins:
    """Agent-to-org and agent-to-``key_gen`` pins, safe to share across threads."""

    def __init__(self) -> None:
        self._orgs: dict[str, str] = {}
        self._own_orgs: dict[str, str] = {}
        self._key_gens: dict[str, int] = {}
        self._handle_orgs: dict[str, str] = {}
        self._lock = Lock()

    def pin_own_agent(self, agent_id: str, org_id: str) -> None:
        """Pin an agent this client knows belongs to ``org_id`` before any fetch.

        This is the own-org pin: a client holding its org id locally passes it
        for every agent of that org, so no answer can move them elsewhere.
        """
        with self._lock:
            self._orgs[agent_id] = org_id
            self._own_orgs[agent_id] = org_id

    def own_org_of(self, agent_id: str) -> str | None:
        """The org a local pin fixed for this agent, or ``None``.

        A pin learned from a served chain (first sight of a peer) never answers
        here: callers that seal to the org's own keys need a value the server
        could not have chosen.
        """
        with self._lock:
            return self._own_orgs.get(agent_id)

    def note_handle_org(self, handle: str, org_id: str) -> str | None:
        """Record the org a handle resolved to; return the previous org when it moved."""
        with self._lock:
            previous = self._handle_orgs.get(handle)
            self._handle_orgs[handle] = org_id
        return previous if previous is not None and previous != org_id else None

    def admit(self, keys: VerifiedAgentKeys, *, historical: bool = False) -> None:
        """Pin verified keys, or refuse them when they contradict a pin.

        Args:
            keys: Keys that already passed the chain check.
            historical: The keys are a superseded generation fetched on purpose
                (``?gen=N``) to verify an old message, so the ``key_gen`` pin
                neither refuses nor advances.

        Raises:
            ChainError: The agent moved org, or ``key_gen`` went backwards.
        """
        with self._lock:
            pinned_org = self._orgs.setdefault(keys.agent_id, keys.org_id)
            if pinned_org != keys.org_id:
                raise ChainError("agent is pinned to another org")
            if historical:
                return
            highest = self._key_gens.get(keys.agent_id, keys.key_gen)
            if keys.key_gen < highest:
                raise ChainError("key_gen is lower than one already verified")
            self._key_gens[keys.agent_id] = keys.key_gen
