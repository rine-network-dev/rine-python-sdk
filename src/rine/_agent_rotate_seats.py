"""Rotating an agent's keys, then moving its group seats to the new key.

:func:`rotate_agent_keys` is the keys-only step and stays that: it derives the
next generation, uploads the public halves and saves the private ones. This wraps
it with the work a rotation leaves behind on a host that holds the agent's MLS
state: republishing the KeyPackages and moving the agent's leaf in each group
(:func:`rine._mls.seat_sweep.settle_rotation`).

The server has committed the rotation by the time the settlement starts, so
nothing after the POST raises: a failure is reported in the result and a later
heartbeat finishes the work. The TypeScript twin is ``rotateAgentWithSeats``
(``rine-core/src/agent-rotate-seats.ts``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._agent_provision import rotate_agent_keys
from rine._mls.actor import MlsActor
from rine._mls.seat_sweep import KeyPackageRotation, settle_rotation
from rine._seat_update import SeatUpdate  # noqa: TC001 - pydantic resolves the annotation
from rine.types import AgentRead

if TYPE_CHECKING:
    from rine._http import SyncHttpClient


class RotatedAgent(AgentRead):
    """The rotated agent, and what the rotation did on this host."""

    key_packages: KeyPackageRotation
    """``republished``, ``pending`` (a later heartbeat finishes it), or ``not_held``
    (this host holds none of the agent's MLS state)."""

    group_seats: list[SeatUpdate]
    """One entry per group whose leaf was tried; empty when nothing was held here."""


def rotate_agent_with_seats(
    client: SyncHttpClient, config_dir: str, owner_dir: str | None, agent_id: str
) -> RotatedAgent:
    """Rotate an agent to its next key generation and move its group seats.

    Raises:
        ConfigError: This process holds no key material for the agent's branch.
        RineApiError: The server refused the rotation. Nothing after it raises.
    """
    agent = rotate_agent_keys(client, config_dir, owner_dir, agent_id)
    settlement = settle_rotation(MlsActor(client, config_dir, agent_id))
    return RotatedAgent(
        **agent.model_dump(),
        key_packages=settlement.key_packages,
        group_seats=settlement.group_seats,
    )


__all__ = ["KeyPackageRotation", "RotatedAgent", "rotate_agent_with_seats"]
