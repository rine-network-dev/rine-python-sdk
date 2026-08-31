"""The one place Python decides that a group has been downgraded.

A rine group is either MLS-encrypted or on sender keys, and the server is the
only party that says which. That makes it the one party a client must not take
at its word: a server that presents an MLS group as a sender-key group walks
every member back onto a broadcast key it distributes itself. The client already
holds the evidence to catch it — its own local MLS state for that group — so the
contradiction is checked here, once, and refused everywhere.

The guard fires ONLY on the contradiction. Holding no local state is never
evidence of a downgrade: a billboard group, a member whose Welcome has not been
processed and a fresh install all hold none, and all keep working.

The TypeScript mirror is ``rine-core/src/crypto/mls-downgrade.ts``; both take the
same normative input, because a guard whose input differs per stack refuses in
one stack and passes in the other.

The evidence is read through :func:`rine._mls.group_access.holds_mls_state`,
which the state module keeps honest by invalidating at every establishment and
retirement. The guard deliberately keeps no cache of its own: a second cache
would be a second thing to invalidate.

Importing this module imports the compiled MLS core, because importing anything
under ``rine._mls`` does. Call sites on the sender-key path — the send branch in
``rine._group_send`` and the group decrypt in ``rine._crypto.message`` — import
it inside the function for that reason, so a client that only ever touches
sender-key groups still never loads the group stack at import time.
"""

from __future__ import annotations

from rine._mls.group_access import holds_mls_state
from rine.errors import MlsDowngradeError


def assert_no_mls_downgrade(
    config_dir: str, agent_id: str, group_id: str, server_says_mls: bool
) -> None:
    """Refuse a group whose server-side account contradicts this agent's MLS state.

    Args:
        config_dir: Config directory path.
        agent_id: The agent whose local state is the evidence.
        group_id: Group UUID.
        server_says_mls: Whether the server presents this group as MLS.
            Normatively ``group.mls_group_id is not None or bool(group.mls_pending)``
            — the send predicate, mirroring the server's own ``is_mls_frozen``, and
            the same expression the TypeScript guard takes. Callers pass
            ``group_accepts_mls_send_only(group)`` rather than restating it. A
            ``sender-key-v1`` ciphertext is itself the server claiming "not MLS",
            so the read path passes ``False``.

    Raises:
        MlsDowngradeError: When the server says not-MLS and this agent holds MLS
            state for the group.
    """
    if server_says_mls:
        return
    if not holds_mls_state(config_dir, agent_id, group_id):
        return
    raise MlsDowngradeError(group_id)


__all__ = ["assert_no_mls_downgrade"]
