"""Releasing the private half of a Welcome that leaves the spool unopened.

A KeyPackage's private half is consumed when its Welcome is joined. A Welcome dropped
without being opened (aged out, evicted past the refused bound, its group gone, or
answered with a final refusal) leaves that half in the local store, so the local pool
count still includes a package nobody can use. The native core releases it by name, which
lets the heartbeat see the real count and publish a replacement without asking the server.

The releaser works through the welcome pass's own client, which is opened on first use:
a pass that drops nothing opens nothing, and the pass and its releaser share one handle
on the store.

The TypeScript twin is ``welcomeReleaser`` in ``rine-core/src/mls-welcome-release.ts``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rine._mls.failures import is_unprocessable_commit

if TYPE_CHECKING:
    from collections.abc import Callable

    from rine._mls.binding import MlsClient


def welcome_releaser(client: Callable[[], MlsClient]) -> Callable[[bytes], None]:
    """A function that releases the key package a Welcome blob was sealed to.

    ``client`` hands over the pass's client; it is called only when a blob is released.

    A blob with nothing to release (not a Welcome, another ciphersuite, or one the
    core cannot read) is skipped; a failure of this process (a store failure, a
    contained panic, a poisoned handle) propagates, so the entry is kept for the
    next pass.
    """

    def release(welcome: bytes) -> None:
        mls = client()
        try:
            mls.discard_welcome_key_package(welcome)
        except Exception as err:
            if not is_unprocessable_commit(err):
                raise

    return release
