"""Whether this host has an MLS store for an agent at all.

A rotation's key-package republish and seat sweep only make sense on the host that
holds the store: the KeyPackages minted here can be opened only here, and with no
store there are no seats here to move. The TypeScript twin is ``holdsMlsStore``
(``rine-core/src/crypto/mls-store-probe.ts``).
"""

from __future__ import annotations

import os
import stat

from rine._config import mls_store_dir


def holds_mls_store(config_dir: str, agent_id: str) -> bool:
    """Whether the agent's MLS store root exists on this host.

    One ``stat``: no compiled core, no signing key, nothing deserialized. An absent
    path is the answer ``False``; a path that is a file is not a store. Any other
    failure propagates, so a store that cannot be read never answers "holds none".
    """
    try:
        return stat.S_ISDIR(os.stat(mls_store_dir(config_dir, agent_id)).st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False
