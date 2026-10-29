"""The keys that let a process act under one branch.

A delegate holds a branch's two subtree keys as files under
``<config dir>/branch/<name>/``; a process with ``root.key`` derives them.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from rine._crypto.derive_nodes import BranchNode, branch_ed_seed, branch_reader_seed
from rine._utils import from_base64url
from rine.errors import ConfigError

_SECRET_SIZE = 32


@dataclass(frozen=True, slots=True)
class BranchSecrets:
    """What is needed to act under one branch: its two secrets and the seeds derived from them."""

    name: str
    b_read: bytes = field(repr=False)
    b_sign: bytes = field(repr=False)
    ed_seed: bytes = field(repr=False)
    reader_seed: bytes = field(repr=False)

    @classmethod
    def from_node(cls, node: BranchNode) -> BranchSecrets:
        """The secrets of a branch derived from an org root."""
        return cls(node.name, node.b_read, node.b_sign, node.ed_seed, node.reader_seed)

    @classmethod
    def from_secrets(cls, name: str, b_read: bytes, b_sign: bytes) -> BranchSecrets:
        """The secrets of a branch held as its two subtree secrets only (a delegate)."""
        return cls(
            name,
            b_read,
            b_sign,
            branch_ed_seed(b_sign),
            branch_reader_seed(b_read),
        )


def _read_secret(path: str) -> bytes:
    try:
        with open(path) as f:
            secret = from_base64url(f.read().strip())
    except ValueError:
        secret = b""
    if len(secret) != _SECRET_SIZE:
        raise ConfigError(f"Corrupt branch key file: {path}")
    return secret


def load_branch_files(config_dir: str, name: str) -> BranchSecrets | None:
    """The branch a delegate dir holds under ``branch/<name>/``, or ``None`` when absent."""
    folder = os.path.join(config_dir, "branch", name)
    read, sign = os.path.join(folder, "read.key"), os.path.join(folder, "sign.key")
    if not (os.path.isfile(read) and os.path.isfile(sign)):
        return None
    return BranchSecrets.from_secrets(name, _read_secret(read), _read_secret(sign))
