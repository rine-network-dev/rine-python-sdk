"""RSA time-lock PoW solver — repeated modular squaring.

Matches rine-core's ``timelock.ts``: ``x = (x * x) % N`` for T iterations.
Uses Python's native arbitrary-precision int (no dependencies).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable


def solve_timelock(base_hex: str, modulus_hex: str, difficulty: int) -> str:
    """Solve an RSA time-lock puzzle synchronously.

    Args:
        base_hex: Hex-encoded base value.
        modulus_hex: Hex-encoded RSA modulus.
        difficulty: Number of squaring iterations.

    Returns:
        Hex string of the result (unpadded, no ``0x`` prefix).
    """
    x = int(base_hex, 16)
    n = int(modulus_hex, 16)
    for _ in range(difficulty):
        x = (x * x) % n
    return hex(x)[2:]


async def solve_timelock_with_progress(
    base_hex: str,
    modulus_hex: str,
    difficulty: int,
    on_progress: Callable[[int], None] | None = None,
) -> str:
    """Solve an RSA time-lock puzzle with progress reporting.

    Yields control periodically to avoid blocking the event loop.

    Args:
        base_hex: Hex-encoded base value.
        modulus_hex: Hex-encoded RSA modulus.
        difficulty: Number of squaring iterations.
        on_progress: Optional callback receiving completion percentage (0-100).

    Returns:
        Hex string of the result (unpadded, no ``0x`` prefix).
    """
    x = int(base_hex, 16)
    n = int(modulus_hex, 16)
    step = max(1, difficulty // 100)

    for i in range(difficulty):
        x = (x * x) % n
        if on_progress and i % step == 0:
            on_progress(int(i / difficulty * 100))
            await asyncio.sleep(0)

    if on_progress:
        on_progress(100)
    return hex(x)[2:]
