"""Tests for RSA time-lock PoW solver."""

from __future__ import annotations

import pytest

from rine._timelock import solve_timelock, solve_timelock_with_progress


class TestSolveTimelock:
    def test_basic_squaring(self):
        # 3^(2^4) mod 7 = 3 squared 4 times mod 7
        # 3^2=9%7=2, 2^2=4, 4^2=16%7=2, 2^2=4 → "4"
        result = solve_timelock("0x3", "0x7", 4)
        assert result == "4"

    def test_zero_difficulty(self):
        # 0 iterations → just return the base
        result = solve_timelock("0x5", "0xb", 0)
        assert result == "5"

    def test_single_iteration(self):
        # 5^2 mod 11 = 25 mod 11 = 3
        result = solve_timelock("0x5", "0xb", 1)
        assert result == "3"

    def test_large_modulus(self):
        # Should handle large numbers without overflow
        result = solve_timelock("0xff", "0xfffffffb", 10)
        assert len(result) > 0  # Just verify it completes

    def test_result_is_unpadded_hex(self):
        result = solve_timelock("0x2", "0x11", 3)
        assert not result.startswith("0x")
        assert all(c in "0123456789abcdef" for c in result)


class TestSolveTimelockWithProgress:
    @pytest.mark.asyncio
    async def test_produces_same_result(self):
        sync_result = solve_timelock("0x3", "0x7", 4)
        async_result = await solve_timelock_with_progress("0x3", "0x7", 4)
        assert sync_result == async_result

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        progress_values: list[int] = []
        await solve_timelock_with_progress("0x3", "0xb", 200, on_progress=progress_values.append)
        assert 100 in progress_values
        assert len(progress_values) > 1

    @pytest.mark.asyncio
    async def test_no_progress_callback(self):
        result = await solve_timelock_with_progress("0x5", "0xb", 1)
        assert result == "3"
