"""A drain outcome with something to report, and the report it must become."""

from __future__ import annotations

from rine._mls.binding import EscrowGapReason
from rine._mls.escrow_drain import DrainOutcome
from rine._mls.escrow_gap import DrainGap
from rine._mls.escrow_report import EscrowDeferral, EscrowReport
from rine.errors import CryptoError

GAP = DrainGap(5, EscrowGapReason.MALFORMED)

#: A drain that found a gap and could not seal: no verified escrow key.
DEFERRED = DrainOutcome(0, 0, (), CryptoError("no escrow key"), gaps=(GAP,))

#: What every result carrying the drain above must say.
DEFERRED_REPORT = EscrowReport(gaps=(GAP,), deferral=EscrowDeferral.KEY_UNAVAILABLE)
