"""SDK logger setup — NullHandler by default, consumers configure logging."""

from __future__ import annotations

import logging

logger = logging.getLogger("rine")
logger.addHandler(logging.NullHandler())
