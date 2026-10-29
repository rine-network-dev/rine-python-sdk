"""The clear header of an ``mls-v1`` payload: ``0x04 || MLSMessage``.

A PrivateMessage names its group and epoch in the clear, inside the AEAD's
authenticated data. This is the client's reading of the layout the server reads
for its seat-span bound (``src/rine/mls_wire.py``, ``parse_private_header``);
the two must agree byte for byte, so this module is the one client-side parser.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from rine._crypto.hybrid import MAX_EPOCH

APP_MESSAGE_TAG: Final = 0x04
_MLS10: Final = 0x0001
_WIRE_FORMAT_PRIVATE_MESSAGE: Final = 0x0002
_EPOCH_LEN: Final = 8
_VARINT_LENGTHS: Final = {0b00: 1, 0b01: 2, 0b10: 4}


class MlsHeaderError(ValueError):
    """The payload is not an ``mls10`` PrivateMessage."""


@dataclass(frozen=True, slots=True)
class MlsHeader:
    """The group id and epoch a PrivateMessage names in the clear."""

    group_id: bytes
    epoch: int


def _take(payload: bytes, offset: int, length: int) -> tuple[bytes, int]:
    end = offset + length
    if end > len(payload):
        raise MlsHeaderError("payload is truncated")
    return payload[offset:end], end


def _varint(payload: bytes, offset: int) -> tuple[int, int]:
    """An RFC 9420 variable-length integer: the top two bits of the first byte size it."""
    first, _ = _take(payload, offset, 1)
    width = _VARINT_LENGTHS.get(first[0] >> 6)
    if width is None:
        raise MlsHeaderError("invalid variable-length integer")
    raw, end = _take(payload, offset, width)
    return int.from_bytes(raw, "big") & ((1 << (8 * width - 2)) - 1), end


def parse_header(payload: bytes) -> MlsHeader:
    """The group id and epoch of an ``mls10`` PrivateMessage, else ``MlsHeaderError``."""
    tag, offset = _take(payload, 0, 1)
    if tag[0] != APP_MESSAGE_TAG:
        raise MlsHeaderError("not an mls-v1 payload")
    version, offset = _take(payload, offset, 2)
    wire_format, offset = _take(payload, offset, 2)
    if int.from_bytes(version, "big") != _MLS10:
        raise MlsHeaderError("not an mls10 message")
    if int.from_bytes(wire_format, "big") != _WIRE_FORMAT_PRIVATE_MESSAGE:
        raise MlsHeaderError("not a PrivateMessage")
    group_len, offset = _varint(payload, offset)
    group_id, offset = _take(payload, offset, group_len)
    raw_epoch, _ = _take(payload, offset, _EPOCH_LEN)
    epoch = int.from_bytes(raw_epoch, "big")
    if epoch > MAX_EPOCH:
        raise MlsHeaderError("epoch is out of range")
    return MlsHeader(group_id, epoch)


__all__ = ["APP_MESSAGE_TAG", "MlsHeader", "MlsHeaderError", "parse_header"]
