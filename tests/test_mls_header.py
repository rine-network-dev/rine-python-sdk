"""The MLS PrivateMessage header parser, against hand-built payloads."""

from __future__ import annotations

import pytest

from rine._crypto.hybrid import MAX_EPOCH
from rine._mls.header import APP_MESSAGE_TAG, MlsHeader, MlsHeaderError, parse_header

_GROUP_ID = bytes(range(16))


def _header(group_id: bytes, epoch: int, *, tag: int = APP_MESSAGE_TAG) -> bytes:
    """A PrivateMessage header: tag, version, wire format, varint length, group, epoch."""
    length = len(group_id)
    if length < 64:
        varint = bytes([length])
    else:
        varint = (0x4000 | length).to_bytes(2, "big")
    return (
        bytes([tag])
        + (0x0001).to_bytes(2, "big")
        + (0x0002).to_bytes(2, "big")
        + varint
        + group_id
        + epoch.to_bytes(8, "big")
    )


def test_parse_header_when_well_formed_then_group_and_epoch_are_read():
    assert parse_header(_header(_GROUP_ID, 7)) == MlsHeader(_GROUP_ID, 7)


def test_parse_header_when_group_id_needs_two_varint_bytes_then_it_is_read():
    group_id = bytes(range(64))
    assert parse_header(_header(group_id, 2**40 + 7)) == MlsHeader(group_id, 2**40 + 7)


def test_parse_header_when_payload_is_truncated_then_it_is_refused():
    with pytest.raises(MlsHeaderError, match="payload is truncated"):
        parse_header(_header(_GROUP_ID, 7)[:-1])


def test_parse_header_when_tag_is_wrong_then_it_is_refused():
    with pytest.raises(MlsHeaderError, match="not an mls-v1 payload"):
        parse_header(_header(_GROUP_ID, 7, tag=0x05))


def test_parse_header_when_version_is_wrong_then_it_is_refused():
    payload = bytearray(_header(_GROUP_ID, 7))
    payload[1:3] = (0x0002).to_bytes(2, "big")
    with pytest.raises(MlsHeaderError, match="not an mls10 message"):
        parse_header(bytes(payload))


def test_parse_header_when_wire_format_is_wrong_then_it_is_refused():
    payload = bytearray(_header(_GROUP_ID, 7))
    payload[3:5] = (0x0001).to_bytes(2, "big")
    with pytest.raises(MlsHeaderError, match="not a PrivateMessage"):
        parse_header(bytes(payload))


def test_parse_header_when_epoch_is_above_the_maximum_then_it_is_refused():
    with pytest.raises(MlsHeaderError, match="epoch is out of range"):
        parse_header(_header(_GROUP_ID, MAX_EPOCH + 1))


def test_parse_header_when_varint_prefix_is_invalid_then_it_is_refused():
    payload = bytearray(_header(_GROUP_ID, 7))
    payload[5] = 0b11000000
    with pytest.raises(MlsHeaderError, match="invalid variable-length integer"):
        parse_header(bytes(payload))
