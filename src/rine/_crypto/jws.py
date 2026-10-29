"""The restricted JCS profile and the compact JWS built on it.

The profile is deliberately narrow so that canonical bytes are unambiguous and
never need escaping: keys are lowercase ASCII words, values are non-negative
safe integers or printable-ASCII strings, and the output is one line with no
whitespace. A compact JWS is a header, a payload and an Ed25519 signature, each
base64url-encoded and joined with ``.``. The header's decoded bytes must equal
the canonical encoding of the one header the expected ``typ`` implies, so a
reordered header is refused even though it would parse to the same object.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rine._crypto.ed25519_strict import verify_ed25519_strict
from rine._utils import from_base64url, to_base64url
from rine.errors import CryptoError

#: The restricted key profile: one to sixteen lowercase letters or underscores.
_KEY_RE = re.compile(r"^[a-z_]{1,16}$")

#: The exclusive upper bound on an integer value, ``2**53``.
_MAX_SAFE_INTEGER = 2**53


class JwsError(CryptoError):
    """A restricted-JCS or compact-JWS value is outside the profile."""


class JwsTyp(StrEnum):
    """The ``typ`` header values the restricted JWS profile admits."""

    BRANCH_CERT = "rine-branch-cert+jws"
    AGENT_CERT = "rine-agent-cert+jws"
    ASSERTION = "rine-assertion+jwt"
    REGISTER_POP = "rine-register-pop+jws"


#: A restricted-JCS object: string keys mapped to strings or integers.
Claims = Mapping[str, str | int]


def _quote_string(value: str) -> str:
    """Return ``value`` quoted verbatim, refusing anything outside the profile."""
    for char in value:
        code = ord(char)
        if code < 0x20 or code > 0x7E or char in '"\\':
            raise JwsError("canonicalize: string outside the printable-ASCII profile")
    return f'"{value}"'


def _canonical_value(value: str | int) -> str:
    """Return the canonical text of one profile value."""
    if isinstance(value, bool):
        raise JwsError("canonicalize: value must be a string or integer")
    if isinstance(value, int):
        if not 0 <= value < _MAX_SAFE_INTEGER:
            raise JwsError("canonicalize: integer outside [0, 2^53)")
        return str(value)
    if isinstance(value, str):
        return _quote_string(value)
    raise JwsError("canonicalize: value must be a string or integer")


def canonicalize(value: Claims) -> str:
    """Serialize a restricted-JCS object to its canonical text.

    Args:
        value: The object to serialize.

    Returns:
        The canonical text: keys sorted by byte value, no whitespace, strings
        quoted verbatim and integers in decimal.

    Raises:
        JwsError: The object is outside the restricted profile.
    """
    if not isinstance(value, Mapping):
        raise JwsError("canonicalize: top level must be a mapping")
    for key in value:
        if not isinstance(key, str) or not _KEY_RE.match(key):
            raise JwsError(f"canonicalize: key outside profile: {key}")
    members = (f"{_quote_string(key)}:{_canonical_value(value[key])}" for key in sorted(value))
    body = ",".join(members)
    return f"{{{body}}}"


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object from ``pairs``, refusing a repeated key."""
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise JwsError(f"canonicalize: duplicate key: {key}")
        result[key] = item
    return result


def _refuse_number(token: str) -> Any:
    """Refuse a JSON number the integer-only profile does not admit."""
    raise JwsError(f"canonicalize: number outside the integer profile: {token}")


def _strict_parse(text: str) -> Any:
    """Parse JSON text with the profile's duplicate-key and number refusals."""
    return json.loads(
        text,
        object_pairs_hook=_no_duplicate_keys,
        parse_float=_refuse_number,
        parse_constant=_refuse_number,
    )


def is_canonical_text(text: str) -> bool:
    """Return whether ``text`` is exactly the canonical encoding of its value.

    Args:
        text: The JSON text to test.

    Returns:
        ``True`` only when ``text`` parses under the profile and re-serializes
        to itself byte for byte.
    """
    try:
        parsed = _strict_parse(text)
        return isinstance(parsed, dict) and canonicalize(parsed) == text
    except Exception:
        return False


def _decode_bytes(part: str) -> bytes:
    """Decode one base64url part to bytes, refusing malformed or non-canonical input.

    Trailing bits must be zero, so a signature has exactly one valid encoding.
    """
    try:
        raw = from_base64url(part)
    except ValueError as exc:
        raise JwsError("jws: malformed base64url") from exc
    if to_base64url(raw) != part:
        raise JwsError("jws: non-canonical base64url")
    return raw


def _decode_text(part: str) -> str:
    """Decode one base64url part to UTF-8 text, refusing malformed input."""
    try:
        return _decode_bytes(part).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JwsError("jws: malformed UTF-8") from exc


def _expected_header(typ: JwsTyp) -> str:
    """Return the canonical header text the expected ``typ`` implies."""
    return canonicalize({"alg": "Ed25519", "typ": typ.value})


def sign_jws(typ: JwsTyp, payload: Claims, seed: bytes) -> str:
    """Sign a payload as a compact JWS under the restricted profile.

    Args:
        typ: The ``typ`` header value the JWS carries.
        payload: The restricted-JCS claims to sign.
        seed: 32-byte Ed25519 private seed.

    Returns:
        The compact serialization ``header.payload.signature``.
    """
    header = _expected_header(typ)
    input_text = f"{to_base64url(header.encode())}.{to_base64url(canonicalize(payload).encode())}"
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(input_text.encode("ascii"))
    return f"{input_text}.{to_base64url(signature)}"


def verify_jws(compact: str, public_key: bytes, typ: JwsTyp) -> dict[str, str | int]:
    """Verify a compact JWS and return its claims.

    The checks run in a fixed order: the shape, then the exact header bytes,
    then the signature, then the payload's canonical form.

    Args:
        compact: The compact serialization to verify.
        public_key: 32-byte Ed25519 public key of the expected signer.
        typ: The ``typ`` header value the JWS must carry.

    Returns:
        The parsed claims.

    Raises:
        JwsError: Any part of the JWS is malformed, mislabelled, unsigned by
            ``public_key`` or outside the restricted profile.
    """
    parts = compact.split(".")
    if len(parts) != 3:
        raise JwsError("jws: expected 3 parts")
    if _decode_text(parts[0]) != _expected_header(typ):
        raise JwsError("jws: header is not the exact expected bytes")
    try:
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise JwsError("jws: malformed compact serialization") from exc
    if not verify_ed25519_strict(public_key, signing_input, _decode_bytes(parts[2])):
        raise JwsError("jws: bad signature")
    payload_text = _decode_text(parts[1])
    if not is_canonical_text(payload_text):
        raise JwsError("jws: payload is not canonical")
    parsed = _strict_parse(payload_text)
    return parsed  # type: ignore[no-any-return]
