"""The client assertion for ``POST /oauth/token`` (RFC 7523 ``private_key_jwt``)."""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

from rine._crypto.jws import JwsTyp, sign_jws
from rine._utils import to_base64url

if TYPE_CHECKING:
    from rine._custody import Signer

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
TOKEN_PATH = "/oauth/token"
_ASSERTION_LIFETIME = 60


def build_assertion(signer: Signer, api_url: str, now: int | None = None) -> str:
    """A fresh compact assertion for ``signer``.

    A new 128-bit ``jti`` is drawn on every call, because the server accepts
    each ``jti`` once: a retry must never reuse the assertion it is retrying.

    Args:
        signer: The principal and the seed that signs for it.
        api_url: The API base the audience is built from; a trailing ``/`` is dropped,
            because the server compares the audience exactly.
        now: Issue time in whole seconds. Defaults to the wall clock.
    """
    issued = int(time.time()) if now is None else now
    principal = str(signer.principal)
    claims: dict[str, str | int] = {
        "aud": f"{api_url.rstrip('/')}{TOKEN_PATH}",
        "exp": issued + _ASSERTION_LIFETIME,
        "iat": issued,
        "iss": principal,
        "jti": to_base64url(os.urandom(16)),
        "sub": principal,
    }
    return sign_jws(JwsTyp.ASSERTION, claims, signer.seed)


def token_form(signer: Signer, api_url: str) -> dict[str, str]:
    """The ``client_credentials`` grant form body carrying a fresh assertion."""
    return {
        "grant_type": "client_credentials",
        "client_assertion_type": CLIENT_ASSERTION_TYPE,
        "client_assertion": build_assertion(signer, api_url),
    }
