"""Regenerates ``verification_words_vectors.json`` — the verification-words goldens.

The **server** is the reference implementation: ``rine.auth.service`` is where the
derivation was first written and where the words an agent card carries come from
(``src/rine/api/agents.py``). This script therefore imports the *backend*, not
the SDK, so a regenerated fixture always states what the server would answer.

Three suites replay the output — the server's, ``rine-core``'s vitest and this
SDK's pytest — so the fixture is the only thing standing between three
implementations of one algorithm and a silent drift between them.

Run from the repository root, against the **backend** venv::

    PYTHONPATH=src .venv/bin/python \\
        rine-sdk/tests/fixtures/generate_verification_words_vectors.py \\
        > rine-sdk/tests/fixtures/verification_words_vectors.json

Regenerating is a deliberate act: if the output differs from what is committed,
either the algorithm changed (a wire break — every published card's words move)
or something is wrong. Never regenerate to make a red suite green.
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Any

from rine.auth.service import compute_verification_words

#: An Ed25519 public key, base64url without padding — the same key the
#: cross-language crypto goldens already use (``vectors.json`` → ``signing``).
BASELINE_X = "kxlETJcW9iab6QzhdOVl-ksvNaPkGxj37pujDVTUGzI"


def _jwk(x: str) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def build() -> dict[str, Any]:
    """Every vector, with the words the server's own implementation produces."""
    baseline_raw = base64.urlsafe_b64decode(BASELINE_X + "=")
    flipped_raw = baseline_raw[:-1] + bytes([baseline_raw[-1] ^ 0x01])

    cases = [
        ("baseline", _jwk(BASELINE_X), "An ordinary Ed25519 signing key."),
        (
            "baseline-one-bit",
            _jwk(_b64u(flipped_raw)),
            "The baseline key with the low bit of its last byte flipped. Its "
            "words must differ from the baseline's — that is the whole point of "
            "showing them to an operator.",
        ),
        (
            "baseline-padded-x",
            _jwk(BASELINE_X + "="),
            "The baseline key whose `x` carries explicit base64url padding. "
            "Decodes to the same 32 bytes, so it must produce the same words.",
        ),
        ("zero-key", _jwk(_b64u(bytes(32))), "Thirty-two zero bytes."),
    ]

    return {
        "note": (
            "Verification-words goldens. Derivation: SHA-256 of the raw 32-byte "
            "public key, first 55 bits, five 11-bit BIP39 English indices, "
            "most-significant group first. Reference implementation: "
            "src/rine/auth/service.py. Regenerate with "
            "rine-sdk/tests/fixtures/generate_verification_words_vectors.py."
        ),
        "one_bit_flip": ["baseline", "baseline-one-bit"],
        "same_key": ["baseline", "baseline-padded-x"],
        "vectors": [
            {
                "name": name,
                "description": description,
                "jwk": jwk,
                "words": compute_verification_words(jwk),
            }
            for name, jwk, description in cases
        ],
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=2)
    sys.stdout.write("\n")
