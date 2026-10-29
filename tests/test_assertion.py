"""The ``private_key_jwt`` client assertion a principal signs.

Every assertion is built by the real signer and verified against the real
public key, so these tests exercise the same restricted-JWS profile the server
checks: the exact header bytes, the canonical claims and the Ed25519 signature.
"""

from __future__ import annotations

import json

import pytest

from rine._assertion import CLIENT_ASSERTION_TYPE, build_assertion, token_form
from rine._crypto.jws import JwsError, JwsTyp, verify_jws
from rine._custody import Signer
from rine._principal import (
    Principal,
    agent_principal,
    branch_principal,
    org_principal,
    reader_principal,
)
from rine._utils import from_base64url
from rine.testing import WORLD

API_URL = "https://rine.network"
AGENT_ID = "00000000-1111-2222-3333-444444444444"


def _agent_signer() -> Signer:
    """The fixed agent's principal and the seed that signs its assertions."""
    return Signer(agent_principal(AGENT_ID), WORLD.keys(AGENT_ID).signing.private_key)


def _header(compact: str) -> dict[str, str]:
    """The decoded JWS header: the first compact part, base64url-decoded."""
    return json.loads(from_base64url(compact.split(".")[0]))


def test_token_form_when_agent_signer_then_client_credentials_grant():
    """The form names the client-credentials grant and the assertion type."""
    form = token_form(_agent_signer(), API_URL)
    assert form["grant_type"] == "client_credentials"
    assert form["client_assertion_type"] == CLIENT_ASSERTION_TYPE


def test_assertion_header_when_built_then_typ_is_rine_assertion_jwt():
    """The header's ``typ`` is the assertion type, not a certificate type."""
    header = _header(build_assertion(_agent_signer(), API_URL))
    assert header["typ"] == "rine-assertion+jwt"


def test_assertion_claims_when_built_then_issuer_subject_audience_and_lifetime():
    """Issuer and subject are the principal, the audience the token endpoint, the life 60s."""
    signer = _agent_signer()
    claims = verify_jws(
        build_assertion(signer, API_URL), WORLD.keys(AGENT_ID).signing.public_key, JwsTyp.ASSERTION
    )
    principal = str(signer.principal)
    assert claims["iss"] == principal
    assert claims["sub"] == principal
    assert claims["aud"] == f"{API_URL}/oauth/token"
    assert claims["exp"] - claims["iat"] == 60
    assert len(str(claims["jti"])) == 22


def test_assertion_audience_when_the_api_url_ends_in_a_slash_then_it_is_the_exact_endpoint():
    """A trailing slash on the base must not become ``//oauth/token``."""
    claims = verify_jws(
        build_assertion(_agent_signer(), f"{API_URL}/"),
        WORLD.keys(AGENT_ID).signing.public_key,
        JwsTyp.ASSERTION,
    )
    assert claims["aud"] == f"{API_URL}/oauth/token"


def test_assertion_when_verified_under_signer_public_key_then_claims_returned():
    """The assertion verifies under the signer's public key as an assertion JWS."""
    signer = _agent_signer()
    claims = verify_jws(
        build_assertion(signer, API_URL), WORLD.keys(AGENT_ID).signing.public_key, JwsTyp.ASSERTION
    )
    assert claims["iss"] == str(signer.principal)


def test_assertion_when_built_twice_then_jti_differs():
    """Each call draws a fresh ``jti``, so a retry never reuses one."""
    signer = _agent_signer()
    first = verify_jws(
        build_assertion(signer, API_URL), WORLD.keys(AGENT_ID).signing.public_key, JwsTyp.ASSERTION
    )
    second = verify_jws(
        build_assertion(signer, API_URL), WORLD.keys(AGENT_ID).signing.public_key, JwsTyp.ASSERTION
    )
    assert first["jti"] != second["jti"]


def test_assertion_when_verified_under_other_key_then_jws_error():
    """A different principal's public key refuses the signature."""
    other = WORLD.keys("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").signing.public_key
    with pytest.raises(JwsError):
        verify_jws(build_assertion(_agent_signer(), API_URL), other, JwsTyp.ASSERTION)


@pytest.mark.parametrize(
    "principal",
    [
        org_principal(WORLD.org_id),
        branch_principal(WORLD.org_id, "main"),
        agent_principal(AGENT_ID),
        reader_principal(WORLD.org_id),
        reader_principal(WORLD.org_id, "main"),
    ],
    ids=["org", "branch", "agent", "org-reader", "branch-reader"],
)
def test_assertion_when_principal_is_any_form_then_iss_is_wire_form(principal: Principal):
    """Every principal form signs its own wire spelling as issuer and subject."""
    signer = Signer(principal, WORLD.org.ed_seed)
    claims = verify_jws(build_assertion(signer, API_URL), WORLD.org.ed_pk, JwsTyp.ASSERTION)
    assert claims["iss"] == str(principal)
    assert claims["sub"] == str(principal)
