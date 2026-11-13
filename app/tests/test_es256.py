import json

import jwt
from jwt.algorithms import ECAlgorithm

from conftest import token_for


def test_access_token_is_es256_with_kid(client):
    t = token_for(client, "alice", "correct-horse-battery")
    header = jwt.get_unverified_header(t)
    assert header["alg"] == "ES256"
    assert "kid" in header


def test_jwks_endpoint_publishes_ec_public_key(client):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    key = r.get_json()["keys"][0]
    assert key["kty"] == "EC" and key["crv"] == "P-256" and key["alg"] == "ES256"


def test_token_verifies_against_jwks_public_key(client):
    # A third party verifies the token using ONLY the published public key
    t = token_for(client, "alice", "correct-horse-battery")
    jwk = client.get("/.well-known/jwks.json").get_json()["keys"][0]
    pub = ECAlgorithm.from_jwk(json.dumps(jwk))
    claims = jwt.decode(t, pub, algorithms=["ES256"])
    assert claims["sub"] == "1"
