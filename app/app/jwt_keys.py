"""ES256 JWT keys and the JWKS (public key) representation.

Access tokens are signed with the EC private key and verified with the public
key, so any party can verify a token without holding a signing secret.
"""
import base64
import hashlib

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from flask import current_app


def _priv_pem():
    with open(current_app.config["JWT_EC_PRIVATE_KEY_PATH"], "rb") as f:
        return f.read()


def _pub_pem():
    with open(current_app.config["JWT_EC_PUBLIC_KEY_PATH"], "rb") as f:
        return f.read()


def private_key():
    return _priv_pem()


def public_key():
    return _pub_pem()


def kid():
    # Stable key id derived from the public key (used in the JWT header + JWKS)
    return hashlib.sha256(_pub_pem()).hexdigest()[:16]


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def jwks():
    pub = load_pem_public_key(_pub_pem())
    nums = pub.public_numbers()
    return {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "x": _b64url(nums.x.to_bytes(32, "big")),
                "y": _b64url(nums.y.to_bytes(32, "big")),
                "use": "sig",
                "alg": "ES256",
                "kid": kid(),
            }
        ]
    }
