import base64
import json

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from flask import current_app


def canonical(data):
    # Signatures cover exact bytes, so serialize the same way every time
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sign(data):
    with open(current_app.config["SIGNING_KEY_PATH"], "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)
    return base64.b64encode(private_key.sign(canonical(data))).decode("ascii")


def public_key_pem():
    with open(current_app.config["SIGNING_PUBKEY_PATH"], "rb") as f:
        return f.read().decode("ascii")
