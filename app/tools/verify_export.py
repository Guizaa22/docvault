"""Verify a signed note export. Needs only the public key, not the app or any secret."""
import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


with open(sys.argv[1]) as f:
    export = json.load(f)
with open(sys.argv[2], "rb") as f:
    public_key = load_pem_public_key(f.read())

try:
    public_key.verify(base64.b64decode(export["signature"]), canonical(export["document"]))
    print("VALID: document is authentic and unmodified")
except InvalidSignature:
    print("INVALID: document was modified or not signed by this server")
    sys.exit(1)
