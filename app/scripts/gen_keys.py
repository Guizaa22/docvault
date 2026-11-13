"""Generate the Ed25519 signing pair and the ES256 (P-256) JWT pair if they do not exist yet.

Usage: python scripts/gen_keys.py <directory>
Replaces the openssl calls of the old entrypoint, so the runtime image does not need the openssl CLI.
Private keys are written with mode 0600 and are never overwritten.
"""
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

PRIV = dict(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption())
PUB = dict(encoding=serialization.Encoding.PEM,
           format=serialization.PublicFormat.SubjectPublicKeyInfo)


def _write(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def make_pair(directory, priv_name, pub_name, key):
    priv_path = os.path.join(directory, priv_name)
    if os.path.exists(priv_path):
        return False
    _write(priv_path, key.private_bytes(**PRIV), 0o600)
    pub_path = os.path.join(directory, pub_name)
    if os.path.exists(pub_path):
        os.remove(pub_path)
    _write(pub_path, key.public_key().public_bytes(**PUB), 0o644)
    return True


def main(directory):
    os.makedirs(directory, mode=0o700, exist_ok=True)
    if make_pair(directory, "signing_key.pem", "signing_pub.pem", ed25519.Ed25519PrivateKey.generate()):
        print(">> Generated Ed25519 signing keys")
    if make_pair(directory, "jwt_ec_key.pem", "jwt_ec_pub.pem", ec.generate_private_key(ec.SECP256R1())):
        print(">> Generated ES256 (P-256) JWT keys")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen_keys.py <directory>")
    main(sys.argv[1])
