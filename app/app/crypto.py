from cryptography.fernet import Fernet
from flask import current_app


def _fernet():
    return Fernet(current_app.config["FERNET_KEY"])


def encrypt_bytes(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_bytes(blob: bytes) -> bytes:
    return _fernet().decrypt(blob)
