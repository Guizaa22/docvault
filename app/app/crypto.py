from cryptography.fernet import Fernet
from flask import current_app


def _fernet():
    return Fernet(current_app.config["FERNET_KEY"])


def encrypt(text):
    return _fernet().encrypt(text.encode("utf-8"))


def decrypt(blob):
    return _fernet().decrypt(blob).decode("utf-8")
