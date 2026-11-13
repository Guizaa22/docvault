import os
import tempfile

import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from app import create_app
from app.db import get_db

ph = PasswordHasher()


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    keys = os.path.join(os.path.dirname(__file__), os.pardir, "keys")
    app = create_app({
        "DATABASE": db_path,
        "JWT_SECRET": "test-secret-not-the-real-one",
        "FERNET_KEY": Fernet.generate_key().decode(),
        "SIGNING_KEY_PATH": os.path.join(keys, "signing_key.pem"),
        "SIGNING_PUBKEY_PATH": os.path.join(keys, "signing_pub.pem"),
        "JWT_EC_PRIVATE_KEY_PATH": os.path.join(keys, "jwt_ec_key.pem"),
        "JWT_EC_PUBLIC_KEY_PATH": os.path.join(keys, "jwt_ec_pub.pem"),
        "INIT_DB": True,
        "TESTING": True,
        "RATELIMIT_ENABLED": False,
    })

    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("alice", ph.hash("correct-horse-battery")),
        )
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            ("bob", ph.hash("another-long-password")),
        )
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            ("admin1", ph.hash("admin-strong-password-2026")),
        )
        db.commit()

    yield app

    os.close(db_fd)
    os.unlink(db_path)


@pytest.fixture
def client(app):
    return app.test_client()


def token_for(client, username, password):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    return r.get_json()["access_token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}
