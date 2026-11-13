import time

import jwt

from conftest import auth, token_for


def test_no_token_is_rejected(client):
    assert client.get("/api/me").status_code == 401


def test_forged_token_rejected(client):
    t = int(time.time())
    forged = jwt.encode({"sub": "1", "jti": "x", "iat": t, "exp": t + 900},
                        "wrong-secret", algorithm="HS256")
    assert client.get("/api/me", headers=auth(forged)).status_code == 401


def test_alg_none_token_rejected(client):
    # T4: the unsigned-token attack
    t = int(time.time())
    evil = jwt.encode({"sub": "1", "jti": "y", "iat": t, "exp": t + 900},
                      None, algorithm="none")
    assert client.get("/api/me", headers=auth(evil)).status_code == 401


def test_expired_token_rejected(client):
    t = int(time.time())
    expired = jwt.encode({"sub": "1", "jti": "z", "iat": t - 2000, "exp": t - 1000},
                         "test-secret-not-the-real-one", algorithm="HS256")
    assert client.get("/api/me", headers=auth(expired)).status_code == 401


def test_user_cannot_reach_admin_route(client):
    # T7 vertical: a normal user hitting an admin endpoint
    alice = token_for(client, "alice", "correct-horse-battery")
    assert client.get("/api/admin/users", headers=auth(alice)).status_code == 403


def test_logout_revokes_token(client):
    # T5: the token must stop working after logout
    alice = token_for(client, "alice", "correct-horse-battery")
    assert client.post("/api/auth/logout", headers=auth(alice)).status_code == 200
    assert client.get("/api/me", headers=auth(alice)).status_code == 401
