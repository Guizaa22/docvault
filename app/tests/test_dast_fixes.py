"""Regression tests for the two findings of the authenticated ZAP scan (docs/evidence/zap-*)."""
from datetime import datetime, timedelta, timezone

from app.db import get_db

GOOD = {"username": "alice", "password": "correct-horse-battery"}
BAD = {"username": "alice", "password": "wrong-password-123"}


def test_f1_security_headers_on_api_responses(client):
    r = client.get("/api/health")
    assert r.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]


def test_f2_bruteforce_lock_is_temporary_not_permanent(client, app):
    for _ in range(5):
        assert client.post("/api/auth/login", json=BAD).status_code == 401
    # locked: even the right password is refused for now
    assert client.post("/api/auth/login", json=GOOD).status_code == 429
    with app.app_context():
        row = get_db().execute("SELECT is_locked, locked_until FROM users WHERE username='alice'").fetchone()
        assert row["is_locked"] == 0          # NOT the permanent admin lock any more
        assert row["locked_until"] is not None
        # simulate the 15 minutes passing
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        get_db().execute("UPDATE users SET locked_until=? WHERE username='alice'", (past,))
        get_db().commit()
    assert client.post("/api/auth/login", json=GOOD).status_code == 200


def test_f2_wrong_passwords_during_lock_do_not_extend_it(client, app):
    for _ in range(5):
        client.post("/api/auth/login", json=BAD)
    with app.app_context():
        first = get_db().execute("SELECT locked_until FROM users WHERE username='alice'").fetchone()[0]
    for _ in range(5):
        client.post("/api/auth/login", json=BAD)
    with app.app_context():
        assert get_db().execute("SELECT locked_until FROM users WHERE username='alice'").fetchone()[0] == first


def test_admin_lock_is_still_permanent(client, app):
    with app.app_context():
        get_db().execute("UPDATE users SET is_locked=1 WHERE username='alice'")
        get_db().commit()
    assert client.post("/api/auth/login", json=GOOD).status_code == 403
