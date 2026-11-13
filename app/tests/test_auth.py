from conftest import auth, token_for


def test_register_defaults_to_user_role(client):
    # T7: even if "role":"admin" is sent, the account must be a normal user
    client.post("/api/auth/register",
                json={"username": "charlie", "password": "a-long-password-123", "role": "admin"})
    admin = token_for(client, "admin1", "admin-strong-password-2026")
    users = client.get("/api/admin/users", headers=auth(admin)).get_json()["users"]
    charlie = next(u for u in users if u["username"] == "charlie")
    assert charlie["role"] == "user"


def test_short_password_rejected(client):
    r = client.post("/api/auth/register", json={"username": "dave", "password": "short"})
    assert r.status_code == 400


def test_login_success_returns_token(client):
    r = client.post("/api/auth/login",
                    json={"username": "alice", "password": "correct-horse-battery"})
    assert r.status_code == 200
    assert "access_token" in r.get_json()


def test_wrong_password_and_unknown_user_are_identical(client):
    # T3: responses must be indistinguishable
    r1 = client.post("/api/auth/login", json={"username": "alice", "password": "wrong-password-x"})
    r2 = client.post("/api/auth/login", json={"username": "ghost", "password": "wrong-password-x"})
    assert r1.status_code == r2.status_code == 401
    assert r1.get_json() == r2.get_json()


def test_sql_injection_in_username_is_harmless(client):
    # T8: a classic injection payload must simply fail to log in, not break the query
    r = client.post("/api/auth/login",
                    json={"username": "alice' OR '1'='1", "password": "whatever-here"})
    assert r.status_code == 401
