def _login(client, username, password):
    return client.post(
        "/api/auth/login", json={"username": username, "password": password}
    ).get_json()


def test_login_returns_refresh_token(client):
    body = _login(client, "alice", "correct-horse-battery")
    assert "access_token" in body and "refresh_token" in body


def test_refresh_rotates_and_issues_new_tokens(client):
    first = _login(client, "alice", "correct-horse-battery")
    r = client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert r.status_code == 200
    body = r.get_json()
    assert "access_token" in body and "refresh_token" in body
    assert body["refresh_token"] != first["refresh_token"]  # rotated


def test_reused_refresh_token_is_rejected(client):
    first = _login(client, "alice", "correct-horse-battery")
    old = first["refresh_token"]
    client.post("/api/auth/refresh", json={"refresh_token": old})       # rotates away
    reuse = client.post("/api/auth/refresh", json={"refresh_token": old})
    assert reuse.status_code == 401


def test_invalid_refresh_token_is_rejected(client):
    r = client.post("/api/auth/refresh", json={"refresh_token": "not-a-real-token"})
    assert r.status_code == 401
