import io

import pytest

from conftest import auth, token_for

ALICE = ("alice", "correct-horse-battery")
BOB = ("bob", "another-long-password")

# Classic UNION payload: tries to read the users table through the search box.
UNION_PAYLOAD = "' UNION SELECT id, username, password_hash, 0, role FROM users --"


def _upload(client, token, title, filename="a.txt"):
    return client.post(
        "/api/documents", headers=auth(token),
        data={"file": (io.BytesIO(b"content"), filename), "title": title},
        content_type="multipart/form-data",
    )


def test_search_finds_own_documents_by_title(client):
    alice = token_for(client, *ALICE)
    _upload(client, alice, "Tax report 2026")
    _upload(client, alice, "Holiday photos")
    r = client.get("/api/documents/search?q=tax", headers=auth(alice))
    assert r.status_code == 200
    assert [d["title"] for d in r.get_json()["documents"]] == ["Tax report 2026"]


def test_search_does_not_return_other_users_documents(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    _upload(client, bob, "Bob private plan")
    r = client.get("/api/documents/search?q=plan", headers=auth(alice))
    assert r.get_json()["documents"] == []


def test_search_requires_login(client):
    assert client.get("/api/documents/search?q=x").status_code == 401


@pytest.mark.xfail(
    strict=True,
    reason="V1: SQL injection in /api/documents/search (intentional; fixed in the remediation step)",
)
def test_search_is_not_injectable(client):
    """Secure behaviour we want. Fails today, so it is marked xfail (strict):
    once V1 is fixed it passes, and the strict marker forces us to remove it."""
    alice = token_for(client, *ALICE)
    r = client.get("/api/documents/search", headers=auth(alice), query_string={"q": UNION_PAYLOAD})
    leaked = [d for d in r.get_json().get("documents", []) if "$argon2" in str(d.get("filename", ""))]
    assert leaked == []
