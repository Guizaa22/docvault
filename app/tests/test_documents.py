import io

from conftest import auth, token_for

ALICE = ("alice", "correct-horse-battery")
BOB = ("bob", "another-long-password")
ADMIN = ("admin1", "admin-strong-password-2026")


def _upload(client, token, content=b"hidden text", filename="secret.txt", title="Secret"):
    return client.post(
        "/api/documents",
        headers=auth(token),
        data={"file": (io.BytesIO(content), filename), "title": title},
        content_type="multipart/form-data",
    )


def _make_doc(client, token, **kw):
    return _upload(client, token, **kw).get_json()["id"]


def test_owner_can_upload_and_download(client):
    alice = token_for(client, *ALICE)
    doc_id = _make_doc(client, alice)
    r = client.get(f"/api/documents/{doc_id}/download", headers=auth(alice))
    assert r.status_code == 200
    assert r.data == b"hidden text"
    assert "attachment" in r.headers["Content-Disposition"]


def test_content_is_encrypted_in_database(app, client):
    from app.db import get_db
    alice = token_for(client, *ALICE)
    doc_id = _make_doc(client, alice, content=b"plaintext-marker")
    with app.app_context():
        row = get_db().execute(
            "SELECT content_encrypted FROM documents WHERE id = ?", (doc_id,)
        ).fetchone()
    assert b"plaintext-marker" not in bytes(row["content_encrypted"])


def test_idor_other_user_gets_404_on_download(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    doc_id = _make_doc(client, alice)
    assert client.get(f"/api/documents/{doc_id}/download", headers=auth(bob)).status_code == 404


def test_idor_other_user_cannot_delete(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    doc_id = _make_doc(client, alice)
    assert client.delete(f"/api/documents/{doc_id}", headers=auth(bob)).status_code == 404
    assert client.get(f"/api/documents/{doc_id}/download", headers=auth(alice)).status_code == 200


def test_admin_cannot_read_user_document(client):
    alice = token_for(client, *ALICE)
    admin = token_for(client, *ADMIN)
    doc_id = _make_doc(client, alice)
    assert client.get(f"/api/documents/{doc_id}/download", headers=auth(admin)).status_code == 404


def test_idor_attempt_is_audited(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    admin = token_for(client, *ADMIN)
    doc_id = _make_doc(client, alice)
    client.get(f"/api/documents/{doc_id}/download", headers=auth(bob))
    events = client.get("/api/admin/audit", headers=auth(admin)).get_json()["events"]
    assert any(e["action"] == f"idor_attempt:document:{doc_id}" for e in events)


def test_share_grants_read_access_and_unshare_revokes(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    doc_id = _make_doc(client, alice)
    r = client.post(f"/api/documents/{doc_id}/shares", headers=auth(alice), json={"username": "bob"})
    assert r.status_code == 201
    assert client.get(f"/api/documents/{doc_id}/download", headers=auth(bob)).status_code == 200
    listed = client.get("/api/documents", headers=auth(bob)).get_json()["documents"]
    assert [d["id"] for d in listed] == [doc_id] and listed[0]["owned"] is False

    bob_id = client.get("/api/me", headers=auth(bob)).get_json()["id"]
    assert client.delete(f"/api/documents/{doc_id}/shares/{bob_id}", headers=auth(alice)).status_code == 200
    assert client.get(f"/api/documents/{doc_id}/download", headers=auth(bob)).status_code == 404


def test_shared_user_cannot_delete_or_reshare(client):
    alice = token_for(client, *ALICE)
    bob = token_for(client, *BOB)
    doc_id = _make_doc(client, alice)
    client.post(f"/api/documents/{doc_id}/shares", headers=auth(alice), json={"username": "bob"})
    assert client.delete(f"/api/documents/{doc_id}", headers=auth(bob)).status_code == 404
    r = client.post(f"/api/documents/{doc_id}/shares", headers=auth(bob), json={"username": "admin1"})
    assert r.status_code == 404


def test_duplicate_share_and_self_share_rejected(client):
    alice = token_for(client, *ALICE)
    doc_id = _make_doc(client, alice)
    assert client.post(f"/api/documents/{doc_id}/shares", headers=auth(alice), json={"username": "alice"}).status_code == 400
    assert client.post(f"/api/documents/{doc_id}/shares", headers=auth(alice), json={"username": "bob"}).status_code == 201
    assert client.post(f"/api/documents/{doc_id}/shares", headers=auth(alice), json={"username": "bob"}).status_code == 409


def test_disallowed_extension_rejected(client):
    alice = token_for(client, *ALICE)
    assert _upload(client, alice, filename="evil.exe").status_code == 400


def test_path_traversal_filename_is_sanitized(client):
    alice = token_for(client, *ALICE)
    doc_id = _make_doc(client, alice, filename="../../etc/passwd.txt")
    r = client.get(f"/api/documents/{doc_id}/download", headers=auth(alice))
    assert ".." not in r.headers["Content-Disposition"] and "/" not in r.headers["Content-Disposition"].split("filename=")[-1]


def test_oversized_file_rejected(client):
    alice = token_for(client, *ALICE)
    assert _upload(client, alice, content=b"x" * (1024 * 1024 + 1)).status_code == 413


def test_empty_file_rejected(client):
    alice = token_for(client, *ALICE)
    assert _upload(client, alice, content=b"").status_code == 400


def test_documents_require_login(client):
    assert client.get("/api/documents").status_code == 401
    assert client.get("/api/documents/1/download").status_code == 401
