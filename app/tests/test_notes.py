from conftest import auth, token_for


def _make_note(client, token, title="Secret", content="hidden text"):
    r = client.post("/api/notes", headers=auth(token),
                    json={"title": title, "content": content})
    return r.get_json()["id"]


def test_owner_can_read_note(client):
    alice = token_for(client, "alice", "correct-horse-battery")
    note_id = _make_note(client, alice)
    r = client.get(f"/api/notes/{note_id}", headers=auth(alice))
    assert r.status_code == 200
    assert r.get_json()["content"] == "hidden text"


def test_idor_other_user_gets_404(client):
    # T6: Bob must not read Alice's note
    alice = token_for(client, "alice", "correct-horse-battery")
    bob = token_for(client, "bob", "another-long-password")
    note_id = _make_note(client, alice)
    assert client.get(f"/api/notes/{note_id}", headers=auth(bob)).status_code == 404


def test_idor_other_user_cannot_delete(client):
    alice = token_for(client, "alice", "correct-horse-battery")
    bob = token_for(client, "bob", "another-long-password")
    note_id = _make_note(client, alice)
    assert client.delete(f"/api/notes/{note_id}", headers=auth(bob)).status_code == 404
    # The note must still be readable by Alice
    assert client.get(f"/api/notes/{note_id}", headers=auth(alice)).status_code == 200


def test_admin_cannot_read_user_note(client):
    # Least privilege: admins have no note access
    alice = token_for(client, "alice", "correct-horse-battery")
    admin = token_for(client, "admin1", "admin-strong-password-2026")
    note_id = _make_note(client, alice)
    assert client.get(f"/api/notes/{note_id}", headers=auth(admin)).status_code == 404


def test_signed_export_verifies(client):
    import base64, json
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    alice = token_for(client, "alice", "correct-horse-battery")
    note_id = _make_note(client, alice, content="verify me")
    export = client.get(f"/api/notes/{note_id}/export", headers=auth(alice)).get_json()

    pub = client.get("/api/public-key").get_json()["public_key"]
    key = load_pem_public_key(pub.encode())
    canonical = json.dumps(export["document"], sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode()
    # Must not raise
    key.verify(base64.b64decode(export["signature"]), canonical)


def test_tampered_export_fails_verification(client):
    import base64, json
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    alice = token_for(client, "alice", "correct-horse-battery")
    note_id = _make_note(client, alice, content="original")
    export = client.get(f"/api/notes/{note_id}/export", headers=auth(alice)).get_json()
    export["document"]["content"] = "tampered"

    pub = client.get("/api/public-key").get_json()["public_key"]
    key = load_pem_public_key(pub.encode())
    canonical = json.dumps(export["document"], sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False).encode()
    try:
        key.verify(base64.b64decode(export["signature"]), canonical)
        assert False, "tampered document should not verify"
    except InvalidSignature:
        pass
