from datetime import datetime, timezone

from cryptography.fernet import InvalidToken
from flask import Blueprint, g, jsonify, request

from .audit import log_event
from .crypto import decrypt, encrypt
from .db import get_db, insert_returning_id
from .security import login_required
from .signing import sign

bp = Blueprint("notes", __name__, url_prefix="/api")


def _read_input():
    data = request.get_json(silent=True) or {}
    title, content = data.get("title"), data.get("content")
    if not isinstance(title, str) or not 1 <= len(title) <= 100:
        return None, "Title must be 1 to 100 characters"
    if not isinstance(content, str) or not 1 <= len(content) <= 5000:
        return None, "Content must be 1 to 5000 characters"
    return (title, content), None


def _not_found(note_id):
    # Same 404 either way, but log it if the note belongs to someone else
    exists = get_db().execute("SELECT 1 FROM notes WHERE id = ?", (note_id,)).fetchone()
    if exists:
        log_event(f"idor_attempt:note:{note_id}", g.user["id"])
    return jsonify(error="Note not found"), 404


def _load_own_note(note_id):
    return get_db().execute(
        "SELECT id, title, content_encrypted, created_at FROM notes "
        "WHERE id = ? AND owner_id = ?",
        (note_id, g.user["id"]),
    ).fetchone()


def _integrity_error(note_id):
    log_event(f"note_integrity_failure:{note_id}", g.user["id"])
    return jsonify(error="Note could not be decrypted"), 500


@bp.get("/notes")
@login_required
def list_notes():
    rows = get_db().execute(
        "SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id",
        (g.user["id"],),
    ).fetchall()
    return jsonify(notes=[dict(r) for r in rows])


@bp.post("/notes")
@login_required
def create_note():
    fields, error = _read_input()
    if error:
        return jsonify(error=error), 400
    title, content = fields
    db = get_db()
    new_id = insert_returning_id(
        db,
        "INSERT INTO notes (owner_id, title, content_encrypted) VALUES (?, ?, ?)",
        (g.user["id"], title, encrypt(content)),
    )
    db.commit()
    return jsonify(id=new_id, message="Note created"), 201


@bp.get("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    row = _load_own_note(note_id)
    if row is None:
        return _not_found(note_id)
    try:
        content = decrypt(row["content_encrypted"])
    except InvalidToken:
        return _integrity_error(note_id)
    return jsonify(
        id=row["id"], title=row["title"], content=content, created_at=row["created_at"]
    )


@bp.put("/notes/<int:note_id>")
@login_required
def update_note(note_id):
    fields, error = _read_input()
    if error:
        return jsonify(error=error), 400
    title, content = fields
    db = get_db()
    cur = db.execute(
        "UPDATE notes SET title = ?, content_encrypted = ? WHERE id = ? AND owner_id = ?",
        (title, encrypt(content), note_id, g.user["id"]),
    )
    db.commit()
    if cur.rowcount == 0:
        return _not_found(note_id)
    return jsonify(message="Note updated"), 200


@bp.delete("/notes/<int:note_id>")
@login_required
def delete_note(note_id):
    db = get_db()
    cur = db.execute(
        "DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, g.user["id"])
    )
    db.commit()
    if cur.rowcount == 0:
        return _not_found(note_id)
    return jsonify(message="Note deleted"), 200


@bp.get("/notes/<int:note_id>/export")
@login_required
def export_note(note_id):
    row = _load_own_note(note_id)
    if row is None:
        return _not_found(note_id)
    try:
        content = decrypt(row["content_encrypted"])
    except InvalidToken:
        return _integrity_error(note_id)
    document = {
        "id": row["id"],
        "title": row["title"],
        "content": content,
        "owner": g.user["username"],
        "created_at": row["created_at"],
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    log_event(f"note_export:{note_id}", g.user["id"])
    return jsonify(document=document, signature=sign(document), algorithm="Ed25519")
