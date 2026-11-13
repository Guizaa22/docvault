"""Documents: upload, list, download, delete and share files.

Secure reference version. Every query that touches a document is scoped to the
caller: the owner, or a user the owner explicitly shared it with. File contents
are encrypted (Fernet) before they reach the database.
"""
import io
import mimetypes
import os

from cryptography.fernet import InvalidToken
from flask import Blueprint, g, jsonify, request, send_file
from werkzeug.utils import secure_filename

from .audit import log_event
from .crypto import decrypt_bytes, encrypt_bytes
from .db import get_db, insert_returning_id, integrity_errors
from .security import login_required

bp = Blueprint("documents", __name__, url_prefix="/api")

MAX_FILE_BYTES = 1024 * 1024  # 1 MB per document
ALLOWED_EXTENSIONS = {".txt", ".md", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".docx"}


def _not_found(doc_id):
    # Same 404 whether the document is missing or belongs to someone else,
    # but record the second case: it is an access-control probe.
    exists = get_db().execute("SELECT 1 FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if exists:
        log_event(f"idor_attempt:document:{doc_id}", g.user["id"])
    return jsonify(error="Document not found"), 404


def _load_accessible(doc_id):
    """The document, only if the caller owns it or it was shared with them."""
    return get_db().execute(
        "SELECT d.id, d.owner_id, d.title, d.filename, d.mime_type, d.size, "
        "d.content_encrypted, d.created_at FROM documents d "
        "WHERE d.id = ? AND (d.owner_id = ? OR EXISTS "
        "(SELECT 1 FROM shares s WHERE s.document_id = d.id AND s.user_id = ?))",
        (doc_id, g.user["id"], g.user["id"]),
    ).fetchone()


def _load_owned(doc_id):
    return get_db().execute(
        "SELECT id FROM documents WHERE id = ? AND owner_id = ?",
        (doc_id, g.user["id"]),
    ).fetchone()


@bp.get("/documents")
@login_required
def list_documents():
    rows = get_db().execute(
        "SELECT d.id, d.title, d.filename, d.size, d.created_at, d.owner_id, "
        "u.username AS owner FROM documents d JOIN users u ON u.id = d.owner_id "
        "WHERE d.owner_id = ? OR d.id IN "
        "(SELECT document_id FROM shares WHERE user_id = ?) ORDER BY d.id",
        (g.user["id"], g.user["id"]),
    ).fetchall()
    documents = []
    for r in rows:
        item = dict(r)
        item["owned"] = item.pop("owner_id") == g.user["id"]
        documents.append(item)
    return jsonify(documents=documents)


@bp.post("/documents")
@login_required
def upload_document():
    file = request.files.get("file")
    if file is None or not file.filename:
        return jsonify(error="A file is required"), 400
    filename = secure_filename(file.filename)
    if os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
        return jsonify(error="File type not allowed"), 400
    data = file.read(MAX_FILE_BYTES + 1)
    if not data:
        return jsonify(error="File is empty"), 400
    if len(data) > MAX_FILE_BYTES:
        return jsonify(error="File too large (max 1 MB)"), 413
    title = (request.form.get("title") or filename).strip()
    if not 1 <= len(title) <= 100:
        return jsonify(error="Title must be 1 to 100 characters"), 400
    mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    db = get_db()
    new_id = insert_returning_id(
        db,
        "INSERT INTO documents (owner_id, title, filename, mime_type, size, content_encrypted) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["id"], title, filename, mime, len(data), encrypt_bytes(data)),
    )
    db.commit()
    log_event(f"document_upload:{new_id}", g.user["id"])
    return jsonify(id=new_id, message="Document uploaded"), 201


@bp.get("/documents/search")
@login_required
def search_documents():
    """Search the caller's own documents by title."""
    q = request.args.get("q", "")
    # INTENTIONAL VULNERABILITY V1 (SQL injection, CWE-89, OWASP A05:2025).
    # The search term is concatenated into the SQL string instead of being
    # passed as a bound parameter. Fixed in the remediation step.
    sql = (
        "SELECT id, title, filename, size, created_at FROM documents "
        "WHERE owner_id = ? AND title LIKE '%%" + q + "%%'"
    )
    rows = get_db().execute(sql, (g.user["id"],)).fetchall()
    return jsonify(documents=[dict(r) for r in rows])


@bp.get("/documents/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    # INTENTIONAL VULNERABILITY V2 (IDOR / broken access control, CWE-639,
    # OWASP A01:2025). The document is loaded by id only: nothing checks that the
    # caller owns it or that it was shared with them. The secure version is
    # _load_accessible(doc_id) + _not_found(doc_id). Fixed in the remediation step.
    row = get_db().execute(
        "SELECT id, owner_id, title, filename, mime_type, size, content_encrypted, "
        "created_at FROM documents WHERE id = ?",
        (doc_id,),
    ).fetchone()
    if row is None:
        return jsonify(error="Document not found"), 404
    try:
        data = decrypt_bytes(bytes(row["content_encrypted"]))
    except InvalidToken:
        log_event(f"document_integrity_failure:{doc_id}", g.user["id"])
        return jsonify(error="Document could not be decrypted"), 500
    log_event(f"document_download:{doc_id}", g.user["id"])
    return send_file(
        io.BytesIO(data),
        mimetype=row["mime_type"],
        as_attachment=True,
        download_name=row["filename"],
    )


@bp.delete("/documents/<int:doc_id>")
@login_required
def delete_document(doc_id):
    db = get_db()
    cur = db.execute(
        "DELETE FROM documents WHERE id = ? AND owner_id = ?", (doc_id, g.user["id"])
    )
    db.commit()
    if cur.rowcount == 0:
        return _not_found(doc_id)
    log_event(f"document_delete:{doc_id}", g.user["id"])
    return jsonify(message="Document deleted"), 200


@bp.get("/documents/<int:doc_id>/shares")
@login_required
def list_shares(doc_id):
    if _load_owned(doc_id) is None:
        return _not_found(doc_id)
    rows = get_db().execute(
        "SELECT u.id, u.username FROM shares s JOIN users u ON u.id = s.user_id "
        "WHERE s.document_id = ? ORDER BY u.username",
        (doc_id,),
    ).fetchall()
    return jsonify(shares=[dict(r) for r in rows])


@bp.post("/documents/<int:doc_id>/shares")
@login_required
def share_document(doc_id):
    if _load_owned(doc_id) is None:
        return _not_found(doc_id)
    username = (request.get_json(silent=True) or {}).get("username")
    if not isinstance(username, str) or not username:
        return jsonify(error="username is required"), 400
    db = get_db()
    target = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if target is None:
        return jsonify(error="User not found"), 404
    if target["id"] == g.user["id"]:
        return jsonify(error="You already own this document"), 400
    try:
        db.execute(
            "INSERT INTO shares (document_id, user_id) VALUES (?, ?)",
            (doc_id, target["id"]),
        )
        db.commit()
    except integrity_errors():
        db.rollback()
        return jsonify(error="Already shared with this user"), 409
    log_event(f"document_share:{doc_id}:{target['id']}", g.user["id"])
    return jsonify(message="Document shared"), 201


@bp.delete("/documents/<int:doc_id>/shares/<int:user_id>")
@login_required
def unshare_document(doc_id, user_id):
    if _load_owned(doc_id) is None:
        return _not_found(doc_id)
    db = get_db()
    cur = db.execute(
        "DELETE FROM shares WHERE document_id = ? AND user_id = ?", (doc_id, user_id)
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="Share not found"), 404
    log_event(f"document_unshare:{doc_id}:{user_id}", g.user["id"])
    return jsonify(message="Share removed"), 200
