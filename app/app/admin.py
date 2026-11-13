from flask import Blueprint, g, jsonify, request

from .audit import log_event
from .db import get_db
from .security import admin_required

bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@bp.get("/users")
@admin_required
def list_users():
    rows = get_db().execute(
        "SELECT id, username, role, is_locked, created_at FROM users ORDER BY id"
    ).fetchall()
    return jsonify(users=[dict(r) for r in rows])


def _set_lock(user_id, locked):
    if locked and user_id == g.user["id"]:
        return jsonify(error="You cannot lock your own account"), 400
    db = get_db()
    cur = db.execute(
        "UPDATE users SET is_locked = ?, failed_attempts = 0 WHERE id = ?",
        (int(locked), user_id),
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="User not found"), 404
    log_event(f"{'lock' if locked else 'unlock'}_user:{user_id}", g.user["id"])
    return jsonify(message="Account locked" if locked else "Account unlocked"), 200


@bp.post("/users/<int:user_id>/lock")
@admin_required
def lock_user(user_id):
    return _set_lock(user_id, True)


@bp.post("/users/<int:user_id>/unlock")
@admin_required
def unlock_user(user_id):
    return _set_lock(user_id, False)


@bp.put("/users/<int:user_id>/role")
@admin_required
def set_role(user_id):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ("user", "admin"):
        return jsonify(error="Role must be 'user' or 'admin'"), 400
    if user_id == g.user["id"]:
        return jsonify(error="You cannot change your own role"), 400
    db = get_db()
    cur = db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="User not found"), 404
    log_event(f"set_role:{user_id}:{role}", g.user["id"])
    return jsonify(message=f"Role set to {role}"), 200


@bp.get("/audit")
@admin_required
def audit():
    rows = get_db().execute(
        "SELECT id, user_id, action, ip, created_at FROM audit_log "
        "ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return jsonify(events=[dict(r) for r in rows])
