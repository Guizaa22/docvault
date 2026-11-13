import hashlib
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Blueprint, current_app, g, jsonify, request

from .audit import log_event
from .db import get_db, insert_returning_id, integrity_errors
from .security import login_required
from .jwt_keys import private_key, kid

bp = Blueprint("auth", __name__, url_prefix="/api/auth")
ph = PasswordHasher()

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
DUMMY_HASH = ph.hash("dummy-password-for-timing")
MAX_FAILED_ATTEMPTS = 5
REFRESH_TTL_DAYS = 7


def _make_access_token(user_id):
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {
            "sub": str(user_id),
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=15),
        },
        private_key(),
        algorithm="ES256",
        headers={"kid": kid()},
    )


def _hash_token(raw):
    # High-entropy random token: a fast cryptographic hash is appropriate
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _issue_refresh_token(db, user_id):
    raw = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(days=REFRESH_TTL_DAYS)).isoformat()
    db.execute(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
        (user_id, _hash_token(raw), expires),
    )
    db.commit()
    return raw


@bp.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return jsonify(error="Username must be 3-32 letters, digits or _"), 400
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return jsonify(error="Password must be 12 to 128 characters"), 400

    db = get_db()
    try:
        new_id = insert_returning_id(
            db,
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, ph.hash(password)),
        )
        db.commit()
    except integrity_errors():
        db.rollback()
        return jsonify(error="Username already taken"), 409

    log_event("register", new_id)
    return jsonify(message="Account created"), 201


@bp.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify(error="Invalid credentials"), 401

    db = get_db()
    user = db.execute(
        "SELECT id, password_hash, is_locked, failed_attempts FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    try:
        ph.verify(user["password_hash"] if user else DUMMY_HASH, password)
    except VerifyMismatchError:
        if user is not None:
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                db.execute(
                    "UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE id = ?",
                    (attempts, user["id"]),
                )
                log_event("account_locked_bruteforce", user["id"])
            else:
                db.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (attempts, user["id"]),
                )
            db.commit()
            log_event("login_failed", user["id"])
        else:
            log_event("login_failed")
        return jsonify(error="Invalid credentials"), 401

    if user is None:
        log_event("login_failed")
        return jsonify(error="Invalid credentials"), 401

    if user["is_locked"]:
        log_event("login_blocked_locked", user["id"])
        return jsonify(error="Account locked, contact an administrator"), 403

    db.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
    db.commit()

    access = _make_access_token(user["id"])
    refresh = _issue_refresh_token(db, user["id"])
    log_event("login_success", user["id"])
    return jsonify(access_token=access, refresh_token=refresh), 200


@bp.post("/refresh")
def refresh():
    data = request.get_json(silent=True) or {}
    raw = data.get("refresh_token", "")
    if not isinstance(raw, str) or not raw:
        return jsonify(error="Invalid refresh token"), 401

    db = get_db()
    row = db.execute(
        "SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash = ?",
        (_hash_token(raw),),
    ).fetchone()
    if row is None or row["revoked"]:
        return jsonify(error="Invalid refresh token"), 401
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        return jsonify(error="Invalid refresh token"), 401

    user = db.execute(
        "SELECT id, is_locked FROM users WHERE id = ?", (row["user_id"],)
    ).fetchone()
    if user is None or user["is_locked"]:
        return jsonify(error="Invalid refresh token"), 401

    # Rotation: revoke the used token, issue a fresh one (detects reuse/theft)
    db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?", (row["id"],))
    db.commit()
    new_refresh = _issue_refresh_token(db, user["id"])
    access = _make_access_token(user["id"])
    log_event("token_refresh", user["id"])
    return jsonify(access_token=access, refresh_token=new_refresh), 200


@bp.post("/logout")
@login_required
def logout():
    expires = datetime.fromtimestamp(g.claims["exp"], timezone.utc).isoformat()
    db = get_db()
    db.execute(
        "INSERT INTO revoked_tokens (jti, expires_at) VALUES (?, ?) ON CONFLICT DO NOTHING",
        (g.claims["jti"], expires),
    )
    # Also revoke the user's refresh tokens
    db.execute(
        "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0",
        (g.user["id"],),
    )
    db.commit()
    log_event("logout", g.user["id"])
    return jsonify(message="Logged out"), 200
