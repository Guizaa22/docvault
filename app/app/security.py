from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from .audit import log_event
from .db import get_db
from .jwt_keys import public_key

GENERIC_ERROR = "Invalid or expired token"


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Authentication required"), 401
        token = header[len("Bearer "):]

        try:
            claims = jwt.decode(
                token,
                public_key(),
                algorithms=["ES256"],
                options={"require": ["exp", "iat", "sub", "jti"]},
            )
        except jwt.InvalidTokenError:
            return jsonify(error=GENERIC_ERROR), 401

        db = get_db()
        revoked = db.execute(
            "SELECT 1 FROM revoked_tokens WHERE jti = ?", (claims["jti"],)
        ).fetchone()
        if revoked:
            return jsonify(error=GENERIC_ERROR), 401

        user = db.execute(
            "SELECT id, username, role, is_locked FROM users WHERE id = ?",
            (int(claims["sub"]),),
        ).fetchone()
        if user is None or user["is_locked"]:
            return jsonify(error=GENERIC_ERROR), 401

        g.user = user
        g.claims = claims
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if g.user["role"] != "admin":
            log_event("admin_access_denied", g.user["id"])
            return jsonify(error="Forbidden"), 403
        return f(*args, **kwargs)
    return wrapper
