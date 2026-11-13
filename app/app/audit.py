from flask import request

from .db import get_db


def log_event(action, user_id=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, action, ip) VALUES (?, ?, ?)",
        (user_id, action, request.remote_addr),
    )
    db.commit()
