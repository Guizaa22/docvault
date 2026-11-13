"""Seed three demo accounts if they do not already exist.
DEMO ONLY — remove or guard behind an env flag before any real deployment."""
from argon2 import PasswordHasher

from app import create_app
from app.db import get_db

ph = PasswordHasher()
DEMO = [
    ("alice",  "correct-horse-battery",      "user"),
    ("bob",    "another-long-password",      "user"),
    ("admin1", "admin-strong-password-2026", "admin"),
]

app = create_app()
with app.app_context():
    db = get_db()
    have = {r["username"] for r in db.execute("SELECT username FROM users").fetchall()}
    for username, password, role in DEMO:
        if username not in have:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, ph.hash(password), role),
            )
    db.commit()
print("Demo users seeded.")
