"""Send the encrypted documents to the backup service (nightly job).

The service host is fake (.invalid), so this only prints what it would send.
"""
from app import create_app
from app.db import get_db
from app.integrations import BACKUP_SERVICE_URL, backup_headers

app = create_app()
with app.app_context():
    rows = get_db().execute("SELECT id, filename, size FROM documents ORDER BY id").fetchall()
    for r in rows:
        print(f"POST {BACKUP_SERVICE_URL}/{r['id']}  ({r['filename']}, {r['size']} bytes)  headers={sorted(backup_headers())}")
print(f"{len(rows)} document(s) would be backed up.")
