"""Credentials and helpers for the third-party backup service.

V3 (hardcoded secret, CWE-798, OWASP A07:2025) was fixed here: the API key is
no longer in the source code. It is read from the BACKUP_SERVICE_API_KEY
environment variable at call time, and the job fails loudly if it is missing.
The key committed earlier is considered burned (revoked first), see
docs/vulnerabilities.md for the rotation record.
"""
import os

BACKUP_SERVICE_URL = "https://backup.docvault.invalid/v1/documents"


def backup_headers():
    key = os.environ.get("BACKUP_SERVICE_API_KEY")
    if not key:
        raise RuntimeError("Missing required secret: BACKUP_SERVICE_API_KEY")
    return {"Authorization": f"Bearer {key}"}
