"""Credentials and helpers for the third-party backup service.

INTENTIONAL VULNERABILITY V3 (hardcoded secret, CWE-798, OWASP A07:2025).
The API key below is committed in the source code. It is a FAKE value made up
for this school project (the host is the reserved .invalid domain, so no real
service exists), but it is shaped like a real production key on purpose.
Fixed in the remediation step: the key moves to a runtime secret.
"""

BACKUP_SERVICE_URL = "https://backup.docvault.invalid/v1/documents"
BACKUP_SERVICE_API_KEY = "dvk_live_7Hq3ZxK9mWcT2vRb8LdYp5NfJ4sGa6UeXo1Ci0Vh"


def backup_headers():
    return {"Authorization": f"Bearer {BACKUP_SERVICE_API_KEY}"}
