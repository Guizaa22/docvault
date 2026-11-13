# Vulnerability register

Each flaw is documented **before** it is fixed: where it is, why it exists, what it allows.
Flaws are planted deliberately, one commit each, with the message prefix `intentional-vuln:`.
References use **OWASP Top 10:2025** (the edition in force). Evidence (screenshots, logs) goes in `docs/evidence/`.

| ID | Flaw | OWASP 2025 | CWE | Status |
|----|------|-----------|-----|--------|
| V1 | SQL injection in document search | A05 Injection | CWE-89 | Planted, not fixed |
| V2 | IDOR on document download | A01 Broken Access Control | CWE-639 | Planned |
| V3 | Hardcoded secret in source | A02 Security Misconfiguration / A04 Cryptographic Failures | CWE-798 | Planned |
| V4 | Vulnerable dependency | A03 Software Supply Chain Failures | CWE-1395 | Planned |
| V5 | Debug mode / verbose errors | A02 Security Misconfiguration | CWE-489 | Planned |

---

## V1: SQL injection in document search

- **Where:** `app/app/documents.py`, function `search_documents()` (`GET /api/documents/search?q=`).
- **Cause:** the search term `q` is concatenated into the SQL string instead of being passed as a bound
  parameter (`... LIKE '%%" + q + "%%'`). Every other query in the app uses `?` placeholders; this one does not.
- **Impact:** any logged-in user can change the meaning of the query. With a `UNION SELECT` they read any
  table the database account can read, for example every user's name, role and password hash, then crack
  the hashes offline. The single-statement execution of the database driver prevents stacked queries
  (`; DROP TABLE ...`), so the impact here is data disclosure rather than data destruction.
- **Exploitation (own instance only):**
  ```bash
  TOK=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login \
        -H 'Content-Type: application/json' \
        -d '{"username":"alice","password":"correct-horse-battery"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  curl -s -G http://127.0.0.1:5000/api/documents/search -H "Authorization: Bearer $TOK" \
       --data-urlencode "q=' UNION SELECT id, username, password_hash, 0, role FROM users --"
  ```
  Result observed: one row per user, with the username in `title` and the argon2 hash in `filename`.
- **Detection plan:** Semgrep (SAST) in the pipeline, ZAP active scan (DAST), and the audit log.
- **Planned fix:** bound parameter (`LIKE ?` with `'%' || ? || '%'` or the value wrapped in Python), plus input
  length limit. The regression test `tests/test_search.py::test_search_is_not_injectable` already encodes the
  secure behaviour (currently `xfail(strict=True)`; remove the marker when the fix lands).
- **Evidence:** TODO screenshot of the UNION result in `docs/evidence/v1-sqli-before.png`.
