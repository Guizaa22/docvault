# Vulnerability register

Each flaw is documented **before** it is fixed: where it is, why it exists, what it allows.
Flaws are planted deliberately, one commit each, with the message prefix `intentional-vuln:`.
References use **OWASP Top 10:2025** (the edition in force). Evidence (screenshots, logs) goes in `docs/evidence/`.

| ID | Flaw | OWASP 2025 | CWE | Status |
|----|------|-----------|-----|--------|
| V1 | SQL injection in document search | A05 Injection | CWE-89 | Planted, not fixed |
| V2 | IDOR on document download | A01 Broken Access Control | CWE-639 | Planted, not fixed |
| V3 | Hardcoded secret in source | A07 Authentication Failures | CWE-798 | Planted, not fixed |
| V4 | Vulnerable dependency | A03 Software Supply Chain Failures | CWE-1395 | Planted |
| V5 | Debug mode / verbose errors | A02 Security Misconfiguration | CWE-489, CWE-209 | Planted |

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

---

## V2: IDOR (broken access control) on document download

- **Where:** `app/app/documents.py`, function `download_document()` (`GET /api/documents/<id>/download`).
- **Cause:** the document is loaded with `WHERE id = ?` only. Nothing checks that the caller owns it or that it was
  shared with them. The secure reference is still in the file: `_load_accessible(doc_id)` scopes the query to
  the owner or a shared user, and `_not_found()` logs the probe. The flawed endpoint simply does not call them.
  Document ids are small sequential integers, which makes guessing trivial.
- **Impact:** any authenticated user, including a freshly registered one, reads every user's documents by trying
  ids 1, 2, 3... The server decrypts the content for them, so encryption at rest does not help: the access
  control decision is the only protection. Admins are not special here: the same hole exposes the admin's files.
  No audit event is written, so the attack is silent.
- **Exploitation (own instance only):**
  ```bash
  # bob was never given access to alice's document 1
  BOB=$(curl -s -X POST http://127.0.0.1:5000/api/auth/login -H 'Content-Type: application/json' \
        -d '{"username":"bob","password":"another-long-password"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
  for id in 1 2 3 4 5; do curl -s -o /dev/null -w "id=$id -> %{http_code}\n" \
        http://127.0.0.1:5000/api/documents/$id/download -H "Authorization: Bearer $BOB"; done
  ```
  Result observed: `200` and the file content, instead of `404`.
- **Detection plan:** ZAP authenticated scan with two users (access-control checks), code review/SAST rule for
  queries without an owner filter, and the `idor_attempt:document:<id>` audit event once fixed.
- **Planned fix:** restore `_load_accessible(doc_id)` and `_not_found(doc_id)`. Four tests already encode the
  secure behaviour (`xfail(strict=True)`; remove the markers when the fix lands).
- **Evidence:** TODO screenshot/log of bob receiving `200` in `docs/evidence/v2-idor-before.png`.

---

## V3: Hardcoded secret in source code

- **Where:** `app/app/integrations.py`, constant `BACKUP_SERVICE_API_KEY` (used by `app/scripts/backup_documents.py`).
- **Cause:** the API key of the third-party backup service is written directly in the source and committed. Anyone
  with read access to the repository (or to any clone, fork, CI log or image layer built from it) has the key.
  The value is **fake**, made up for this project: the service host is the reserved `.invalid` domain, so no real
  system is involved. It is shaped like a production key on purpose so scanners treat it as real.
- **Impact:** an attacker who reads the repository can authenticate to the backup service as DocVault and read or
  overwrite backups. Because the key lives in version control, **deleting it from the code later does not remove
  it**: it stays in the git history. A hardcoded secret also cannot be rotated without a code change and redeploy.
- **Exploitation (own instance only):** no attack needed beyond reading the file:
  ```bash
  git grep -n "BACKUP_SERVICE_API_KEY" -- app/app/integrations.py
  # secret scanner view (this is also how the pipeline will catch it):
  gitleaks detect --source . --redact -v
  ```
  Result observed: Gitleaks rule `generic-api-key` reports `app/app/integrations.py:11`.
- **Detection plan:** Gitleaks in the pipeline (blocking), plus a history scan. Semgrep may also flag the literal.
- **Planned fix (requirement 4.4):** read the key at runtime from an environment variable / secret store, fail at
  startup if missing, and add a pre-commit/CI secret scan. Then run the incident procedure **revoke first, purge
  after**: (1) rotate the key at the service so the leaked value is dead, (2) only then rewrite git history
  (`git filter-repo`) and force-push, (3) re-scan the whole history to prove it is clean.
- **Evidence:** TODO Gitleaks output in `docs/evidence/v3-gitleaks-before.txt`.


---

## V4: Vulnerable dependency (gunicorn 21.2.0)

- **Where:** `app/requirements.txt`, line `gunicorn==21.2.0`. Gunicorn is the production WSGI server started by the
  Dockerfile `CMD`, so the vulnerable code runs in every deployed container and faces the network directly.
- **Cause:** the dependency is pinned to an old release with known CVEs instead of a maintained version. Nobody
  scans or updates it, which is the typical supply-chain failure.
- **Known issues (fixed in 22.0.0):** CVE-2024-1135 (HTTP request smuggling through improper `Transfer-Encoding`
  validation, High 7.5) and CVE-2024-6827 (request smuggling via `Transfer-Encoding: chunked` handling, High 7.5);
  `pip-audit` lists them as PYSEC-2026-1433 and PYSEC-2026-1434.
- **Impact:** when gunicorn sits behind a proxy or ingress, a crafted request can be interpreted differently by the
  two components. That allows bypassing front-end access rules, poisoning shared connections and reaching routes
  that should be blocked.
- **Exploitation:** not exploited here. The finding is proven by scanning, which is how the pipeline sees it:
  ```bash
  pip-audit -r app/requirements.txt --no-deps --disable-pip
  ```
- **Detection plan:** dependency scan (pip-audit and Trivy `fs`) plus Trivy on the built image, both blocking.
  Policy: fail on Critical, or on High when a fixed version exists (see `docs/blocking-policy.md`).
- **Planned fix:** upgrade to `gunicorn>=22.0.0`, then re-run the scans to prove the finding is gone. Longer term,
  pin with hashes and enable automated update PRs.
- **Evidence:** TODO `docs/evidence/v4-pip-audit-before.txt`.

---

## V5: Debug mode and verbose error messages

- **Where:** `app/app/__init__.py`, the `500` error handler (debug output is **on by default**, switch
  `DOCVAULT_DEBUG`), and `app/run.py` (`app.run(debug=True)` starts the Werkzeug debugger when run directly).
- **Cause:** insecure default. Unless someone remembers to turn it off, any unhandled exception returns the
  exception type, its message, the full stack trace and the database path to the caller.
- **Impact:** information disclosure that helps every other attack: file paths and code structure, library
  versions, SQL fragments and error text (which makes SQL injection like V1 much easier to tune). With the
  Werkzeug debugger exposed, a console PIN is the only barrier to remote code execution.
- **Exploitation (own instance only):** send a lone quote to the search box (this also shows how V1 and V5
  reinforce each other: the SQL error text reveals the query structure). Replace `$TOKEN` with a login token:
  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" "http://localhost:5000/api/documents/search?q='"
  ```
  Observed: HTTP 500 whose JSON body contains `"trace"`, source file paths and the SQLite error text.
- **Detection plan:** ZAP active scan (information disclosure, application error disclosure) in the authenticated
  DAST step, Semgrep rule for `debug=True`, and Kubernetes review of environment values.
- **Planned fix:** return a generic message plus a correlation id, log the details server side only, default
  `DOCVAULT_DEBUG` to off, remove `debug=True` from `run.py`, and send logs to Loki. The strict xfail test
  `test_server_error_does_not_leak_details` flips when this lands.
- **Evidence:** TODO `docs/evidence/v5-verbose-error-before.txt` (curl output).
