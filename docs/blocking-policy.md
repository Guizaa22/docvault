# Blocking policy (requirement 4)

The pipeline (`.github/workflows/ci.yml`) has one **required status check**, `security gate`. It is green only when
every job below succeeded. A red job means the change cannot be merged to `main`. Nobody bypasses it by editing a
threshold: accepting a risk needs a written entry (see "Exceptions").

## What blocks, and why

| # | Control | Tool | Blocks when | Why this threshold |
|---|---|---|---|---|
| 1 | SAST | Semgrep (custom DocVault rules, `p/flask`, `p/owasp-top-ten`) | any finding of severity ERROR or WARNING | These are code patterns that are almost always real defects (string-built SQL, debug mode). INFO is reported but does not block, to avoid alert fatigue |
| 2 | Secret detection | Gitleaks, full git history | any secret found, in any commit | A secret that was ever committed is leaked, even if deleted later. Zero tolerance, no severity levels |
| 3 | Dependency scan | Trivy `fs` on `app/` (runtime requirements only) | CRITICAL, or HIGH **when a fixed version exists** | A High with no fix cannot be acted on and would only stall the team; it is tracked, not blocking. A High with a fix is a one-line upgrade, so there is no excuse |
| 4 | IaC and Dockerfile | Trivy `config` (Dockerfile now, Kubernetes manifests later) | HIGH or CRITICAL misconfiguration | Misconfiguration is deterministic and cheap to fix |
| 5 | Image scan | Trivy `image` on the built image | CRITICAL, or HIGH with a fix available | Catches OS packages and anything not visible in `requirements.txt` |
| 6 | Pipeline supply chain | `pinned-actions` job | any action referenced by tag or branch instead of a full commit SHA | The Trivy action itself was hijacked in March 2026 through moved tags |
| - | Tests | pytest | any failure, including a strict `xfail` that unexpectedly passes | The tests encode the secure behaviour; a fix must remove its `xfail` marker on purpose |

Tool versions are pinned (Semgrep 1.185.0, Gitleaks v8.30.1, Trivy v0.69.3) and every third-party action is pinned to
a commit SHA. The workflow runs with read-only repository permissions and does not persist credentials.

## Which control catches which planted flaw

| Flaw | Primary detector | Second layer |
|---|---|---|
| V1 SQL injection | Semgrep taint rule `docvault-sql-injection-request-to-execute` | strict xfail test; ZAP active scan |
| V2 IDOR | **Not detectable by static analysis**: the code is syntactically fine, only the missing ownership check is wrong | strict xfail tests (4); authenticated ZAP/DAST |
| V3 hardcoded secret | Gitleaks (history) | Trivy secret scanner on the working tree |
| V4 vulnerable dependency | Trivy `fs` and `image` (High with fix) | Dependabot pull request |
| V5 debug and verbose errors | Semgrep rules `docvault-flask-debug-enabled` and `docvault-traceback-in-application-code` | ZAP information-disclosure checks |

V2 is the important lesson: automated scanners miss authorisation logic bugs, which is why the plan also has tests
and an authenticated dynamic scan.

## Exceptions (accepted risks)

A finding may be accepted only by adding it to `.trivyignore` (or a Semgrep `nosem` comment) with a reason, an owner
and an **expiry date**, in a pull request that the other team member reviews. After the expiry date the finding
blocks again. The file is empty today.

## Enforcing it

Blocking only works if `main` cannot be changed around the pipeline. In GitHub: Settings, Branches, add a rule for
`main`, require a pull request, and require the status check `security gate` before merging.

## Known limits

- SAST and secret scanners produce false positives and false negatives; the strict tests and the DAST step cover
  part of that gap.
- Trivy's vulnerability database is only as current as its last update; a brand-new CVE is invisible until published.
- Registry rule packs (`p/flask`, `p/owasp-top-ten`) are downloaded at run time, so their content can change between
  runs. Custom rules in `.semgrep/` are versioned with the code.
