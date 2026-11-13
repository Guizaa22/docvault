# DocVault — DevSecOps project (ING-5-SSIR, TEK-UP)

Document storage and sharing app, deliberately vulnerable at the start, then secured across its whole
lifecycle: code -> build -> pipeline -> deploy -> runtime monitoring.

## Stack
| Need | Choice |
|---|---|
| App | Flask + PostgreSQL |
| CI | GitHub Actions |
| SAST | Semgrep |
| Dependencies + image | Trivy |
| Secrets | Gitleaks |
| IaC scan | Trivy config (or Checkov) |
| DAST | OWASP ZAP (authenticated) |
| Orchestration | Kubernetes (kind + Calico) |
| Admission | Kyverno |
| Observability | Prometheus + Grafana + Loki |

## Repository layout
- `app/` application code and Dockerfile
- `k8s/` deployment manifests (RBAC, NetworkPolicy, Kyverno policies)
- `.github/workflows/` CI pipeline with the blocking security stage
- `docs/` threat model, vulnerability register, blocking policy, incident response plan, AI usage declaration
- `docs/evidence/` screenshots/logs proving each requirement
- `scripts/` helper scripts

## Progress (requirement -> status)
| Step | Requirement | Status |
|---|---|---|
| 0 | Foundations | in progress |
| 1 | 4.1 / 4.2 Vulnerable app | todo |
| 2 | 4.2 Threat model + flaw register | todo |
| 3 | 4.1 Hardened container | todo |
| 4 | 4.3 Blocking security pipeline | todo |
| 5 | 4.4 Secrets | todo |
| 6 | 4.5 K8s hardening + admission | todo |
| 7 | 4.6 DAST | todo |
| 8 | 4.7 Observability + incident response | todo |

> All offensive testing is done only against our own app, locally. No real secrets are ever used.
