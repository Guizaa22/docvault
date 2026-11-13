# Decision log
| Date | Decision | Why |
|---|---|---|
| 2026-11-13 | Theme: DocVault | Valid: backend, DB, role-based auth, sensitive documents |
| 2026-11-13 | CI: GitHub Actions | Accepted alternative; code already on GitHub |
| 2026-11-13 | Stack: Flask + PostgreSQL | Known stack, easy to plant and fix SQLi / IDOR |
| 2026-11-13 | Cluster: kind + Calico | Local; Calico enforces NetworkPolicies |
