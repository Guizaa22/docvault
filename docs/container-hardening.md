# Container hardening (requirement 3)

Goal: if an attacker gets code execution inside the API container (T16/T17 in `threat-model.md`), they should find
almost nothing to use and almost nothing they can change.

## Before and after

| Area | Before | After | Why it matters |
|---|---|---|---|
| Build | Single stage | Multi-stage (builder + runtime) | pip and the build layer are not shipped |
| User | Named user `app` created with a dynamic UID | Fixed `USER 10001:10001`, no home, no login shell | Kubernetes `runAsNonRoot` and Kyverno can verify a number |
| Code ownership | `chown -R app:app /app` (app owns its code) | Code owned by root, read-only to the app | A compromised process cannot rewrite the application |
| Writable paths | Whole `/app` | Only `/app/data` (volume) and `/tmp` (tmpfs) | Supports `readOnlyRootFilesystem` |
| Extra tools | `curl`, `openssl` CLI, apt lists | None; healthcheck and key generation use Python | Fewer binaries for an attacker to reuse |
| Dependencies | Test tools (pytest, coverage) in the image | Runtime requirements only (`requirements.txt`); tests use `requirements-dev.txt` | Fewer packages to patch. Image size is unchanged (259 MB before, 258 MB after) because the Debian base dominates it |
| Gunicorn | Installed twice, unpinned in the Dockerfile | Installed once, from `requirements.txt` | One source of truth for the scanner |
| Secrets | Always generated into the volume | Taken from environment (Kubernetes Secret) when present; generated only for plain `docker run` | Prepares the Kubernetes secret flow |
| Demo accounts | Always created with known passwords | Only if `SEED_DEMO_USERS=1` | Removes default credentials (A07) from the image |
| Runtime options (compose) | None | `read_only`, `cap_drop: ALL`, `no-new-privileges`, pids, memory and CPU limits | Same controls Kubernetes will enforce |
| Build context | Basic `.dockerignore` | Also excludes `*.pem`, `*.key`, env files, tests, docs, compose files | Secrets cannot be copied into a layer by accident |

## What each choice defends against

- **Non-root, fixed UID:** a code-execution bug no longer starts with root privileges.
- **Read-only root filesystem and root-owned code:** attacker cannot drop a web shell or patch the app on disk.
- **Dropped capabilities and `no-new-privileges`:** limits what a process can do even if it finds a setuid binary.
- **No curl or openssl:** removes ready-made download and crypto tools used after exploitation.
- **Resource limits:** an abused container cannot starve the host (T12, T14).
- **Digest-pinned base image (below):** the base cannot change underneath us (supply chain, T6).

## Known gaps (honest limits)

- The base image still ships Debian packages the app does not use; the scan in CI will list their CVEs. A distroless
  or Alpine base would shrink this but adds compatibility risk, so it is a documented trade-off.
- The image still contains the V4 vulnerable gunicorn and V5 debug default on purpose; the pipeline must fail on
  them until they are fixed.
- Image signing (cosign) and an SBOM are not done; they would be the next step beyond this project's scope.

## Base image pinned by digest

A tag like `3.12-slim` moves; a digest does not. `app/Dockerfile` now pins
`python:3.12-slim@sha256:5e2bdb1b...fa5b` (the digest of the manifest list, obtained with
`docker buildx imagetools inspect python:3.12-slim`). Dependabot proposes digest updates as pull requests.

## How to verify (commands and expected results)

```bash
docker build -t docvault-api:hardened app/
docker run -d --name dv --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:5000:5000 -v dv-data:/app/data docvault-api:hardened
docker exec dv id                                  # uid=10001(app) gid=10001(app)
docker exec dv touch /app/x                        # fails: read-only file system
docker exec dv sh -c 'command -v curl openssl'     # prints nothing
docker exec dv python -c "import pytest"           # ModuleNotFoundError
docker inspect --format '{{.State.Health.Status}}' dv   # healthy
```
