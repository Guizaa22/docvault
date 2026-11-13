# syntax=docker/dockerfile:1

# Base image. Pin it by digest once (see docs/container-hardening.md), e.g.
#   --build-arg PYTHON_IMAGE=python:3.12-slim@sha256:<digest>
ARG PYTHON_IMAGE=python:3.12-slim

# ---------- Stage 1: builder (has pip and the dependency install; never shipped) ----------
FROM ${PYTHON_IMAGE} AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---------- Stage 2: runtime (only what is needed to run) ----------
FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="docvault-api" \
      org.opencontainers.image.description="DocVault document storage and sharing API" \
      org.opencontainers.image.source="https://github.com/Guizaa22/docvault"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH=/app

# Fixed numeric UID/GID: Kubernetes (runAsNonRoot) and Kyverno can verify a number, not a name.
# No home directory and no login shell.
RUN groupadd --system --gid 10001 app \
 && useradd  --system --uid 10001 --gid app --no-create-home \
             --home-dir /nonexistent --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Code is owned by root and not writable by the app user: a compromised process cannot rewrite it.
COPY app ./app
COPY run.py ./
COPY scripts/init_db.py scripts/seed.py scripts/gen_keys.py ./scripts/
COPY --chmod=0555 docker/entrypoint.sh ./docker/entrypoint.sh

# The only writable place: runtime data (database, keys). Mount a volume here.
RUN mkdir /app/data && chown 10001:10001 /app/data && chmod 0700 /app/data

USER 10001:10001
EXPOSE 5000

# No curl in the image: the healthcheck uses Python (a non-200 or error makes the probe fail).
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=2)"]

ENTRYPOINT ["/app/docker/entrypoint.sh"]
# --worker-tmp-dir /dev/shm lets gunicorn run with a read-only root filesystem.
CMD ["gunicorn", "--workers", "2", "--bind", "0.0.0.0:5000", "--worker-tmp-dir", "/dev/shm", "--access-logfile", "-", "run:app"]
