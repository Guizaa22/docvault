# Pinned slim base image
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Security: create an unprivileged user to run the app
RUN groupadd -r app && useradd -r -g app -d /app app

WORKDIR /app

# Runtime system deps only (openssl for key generation, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
      openssl curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy the application (secrets are excluded by .dockerignore)
COPY . .

# Data dir for runtime-generated secrets/keys/db; owned by the app user
RUN chmod +x docker/entrypoint.sh && mkdir -p /app/data && chown -R app:app /app

USER app
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --start-period=6s --retries=3 \
  CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "run:app"]
