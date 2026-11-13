#!/usr/bin/env sh
set -e

DATA=/app/data
export DATABASE="${DATABASE:-$DATA/app.db}"
export SIGNING_KEY_PATH="${SIGNING_KEY_PATH:-$DATA/keys/signing_key.pem}"
export SIGNING_PUBKEY_PATH="${SIGNING_PUBKEY_PATH:-$DATA/keys/signing_pub.pem}"
export JWT_EC_PRIVATE_KEY_PATH="${JWT_EC_PRIVATE_KEY_PATH:-$DATA/keys/jwt_ec_key.pem}"
export JWT_EC_PUBLIC_KEY_PATH="${JWT_EC_PUBLIC_KEY_PATH:-$DATA/keys/jwt_ec_pub.pem}"

# Application secrets. In Kubernetes they are injected as environment variables from a Secret,
# so nothing is generated. For a plain `docker run` they are generated once into the data volume.
if [ -z "$JWT_SECRET" ] || [ -z "$FERNET_KEY" ]; then
  if [ ! -f "$DATA/.env" ]; then
    echo ">> Generating application secrets..."
    umask 077
    echo "JWT_SECRET=$(python -c 'import secrets; print(secrets.token_hex(32))')" >  "$DATA/.env"
    echo "FERNET_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')" >> "$DATA/.env"
  fi
  set -a; . "$DATA/.env"; set +a
fi

# Signing and JWT key pairs (generated once, mode 0600)
python scripts/gen_keys.py "$DATA/keys"

# Database schema
echo ">> Initializing database..."
python scripts/init_db.py

# Demo accounts have well-known passwords: they are created only when explicitly requested.
if [ "$SEED_DEMO_USERS" = "1" ]; then
  echo ">> SEED_DEMO_USERS=1: creating demo accounts (never enable this in production)"
  python scripts/seed.py
fi

exec "$@"
