"""Generate JWT and Fernet secrets and store them in Vault (once)."""
import os
import secrets
import time

import hvac
from cryptography.fernet import Fernet

client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])

# Wait for Vault to be ready
for _ in range(30):
    try:
        if client.is_authenticated():
            break
    except Exception:
        pass
    time.sleep(1)

# Only write if not already present
try:
    client.secrets.kv.v2.read_secret_version(path="secure-notes", mount_point="secret")
    print("Secrets already present in Vault — skipping.")
except Exception:
    client.secrets.kv.v2.create_or_update_secret(
        path="secure-notes",
        mount_point="secret",
        secret={
            "jwt_secret": secrets.token_hex(32),
            "fernet_key": Fernet.generate_key().decode(),
        },
    )
    print("Secrets generated and written to Vault at secret/secure-notes.")
