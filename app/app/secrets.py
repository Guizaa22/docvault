"""Load secrets from HashiCorp Vault when configured, else from the environment.

If VAULT_ADDR and VAULT_TOKEN are set, secrets are read from the KV v2 store at
secret/secure-notes. Otherwise the matching environment variable is used. This
keeps local development and the test suite working with no Vault present.
"""
import os


def get_secret(vault_key, env_key):
    addr = os.environ.get("VAULT_ADDR")
    token = os.environ.get("VAULT_TOKEN")
    if addr and token:
        try:
            import hvac
            client = hvac.Client(url=addr, token=token)
            resp = client.secrets.kv.v2.read_secret_version(
                path="secure-notes", mount_point="secret"
            )
            value = resp["data"]["data"].get(vault_key)
            if value:
                return value
        except Exception:
            # Vault unreachable or key missing — fall back to the environment
            pass
    return os.environ.get(env_key)
