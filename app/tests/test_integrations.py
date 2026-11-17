import pytest

from app.integrations import backup_headers


def test_backup_key_comes_from_environment(monkeypatch):
    monkeypatch.setenv("BACKUP_SERVICE_API_KEY", "test-key-not-real")
    assert backup_headers() == {"Authorization": "Bearer test-key-not-real"}


def test_backup_fails_without_key(monkeypatch):
    monkeypatch.delenv("BACKUP_SERVICE_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        backup_headers()


def test_no_hardcoded_key_in_source():
    import inspect
    import app.integrations as mod
    assert "dvk_live_" not in inspect.getsource(mod)
