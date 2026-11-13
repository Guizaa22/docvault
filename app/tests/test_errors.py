import pytest


@pytest.fixture
def boom_client(app):
    """A client for an app that has one route which always crashes."""
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.get("/api/_boom")
    def boom():
        raise ValueError("secret internal detail")

    return app.test_client()


def test_server_error_returns_json_500(boom_client):
    r = boom_client.get("/api/_boom")
    assert r.status_code == 500
    assert r.get_json()["error"] == "Internal server error"


@pytest.mark.xfail(strict=True, reason="V5: 500 responses leak exception details and stack trace")
def test_server_error_does_not_leak_details(boom_client):
    r = boom_client.get("/api/_boom")
    body = r.get_data(as_text=True)
    assert "secret internal detail" not in body
    assert "Traceback" not in body and "ValueError" not in body
    assert ".py" not in body
