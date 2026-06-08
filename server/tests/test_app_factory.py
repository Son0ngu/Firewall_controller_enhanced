import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from bootstrap import app_factory
from database.config import _mask_connection_uri


class _FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message, *args):
        self.warnings.append((message, args))


class _FakeApp:
    def __init__(self):
        self.config = {}
        self.logger = _FakeLogger()


def test_create_socketio_falls_back_to_threading_when_async_mode_missing(monkeypatch):
    calls = []

    def fake_socketio(app, **kwargs):
        calls.append(kwargs)
        if kwargs["async_mode"] == "gevent":
            raise ValueError("Invalid async_mode specified")
        return {"async_mode": kwargs["async_mode"]}

    monkeypatch.setattr(app_factory, "SocketIO", fake_socketio)
    app = _FakeApp()

    socketio = app_factory._create_socketio(app, "gevent")

    assert socketio == {"async_mode": "threading"}
    assert app.config["SOCKETIO_ASYNC_MODE"] == "threading"
    assert [call["async_mode"] for call in calls] == ["gevent", "threading"]
    assert app.logger.warnings


def test_create_socketio_reraises_non_backend_errors(monkeypatch):
    def fake_socketio(app, **kwargs):
        raise ValueError("different setup error")

    monkeypatch.setattr(app_factory, "SocketIO", fake_socketio)

    with pytest.raises(ValueError, match="different setup error"):
        app_factory._create_socketio(_FakeApp(), "gevent")


def test_api_cors_options_cover_patch_and_csrf_header():
    options = app_factory.API_CORS_OPTIONS

    assert "PATCH" in options["methods"]
    assert "X-CSRF-Token" in options["allow_headers"]


def test_mask_connection_uri_hides_credentials():
    uri = "mongodb+srv://dbuser:dbpass@example.mongodb.net/Monitoring?retryWrites=true"

    masked = _mask_connection_uri(uri)

    assert masked == "mongodb+srv://***:***@example.mongodb.net/Monitoring?retryWrites=true"
    assert "dbuser" not in masked
    assert "dbpass" not in masked
