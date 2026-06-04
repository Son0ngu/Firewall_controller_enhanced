import json
import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.registry import _registration_timeout, try_register_with_server


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def test_registration_timeout_uses_connect_and_read_timeout():
    config = {"server": {"connect_timeout": 3, "read_timeout": 77}}

    assert _registration_timeout(config) == (3.0, 77.0)


def test_registration_timeout_defaults_when_values_are_missing_or_invalid():
    config = {"server": {"connect_timeout": 0, "read_timeout": "bad"}}

    assert _registration_timeout(config) == (15.0, 45.0)


def test_try_register_uses_timeout_tuple_and_stores_credentials(monkeypatch):
    seen = {}

    def fake_post(url, json, timeout, headers):
        seen["url"] = url
        seen["payload"] = json
        seen["timeout"] = timeout
        seen["headers"] = headers
        return FakeResponse(
            200,
            {
                "success": True,
                "data": {
                    "agent_id": "agent-1",
                    "token": "legacy-token",
                    "user_id": "device-1",
                    "jwt": {
                        "access_token": "jwt-access",
                        "refresh_token": "jwt-refresh",
                        "token_type": "Bearer",
                        "access_expires_at": "2026-06-04T12:00:00+07:00",
                        "refresh_expires_at": "2026-06-05T12:00:00+07:00",
                    },
                },
            },
        )

    monkeypatch.setattr("core.registry.requests.post", fake_post)

    config = {
        "server": {"connect_timeout": 2, "read_timeout": 65},
        "auth": {"api_key": "fc_test"},
    }

    assert try_register_with_server(
        "https://controller.example",
        {"hostname": "PC1", "device_id": "device-1"},
        config,
    )
    assert seen["url"] == "https://controller.example/api/agents/register"
    assert seen["timeout"] == (2.0, 65.0)
    assert seen["headers"]["X-API-Key"] == "fc_test"
    assert config["agent_id"] == "agent-1"
    assert config["agent_token"] == "legacy-token"
    assert config["jwt"]["access_token"] == "jwt-access"
