"""Tests for the CSRF double-submit middleware.

These exercise the ``before_request`` hook in isolation: we mount a tiny
Flask app, register the hook, and hit synthetic admin endpoints with the
test client. No database / DI container required.
"""
from __future__ import annotations

import os
import sys

import pytest
from flask import Blueprint, Flask, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from middleware import csrf as csrf_module
from middleware.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    mint_csrf_token,
    register_csrf,
    set_csrf_cookie,
    delete_csrf_cookie,
)


def _build_app(enforce: bool = True) -> Flask:
    """Construct a minimal Flask app with the CSRF hook wired in.

    The hook calls ``database.config.get_config_by_name()`` to read the
    ``ENFORCE_CSRF`` flag; we patch that lookup via a class attribute on a
    throwaway config object so the tests don't depend on the real config
    machinery.
    """
    app = Flask(__name__)
    app.testing = True

    class _StubConfig:
        ENFORCE_CSRF = enforce
        ADMIN_COOKIE_SECURE = False

    def _stub_get_config():
        return _StubConfig()

    # Replace the config lookup the middleware uses.
    import database.config as dbconfig
    app._stub_prev = dbconfig.get_config_by_name
    dbconfig.get_config_by_name = _stub_get_config

    bp = Blueprint("test_admin", __name__)

    @bp.route("/api/admin/things", methods=["POST", "PUT", "PATCH", "DELETE", "GET"])
    def things():
        return jsonify({"ok": True}), 200

    @bp.route("/api/admin/auth/login", methods=["POST"])
    def login():
        return jsonify({"ok": True}), 200

    @bp.route("/api/auth/agent-login", methods=["POST"])
    def agent_login():
        return jsonify({"ok": True}), 200

    app.register_blueprint(bp)
    register_csrf(app)
    return app


@pytest.fixture
def app():
    """Build the app fresh per-test and restore the patched config after."""
    app = _build_app(enforce=True)
    yield app
    import database.config as dbconfig
    dbconfig.get_config_by_name = app._stub_prev


@pytest.fixture
def lax_app():
    app = _build_app(enforce=False)
    yield app
    import database.config as dbconfig
    dbconfig.get_config_by_name = app._stub_prev


def test_get_is_never_csrf_checked(app):
    """Safe methods are exempt by definition (RFC 9110)."""
    resp = app.test_client().get("/api/admin/things")
    assert resp.status_code == 200


def test_post_without_token_is_rejected(app):
    resp = app.test_client().post("/api/admin/things", json={"a": 1})
    assert resp.status_code == 403
    body = resp.get_json()
    assert body["code"] == "CSRF_FAIL"


def test_post_with_matching_token_passes(app):
    client = app.test_client()
    token = mint_csrf_token()
    client.set_cookie(CSRF_COOKIE_NAME, token, domain="localhost")
    resp = client.post(
        "/api/admin/things",
        json={"a": 1},
        headers={CSRF_HEADER_NAME: token},
    )
    assert resp.status_code == 200


def test_post_with_mismatched_token_is_rejected(app):
    client = app.test_client()
    client.set_cookie(CSRF_COOKIE_NAME, mint_csrf_token(), domain="localhost")
    resp = client.post(
        "/api/admin/things",
        json={"a": 1},
        headers={CSRF_HEADER_NAME: mint_csrf_token()},  # different value
    )
    assert resp.status_code == 403


def test_post_with_cookie_but_no_header_is_rejected(app):
    client = app.test_client()
    client.set_cookie(CSRF_COOKIE_NAME, mint_csrf_token(), domain="localhost")
    resp = client.post("/api/admin/things", json={"a": 1})
    assert resp.status_code == 403


def test_login_path_is_exempt(app):
    # No session exists yet at login, so the middleware must not block.
    resp = app.test_client().post("/api/admin/auth/login", json={"u": "x"})
    assert resp.status_code == 200


def test_agent_auth_path_is_exempt(app):
    resp = app.test_client().post("/api/auth/agent-login", json={"u": "x"})
    assert resp.status_code == 200


def test_bearer_auth_request_is_exempt(app):
    """Bearer-authenticated requests can't be forged via CSRF (browsers
    don't auto-attach Authorization), so they bypass the cookie check."""
    resp = app.test_client().post(
        "/api/admin/things",
        json={"a": 1},
        headers={"Authorization": "Bearer some-jwt-token"},
    )
    assert resp.status_code == 200


def test_api_key_request_is_exempt(app):
    resp = app.test_client().post(
        "/api/admin/things",
        json={"a": 1},
        headers={"X-API-Key": "agent-key"},
    )
    assert resp.status_code == 200


def test_enforcement_can_be_disabled(lax_app):
    """ENFORCE_CSRF=False turns the hook into a no-op."""
    resp = lax_app.test_client().post("/api/admin/things", json={"a": 1})
    assert resp.status_code == 200


def test_set_csrf_cookie_returns_token(app):
    """``set_csrf_cookie`` is the seam controllers use; verify both sides
    of the contract (cookie attached, value returned)."""
    with app.test_request_context():
        from flask import make_response
        resp = make_response("ok")
        token = set_csrf_cookie(resp)
        assert token and len(token) >= 32
        cookies = resp.headers.getlist("Set-Cookie")
        assert any(c.startswith(f"{CSRF_COOKIE_NAME}=") for c in cookies)


def test_delete_csrf_cookie_emits_expiry(app):
    with app.test_request_context():
        from flask import make_response
        resp = make_response("ok")
        delete_csrf_cookie(resp)
        cookies = resp.headers.getlist("Set-Cookie")
        # Flask emits a Set-Cookie with Expires in the past to clear it.
        cleared = [c for c in cookies if c.startswith(f"{CSRF_COOKIE_NAME}=")]
        assert cleared
        assert "Expires=" in cleared[0]
