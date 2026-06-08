"""
Web Auth Controller - Login, logout, refresh, profile, change password for the
admin/teacher web UI.

- Blueprint prefix: /admin/auth/*
- Separate from agent auth (see controllers/auth_controller.py:AgentAuthController
  which serves /api/auth/* with Bearer JWT/API key).
- Tokens are stored in httpOnly cookies (no Authorization header expected from
  browsers).

Renamed from AdminAuthController to disambiguate from the agent-side controller.
A backwards-compat alias is exported at the bottom of this module so existing
``from controllers.admin_auth_controller import AdminAuthController`` callers
keep working while imports are migrated.
"""

import logging
from flask import Blueprint, request, jsonify, g, make_response
from typing import Tuple

from services.admin_auth_service import AdminAuthService
from services.jwt_service import JWTService
from middleware.rbac import require_login
from middleware.csrf import set_csrf_cookie, delete_csrf_cookie
from time_utils import now_iso
from utils.request_ip import get_client_ip
from database.config import get_config_by_name

logger = logging.getLogger(__name__)

# Cookie config
COOKIE_ACCESS_NAME = "access_token"
COOKIE_REFRESH_NAME = "refresh_token"
COOKIE_HTTPONLY = True
COOKIE_SAMESITE = "Lax"
COOKIE_PATH = "/"


def _cookie_secure() -> bool:
    """Read ADMIN_COOKIE_SECURE from config at request time.

    Why: avoid capturing the value at import — pytest and dev shells may load
    env after this module imports, and production deployments toggle the flag
    via env vars without restarting workers.
    """
    try:
        return bool(get_config_by_name().ADMIN_COOKIE_SECURE)
    except Exception:
        return False


class WebAuthController:
    """Controller for admin/teacher authentication via the web UI."""

    def __init__(self, admin_auth_service: AdminAuthService,
                 jwt_service: JWTService, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.auth_service = admin_auth_service
        self.jwt_service = jwt_service
        self.socketio = socketio
        self.blueprint = Blueprint('admin_auth', __name__)
        self._register_routes()

    def _register_routes(self):
        """Register routes"""
        # Public
        self.blueprint.add_url_rule(
            '/admin/auth/login', 'login', self.login, methods=['POST']
        )
        # Protected
        self.blueprint.add_url_rule(
            '/admin/auth/me', 'me', self.get_profile, methods=['GET']
        )
        self.blueprint.add_url_rule(
            '/admin/auth/refresh', 'refresh', self.refresh_token, methods=['POST']
        )
        self.blueprint.add_url_rule(
            '/admin/auth/logout', 'logout', self.logout, methods=['POST']
        )
        self.blueprint.add_url_rule(
            '/admin/auth/change-password', 'change_password',
            self.change_password, methods=['PUT']
        )
        self.blueprint.add_url_rule(
            '/admin/auth/profile', 'update_profile',
            self.update_profile, methods=['PUT']
        )

    def _success(self, data=None, message="Success", status_code=200) -> Tuple:
        response = {"success": True, "message": message}
        if data is not None:
            response["data"] = data
        return jsonify(response), status_code

    def _error(self, message: str, status_code=400, code=None) -> Tuple:
        response = {"success": False, "error": message}
        if code:
            response["code"] = code
        return jsonify(response), status_code

    # ========================================================================
    # PUBLIC
    # ========================================================================

    def login(self):
        """
        POST /api/admin/auth/login
        Body: {"username": "<admin-username>", "password": "<admin-password>"}
        Response: Set httpOnly cookies + return user info
        """
        try:
            if not request.is_json:
                return self._error("Request must be JSON", 400)

            data = request.get_json()
            username = data.get("username", "").strip()
            password = data.get("password", "")

            if not username or not password:
                return self._error("Username and password are required", 400)

            success, result, error = self.auth_service.login(
                username=username,
                password=password,
                ip_address=get_client_ip(),
                user_agent=request.headers.get("User-Agent"),
            )

            if not success:
                return self._error(error or "Login failed", 401)

            # Build response with httpOnly cookies
            tokens = result["tokens"]
            # Mint a fresh CSRF token for this session. We include it in the
            # JSON body so single-page clients can pick it up immediately
            # without an extra ``document.cookie`` read, and also drop it on
            # a non-httpOnly cookie so the SaintAPI helper can echo it back
            # in the ``X-CSRF-Token`` header on subsequent mutations.
            resp = make_response(jsonify({
                "success": True,
                "message": "Login successful",
                "data": {
                    "user": result["user"],
                    "tokens": tokens,  # Also return in body for API clients
                },
            }))

            # Set httpOnly cookies
            resp.set_cookie(
                COOKIE_ACCESS_NAME,
                tokens["access_token"],
                httponly=COOKIE_HTTPONLY,
                secure=_cookie_secure(),
                samesite=COOKIE_SAMESITE,
                path=COOKIE_PATH,
                max_age=tokens.get("access_expires_in", 86400),
            )
            resp.set_cookie(
                COOKIE_REFRESH_NAME,
                tokens["refresh_token"],
                httponly=COOKIE_HTTPONLY,
                secure=_cookie_secure(),
                samesite=COOKIE_SAMESITE,
                path=COOKIE_PATH,
                max_age=tokens.get("refresh_expires_in", 604800),
            )

            csrf_token = set_csrf_cookie(resp)
            # Re-emit the response body with the CSRF token included so the
            # frontend can pick it up before its first cookie-read race.
            resp.set_data(jsonify({
                "success": True,
                "message": "Login successful",
                "data": {
                    "user": result["user"],
                    "tokens": tokens,
                    "csrf_token": csrf_token,
                },
            }).get_data())

            return resp

        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return self._error("Login failed", 500)

    # ========================================================================
    # PROTECTED
    # ========================================================================

    @require_login
    def get_profile(self):
        """
        GET /api/admin/auth/me
        Returns current user profile
        """
        try:
            user = g.current_user
            safe_user = {
                "_id": str(user["_id"]),
                "username": user.get("username"),
                "email": user.get("email"),
                "role": user.get("role"),
                "is_active": user.get("is_active"),
                "last_login": user.get("last_login"),
                "created_at": user.get("created_at"),
            }
            return self._success(safe_user)
        except Exception as e:
            self.logger.error(f"Get profile error: {e}")
            return self._error("Failed to get info", 500)

    @require_login
    def refresh_token(self):
        """
        POST /api/admin/auth/refresh
        Body: {"refresh_token": "..."} or from cookie
        """
        try:
            # Get refresh token from body or cookie
            refresh_token = None
            if request.is_json:
                data = request.get_json()
                refresh_token = data.get("refresh_token")
            if not refresh_token:
                refresh_token = request.cookies.get(COOKIE_REFRESH_NAME)

            if not refresh_token:
                return self._error("Refresh token required", 400)

            success, result, error = self.auth_service.refresh_token(refresh_token)

            if not success:
                if "expired" in (error or "").lower():
                    return self._error(error, 401, "REFRESH_TOKEN_EXPIRED")
                return self._error(error or "Refresh failed", 401)

            # Update access_token cookie and rotate the CSRF token. Rotating
            # on refresh limits the lifetime of a leaked CSRF cookie to one
            # access-token window.
            csrf_token = set_csrf_cookie(make_response())  # generate fresh value
            result_with_csrf = dict(result)
            result_with_csrf["csrf_token"] = csrf_token

            resp = make_response(jsonify({
                "success": True,
                "message": "Token refreshed",
                "data": result_with_csrf,
            }))
            resp.set_cookie(
                COOKIE_ACCESS_NAME,
                result["access_token"],
                httponly=COOKIE_HTTPONLY,
                secure=_cookie_secure(),
                samesite=COOKIE_SAMESITE,
                path=COOKIE_PATH,
                max_age=result.get("expires_in", 86400),
            )
            set_csrf_cookie(resp, csrf_token)
            return resp

        except Exception as e:
            self.logger.error(f"Refresh error: {e}")
            return self._error("Refresh failed", 500)

    @require_login
    def logout(self):
        """
        POST /api/admin/auth/logout
        Revoke tokens + clear cookies
        """
        try:
            access_token = request.cookies.get(COOKIE_ACCESS_NAME)
            refresh_token = None
            if request.is_json:
                data = request.get_json()
                refresh_token = data.get("refresh_token")
            if not refresh_token:
                refresh_token = request.cookies.get(COOKIE_REFRESH_NAME)

            self.auth_service.logout(access_token, refresh_token)

            # Clear cookies
            resp = make_response(jsonify({
                "success": True,
                "message": "Logout successful",
            }))
            resp.delete_cookie(COOKIE_ACCESS_NAME, path=COOKIE_PATH)
            resp.delete_cookie(COOKIE_REFRESH_NAME, path=COOKIE_PATH)
            delete_csrf_cookie(resp)

            return resp

        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            return self._error("Logout failed", 500)

    @require_login
    def change_password(self):
        """
        PUT /api/admin/auth/change-password
        Body: {"old_password": "...", "new_password": "..."}
        """
        try:
            if not request.is_json:
                return self._error("Request must be JSON", 400)

            data = request.get_json()
            old_password = data.get("old_password", "")
            new_password = data.get("new_password", "")

            if not old_password or not new_password:
                return self._error("old_password and new_password are required", 400)

            success, error = self.auth_service.change_password(
                g.current_user_id, old_password, new_password
            )

            if not success:
                return self._error(error, 400)

            return self._success(None, "Password changed successfully")

        except Exception as e:
            self.logger.error(f"Change password error: {e}")
            return self._error("Password change failed", 500)

    @require_login
    def update_profile(self):
        """
        PUT /api/admin/auth/profile
        Body: {"email": "..."}
        """
        try:
            if not request.is_json:
                return self._error("Request must be JSON", 400)

            data = request.get_json()
            email = data.get("email", "").strip()

            update_data = {}
            if email:
                # Check email duplicate
                existing = self.auth_service.user_model.find_by_email(email)
                if existing and str(existing.get("_id")) != str(g.current_user_id):
                    return self._error("Email already in use by another user", 400)
                update_data["email"] = email

            if update_data:
                success = self.auth_service.user_model.update(g.current_user_id, update_data)
                if success:
                    try:
                        if hasattr(self.auth_service, 'audit_service'):
                            self.auth_service.audit_service.log_action(
                                user=g.current_user,
                                action="profile.update",
                                resource_type="users",
                                resource_id=str(g.current_user_id),
                                details={"updated_fields": list(update_data.keys())},
                                ip_address=get_client_ip(),
                            )
                    except Exception as e:
                        self.logger.error(f"Failed to log profile update: {e}")

                    return self._success(None, "Profile updated successfully")
                return self._error("Cannot update profile", 500)

            return self._success(None, "No changes")

        except Exception as e:
            self.logger.error(f"Update profile error: {e}")
            return self._error("Profile update failed", 500)


# Backwards-compat alias for callers that still import the old name.
# Remove once all imports are migrated (see app.py and tests/).
AdminAuthController = WebAuthController
