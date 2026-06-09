"""
Admin Auth Service - Login, logout, refresh, change password for Admin/Teacher.
- Completely separate from Agent auth (auth_controller.py)
- Brute-force protection
- Session management
- httpOnly cookie JWT
"""

import logging
from datetime import timedelta
from typing import Dict, Optional, Tuple

import bcrypt
from flask import request as flask_request

from models.user_model import UserModel
from models.session_model import SessionModel
from services.jwt_service import JWTService
from services.audit_service import AuditService
from time_utils import now_vietnam

# Password policy
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72


class AdminAuthService:
    """Service for admin/teacher authentication"""

    def __init__(self, user_model: UserModel, jwt_service: JWTService,
                 session_model: SessionModel, audit_service: AuditService,
                 socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.user_model = user_model
        self.jwt_service = jwt_service
        self.session_model = session_model
        self.audit_service = audit_service
        self.socketio = socketio

    # ========================================================================
    # LOGIN
    # ========================================================================

    def login(self, username: str, password: str,
              ip_address: str = None, user_agent: str = None) -> Tuple[bool, Dict, Optional[str]]:
        """
        Authenticate admin/teacher user.

        Returns:
            (success, {user, tokens} or {}, error_message)
        """
        try:
            username = username.strip().lower()

            # Find user
            user = self.user_model.find_by_username(username)
            if not user:
                return False, {}, "Invalid login credentials"

            user_id_str = str(user["_id"])

            # Check active
            if not user.get("is_active", True):
                self.audit_service.log_action(
                    user=user, action="auth.failed",
                    resource_type="auth", details={"reason": "account_disabled"},
                    ip_address=ip_address,
                )
                return False, {}, "Account has been disabled"

            # Check locked
            if self.user_model.is_locked(user):
                self.audit_service.log_action(
                    user=user, action="auth.failed",
                    resource_type="auth", details={"reason": "account_locked"},
                    ip_address=ip_address,
                )
                return False, {}, "Account temporarily locked. Please try again later"

            # Verify password
            if not self._verify_password(password, user.get("password_hash", "")):
                # Increment failed attempts
                attempts = self.user_model.increment_failed_attempts(user_id_str)
                self.audit_service.log_action(
                    user=user, action="auth.failed",
                    resource_type="auth",
                    details={"reason": "wrong_password", "attempts": attempts},
                    ip_address=ip_address,
                )
                return False, {}, "Invalid login credentials"

            # === Login success ===

            # Reset failed attempts
            self.user_model.reset_failed_attempts(user_id_str)
            self.user_model.update_last_login(user_id_str)

            # Generate JWT tokens with role info
            tokens = self.jwt_service.generate_tokens(
                agent_id=user_id_str,
                user_id=username,
                additional_claims={
                    "token_for": "admin_user",
                    "role": user["role"],
                    "username": username,
                }
            )

            # Create session record
            self.session_model.create({
                "user_id": user["_id"],
                "access_token_jti": self._extract_jti(tokens["access_token"]),
                "refresh_token_jti": self._extract_jti(tokens["refresh_token"]),
                "ip_address": ip_address,
                "user_agent": user_agent,
                "expires_at": now_vietnam() + timedelta(days=7),
            })

            # Audit log
            self.audit_service.log_action(
                user=user, action="auth.login",
                resource_type="auth", details={},
                ip_address=ip_address,
            )

            self.logger.info(f"Login success: {username} (role: {user['role']})")

            # Emit socket event
            if self.socketio:
                self.socketio.emit("admin_login", {
                    "username": username, "role": user["role"],
                })

            return True, {
                "user": self._sanitize_user(user),
                "tokens": tokens,
            }, None

        except Exception as e:
            self.logger.error(f"Login error: {e}")
            return False, {}, "Login failed"

    # ========================================================================
    # LOGOUT
    # ========================================================================

    def logout(self, access_token: str, refresh_token: str = None) -> Tuple[bool, Optional[str]]:
        """Logout by revoking tokens"""
        try:
            revoked = 0

            if access_token:
                jti = self._extract_jti(access_token)
                if jti:
                    self.session_model.revoke(jti)
                    self.jwt_service.revoke_token(access_token, "access")
                    revoked += 1

            if refresh_token:
                jti = self._extract_jti(refresh_token)
                if jti:
                    self.session_model.revoke(jti)
                    self.jwt_service.revoke_token(refresh_token, "refresh")
                    revoked += 1

            return True, None

        except Exception as e:
            self.logger.error(f"Logout error: {e}")
            return False, "Logout failed"

    # ========================================================================
    # REFRESH TOKEN
    # ========================================================================

    def refresh_token(self, refresh_token: str) -> Tuple[bool, Dict, Optional[str]]:
        """
        Refresh access token for admin/teacher.
        Re-generates tokens with admin claims (token_for, role, username)
        because JWTService.refresh_access_token() doesn't carry additional_claims.
        """
        try:
            # Validate refresh token first
            is_valid, payload, error = self.jwt_service.validate_refresh_token(refresh_token)
            if not is_valid:
                return False, {}, error

            # Get user from DB to ensure still active + get current role
            user_id = payload.get("sub")
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, {}, "User not found"
            if not user.get("is_active", True):
                return False, {}, "Account has been disabled"
            if self.user_model.is_locked(user):
                return False, {}, "Account temporarily locked"

            # Generate new tokens WITH admin claims
            tokens = self.jwt_service.generate_tokens(
                agent_id=user_id,
                user_id=user.get("username"),
                additional_claims={
                    "token_for": "admin_user",
                    "role": user["role"],
                    "username": user.get("username"),
                }
            )

            return True, {
                "access_token": tokens["access_token"],
                "token_type": "Bearer",
                "expires_in": tokens.get("access_expires_in", 86400),
                "expires_at": tokens.get("access_expires_at"),
            }, None

        except Exception as e:
            self.logger.error(f"Refresh token error: {e}")
            return False, {}, "Refresh token failed"

    # ========================================================================
    # CHANGE PASSWORD
    # ========================================================================

    def change_password(self, user_id: str, old_password: str,
                        new_password: str) -> Tuple[bool, Optional[str]]:
        """Change user's own password"""
        try:
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, "User not found"

            if not self._verify_password(old_password, user.get("password_hash", "")):
                return False, "Current password is incorrect"

            valid, error = self._validate_password(new_password)
            if not valid:
                return False, error

            new_hash = self._hash_password(new_password)
            self.user_model.update(user_id, {"password_hash": new_hash})

            # Audit log
            self.audit_service.log_action(
                user=user, action="profile.change_password",
                resource_type="profile", resource_id=user_id,
                details={},
            )

            self.logger.info(f"Password changed for {user.get('username')}")
            return True, None

        except Exception as e:
            self.logger.error(f"Change password error: {e}")
            return False, "Password change failed"

    # ========================================================================
    # PASSWORD HELPERS
    # ========================================================================

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password with bcrypt"""
        return bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                password_hash.encode("utf-8")
            )
        except Exception:
            return False

    @staticmethod
    def _validate_password(password: str) -> Tuple[bool, Optional[str]]:
        """Validate password policy"""
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            return False, f"Password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes (bcrypt limit)"
        return True, None

    def _extract_jti(self, token: str) -> Optional[str]:
        """Extract JTI from token without verification"""
        payload = self.jwt_service.decode_token_without_verification(token)
        if payload:
            return payload.get("jti")
        return None

    @staticmethod
    def _sanitize_user(user: Dict) -> Dict:
        """Remove sensitive fields"""
        safe = {**user}
        safe.pop("password_hash", None)
        safe.pop("failed_login_attempts", None)
        safe.pop("locked_until", None)
        if "_id" in safe:
            safe["_id"] = str(safe["_id"])
        if "created_by" in safe and safe["created_by"]:
            safe["created_by"] = str(safe["created_by"])
        return safe
