"""
User Service - CRUD Teacher accounts (Admin only).
- Admin creates/edits/deletes Teacher accounts
- No public registration
"""

import logging
from typing import Dict, List, Optional, Tuple

import bcrypt
from bson import ObjectId

from models.user_model import UserModel
from services.audit_service import AuditService
from config.rbac_config import VALID_ROLES

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 72


class UserService:
    """Service for user CRUD operations (Admin manages Teachers)"""

    def __init__(self, user_model: UserModel, audit_service: AuditService,
                 socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.user_model = user_model
        self.audit_service = audit_service
        self.socketio = socketio

    # ========================================================================
    # CREATE (Admin creates Teacher)
    # ========================================================================

    def create_user(self, username: str, password: str, role: str = "teacher",
                    email: str = None, created_by_user: Dict = None) -> Tuple[bool, Dict, Optional[str]]:
        """
        Create a new user (Admin creates Teacher).

        Args:
            username: Username (lowercase, 3-50 chars)
            password: Password (min 8 chars)
            role: Role (admin or teacher)
            email: Email (optional)
            created_by_user: Admin user dict who creates this account

        Returns:
            (success, user_data, error_message)
        """
        try:
            # Validate username
            username = username.strip().lower()
            if len(username) < 3 or len(username) > 50:
                return False, {}, "Username must be 3-50 characters"

            if not all(c.isalnum() or c in "_.-" for c in username):
                return False, {}, "Username may only contain letters, numbers, hyphens, and dots"

            # Check duplicate
            if self.user_model.find_by_username(username):
                return False, {}, "Username already exists"

            # Validate email
            if email:
                email = email.strip().lower()
                if self.user_model.find_by_email(email):
                    return False, {}, "Email already in use"

            # Validate role
            if role not in VALID_ROLES:
                return False, {}, f"Invalid role. Only accepted: {VALID_ROLES}"

            # Validate password
            if len(password) < MIN_PASSWORD_LENGTH:
                return False, {}, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
            if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
                return False, {}, f"Password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes (bcrypt limit)"

            # Hash password
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=12)
            ).decode("utf-8")

            # Build user document
            user_data = {
                "username": username,
                "password_hash": password_hash,
                "email": email,
                "role": role,
                "created_by": created_by_user.get("_id") if created_by_user else None,
            }

            user = self.user_model.create(user_data)
            safe_user = self._sanitize_user(user)

            # Audit log
            if created_by_user:
                self.audit_service.log_action(
                    user=created_by_user,
                    action="user.create",
                    resource_type="users",
                    resource_id=str(user["_id"]),
                    details={"created_username": username, "role": role},
                )

            self.logger.info(f"User created: {username} (role: {role})")

            if self.socketio:
                self.socketio.emit("user_created", {"username": username, "role": role})

            return True, safe_user, None

        except Exception as e:
            self.logger.error(f"Error creating user: {e}")
            return False, {}, f"Failed to create user: {str(e)}"

    # ========================================================================
    # READ
    # ========================================================================

    def get_user_by_id(self, user_id: str) -> Optional[Dict]:
        """Get sanitized user by id"""
        user = self.user_model.find_by_id(user_id)
        if user:
            return self._sanitize_user(user)
        return None

    def get_all_users(self, query: Dict = None, limit: int = 100,
                      skip: int = 0) -> List[Dict]:
        """Get all users (sanitized)"""
        users = self.user_model.get_all_users(query, limit, skip)
        return [self._sanitize_user(u) for u in users]

    # ========================================================================
    # UPDATE
    # ========================================================================

    def update_user(self, user_id: str, update_data: Dict,
                    updated_by_user: Dict = None) -> Tuple[bool, Optional[str]]:
        """Update user (Admin only)"""
        try:
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, "User not found"

            # Only allow safe fields
            allowed = {"email", "role", "is_active"}
            safe_data = {k: v for k, v in update_data.items() if k in allowed}

            if "role" in safe_data and safe_data["role"] not in VALID_ROLES:
                return False, f"Invalid role. Only accepted: {VALID_ROLES}"

            if "email" in safe_data and safe_data["email"]:
                existing = self.user_model.find_by_email(safe_data["email"])
                if existing and str(existing["_id"]) != user_id:
                    return False, "Email already in use"

            success = self.user_model.update(user_id, safe_data)

            if success and updated_by_user:
                self.audit_service.log_action(
                    user=updated_by_user,
                    action="user.update",
                    resource_type="users",
                    resource_id=user_id,
                    details={"changes": safe_data, "target_user": user.get("username")},
                )

            return success, None

        except Exception as e:
            self.logger.error(f"Error updating user: {e}")
            return False, f"Update failed: {str(e)}"

    def toggle_active(self, user_id: str, is_active: bool,
                      updated_by_user: Dict = None) -> Tuple[bool, Optional[str]]:
        """Enable/disable user account"""
        try:
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, "User not found"

            # Cannot disable last admin
            if not is_active and user.get("role") == "admin":
                count = self.user_model.count_users({"role": "admin", "is_active": True})
                if count <= 1:
                    return False, "Cannot deactivate the last admin"

            success = self.user_model.update(user_id, {"is_active": is_active})

            if success and updated_by_user:
                action = "user.activate" if is_active else "user.deactivate"
                self.audit_service.log_action(
                    user=updated_by_user,
                    action=action,
                    resource_type="users",
                    resource_id=user_id,
                    details={"target_user": user.get("username")},
                )

            return success, None

        except Exception as e:
            self.logger.error(f"Error toggling user active: {e}")
            return False, "Operation failed"

    def reset_password(self, user_id: str, new_password: str,
                       reset_by_user: Dict = None) -> Tuple[bool, Optional[str]]:
        """Admin reset Teacher password"""
        try:
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, "User not found"

            if len(new_password) < MIN_PASSWORD_LENGTH:
                return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
            if len(new_password.encode("utf-8")) > MAX_PASSWORD_BYTES:
                return False, f"Password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes (bcrypt limit)"

            new_hash = bcrypt.hashpw(
                new_password.encode("utf-8"),
                bcrypt.gensalt(rounds=12)
            ).decode("utf-8")

            self.user_model.update(user_id, {"password_hash": new_hash})

            if reset_by_user:
                self.audit_service.log_action(
                    user=reset_by_user,
                    action="user.reset_password",
                    resource_type="users",
                    resource_id=user_id,
                    details={"target_user": user.get("username")},
                )

            return True, None

        except Exception as e:
            self.logger.error(f"Error resetting password: {e}")
            return False, "Password reset failed"

    # ========================================================================
    # DELETE
    # ========================================================================

    def delete_user(self, user_id: str,
                    deleted_by_user: Dict = None) -> Tuple[bool, Optional[str]]:
        """Delete user (Admin only)"""
        try:
            user = self.user_model.find_by_id(user_id)
            if not user:
                return False, "User not found"

            # Cannot delete last admin
            if user.get("role") == "admin":
                count = self.user_model.count_users({"role": "admin", "is_active": True})
                if count <= 1:
                    return False, "Cannot delete the last admin"

            # Cannot self-delete
            if deleted_by_user and str(deleted_by_user.get("_id")) == user_id:
                return False, "Cannot delete yourself"

            success = self.user_model.delete(user_id)

            if success and deleted_by_user:
                self.audit_service.log_action(
                    user=deleted_by_user,
                    action="user.delete",
                    resource_type="users",
                    resource_id=user_id,
                    details={"deleted_username": user.get("username"), "role": user.get("role")},
                )

            return success, None

        except Exception as e:
            self.logger.error(f"Error deleting user: {e}")
            return False, f"Failed to delete user: {str(e)}"

    # ========================================================================
    # SEED DEFAULT ADMIN
    # ========================================================================

    def ensure_default_admin(self, username: str = None,
                             password: str = None) -> Optional[Dict]:
        """Create default admin if no admin exists and credentials are supplied."""
        try:
            admin_count = self.user_model.count_users({"role": "admin"})
            if admin_count > 0:
                self.logger.info("Admin already exists, skipping seed")
                return None

            if not username or not password:
                self.logger.info("Default admin bootstrap skipped (no credentials provided)")
                return None
            success, user_data, error = self.create_user(
                username=username,
                password=password,
                role="admin",
            )
            if not success:
                self.logger.error(f"Error creating default admin: {error}")
                return None

            self.logger.warning("=" * 60)
            self.logger.warning("DEFAULT ADMIN CREATED!")
            self.logger.warning(f"  Username: {username}")
            self.logger.warning("  Password is not logged; copy it from your seed source immediately.")
            self.logger.warning("=" * 60)

            return user_data

        except Exception as e:
            self.logger.error(f"Error creating default admin: {e}")
            return None

    # ========================================================================
    # HELPERS
    # ========================================================================

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
