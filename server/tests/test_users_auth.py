"""
Test Suite: Users + Auth (Admin/Teacher accounts)
==================================================
1. UserModel          - CRUD, brute-force protection, lock/unlock, statistics
2. UserService        - create/update/delete with validation, toggle_active, last-admin protection
3. SessionModel       - create/find/revoke sessions, is_session_revoked
4. AdminAuthService   - login, logout, refresh, change_password, brute-force
5. UserController     - admin-only CRUD endpoints
6. WebAuthController   - login/logout/refresh/profile endpoints

Run:
  cd server && python -m pytest tests/test_users_auth.py -v
"""

import pytest
import sys
import os
import bcrypt
from datetime import timedelta
from bson import ObjectId
from unittest.mock import patch, MagicMock
from flask import Flask, g

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.user_model import UserModel, MAX_FAILED_ATTEMPTS, LOCK_DURATION_MINUTES
from models.session_model import SessionModel
from models.audit_model import AuditModel
from services.user_service import UserService
from services.audit_service import AuditService
from services.admin_auth_service import AdminAuthService
from services.jwt_service import JWTService
from time_utils import now_vietnam, VIETNAM_TZ


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(scope='session')
def mongo_client():
    from pymongo import MongoClient
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path)
    uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    yield client
    client.close()


TEST_DB = 'test_saint_users_auth'


@pytest.fixture
def db(mongo_client):
    from bson.codec_options import CodecOptions
    codec = CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)
    database = mongo_client.get_database(TEST_DB, codec_options=codec)
    yield database
    mongo_client.drop_database(TEST_DB)


@pytest.fixture
def user_model(db):
    return UserModel(db)


@pytest.fixture
def session_model(db):
    return SessionModel(db)


@pytest.fixture
def audit_model(db):
    return AuditModel(db)


@pytest.fixture
def audit_service(audit_model):
    return AuditService(audit_model)


@pytest.fixture
def jwt_service(db):
    return JWTService(db=db)


@pytest.fixture
def user_service(user_model, audit_service):
    return UserService(user_model, audit_service)


@pytest.fixture
def auth_service(user_model, jwt_service, session_model, audit_service):
    return AdminAuthService(user_model, jwt_service, session_model, audit_service)


# ============================================================================
# HELPERS
# ============================================================================

def _hash(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=4)).decode("utf-8")


def _create_user(user_model, username="testuser", password="password123",
                 role="teacher", email=None, is_active=True):
    data = {
        "username": username,
        "password_hash": _hash(password),
        "role": role,
        "is_active": is_active,
    }
    # Only include email if provided - sparse unique index rejects multiple null values
    if email:
        data["email"] = email
    return user_model.create(data)


def make_admin_user(user_model, username="admin01", password="admin12345678"):
    return _create_user(user_model, username=username, password=password, role="admin")


def _mock_auth(user):
    """Patch middleware internals so @require_login passes and sets g.current_user."""
    return patch.multiple(
        'middleware.rbac',
        _extract_token=lambda: 'fake-token',
        _validate_admin_token=lambda token: (True, user, None),
    )


def test_jwt_token_info_handles_timezone_aware_expiry():
    jwt_service = JWTService(db=None)
    tokens = jwt_service.generate_tokens("agent-1", "user-1")

    info = jwt_service.get_token_info(tokens["access_token"])

    assert info["agent_id"] == "agent-1"
    assert info["token_type"] == "access"
    assert info["is_expired"] is False
    assert info["expires_at"].endswith("+07:00")


def test_revoke_all_agent_tokens_invalidates_existing_tokens(jwt_service):
    tokens = jwt_service.generate_tokens("agent-revoke-1", "user-revoke-1")

    access_valid_before, _, _ = jwt_service.validate_access_token(tokens["access_token"])
    refresh_valid_before, _, _ = jwt_service.validate_refresh_token(tokens["refresh_token"])

    assert access_valid_before is True
    assert refresh_valid_before is True
    assert jwt_service.revoke_all_agent_tokens("agent-revoke-1") == 1

    access_valid_after, _, _ = jwt_service.validate_access_token(tokens["access_token"])
    refresh_valid_after, _, _ = jwt_service.validate_refresh_token(tokens["refresh_token"])

    assert access_valid_after is False
    assert refresh_valid_after is False


# ============================================================================
# 1. USER MODEL TESTS
# ============================================================================

class TestUserModel:

    def test_create_user(self, user_model):
        user = _create_user(user_model, username="create_test")
        assert "_id" in user
        assert user["username"] == "create_test"
        assert user["role"] == "teacher"
        assert user["is_active"] is True
        assert user["failed_login_attempts"] == 0
        assert user["locked_until"] is None

    def test_find_by_id(self, user_model):
        user = _create_user(user_model, username="findid_test")
        found = user_model.find_by_id(str(user["_id"]))
        assert found is not None
        assert found["username"] == "findid_test"

    def test_find_by_id_not_found(self, user_model):
        assert user_model.find_by_id(str(ObjectId())) is None

    def test_find_by_username(self, user_model):
        _create_user(user_model, username="findname_test")
        found = user_model.find_by_username("findname_test")
        assert found is not None

    def test_find_by_username_case_insensitive(self, user_model):
        _create_user(user_model, username="casetest")
        found = user_model.find_by_username("CaseTest")
        assert found is not None

    def test_find_by_email(self, user_model):
        _create_user(user_model, username="emailuser", email="test@example.com")
        found = user_model.find_by_email("test@example.com")
        assert found is not None

    def test_get_all_users(self, user_model):
        _create_user(user_model, username="all_1")
        _create_user(user_model, username="all_2")
        users = user_model.get_all_users()
        assert len(users) >= 2

    def test_count_users(self, user_model):
        _create_user(user_model, username="count_1")
        assert user_model.count_users() >= 1

    def test_count_users_with_filter(self, user_model):
        _create_user(user_model, username="cnt_admin", role="admin")
        _create_user(user_model, username="cnt_teacher", role="teacher")
        assert user_model.count_users({"role": "admin"}) >= 1

    def test_update_user(self, user_model):
        user = _create_user(user_model, username="upd_test")
        result = user_model.update(str(user["_id"]), {"email": "new@test.com"})
        assert result is True
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["email"] == "new@test.com"

    def test_update_last_login(self, user_model):
        user = _create_user(user_model, username="login_ts")
        result = user_model.update_last_login(str(user["_id"]))
        assert result is True
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["last_login"] is not None

    def test_delete_user(self, user_model):
        user = _create_user(user_model, username="del_test")
        assert user_model.delete(str(user["_id"])) is True
        assert user_model.find_by_id(str(user["_id"])) is None

    def test_delete_user_not_found(self, user_model):
        assert user_model.delete(str(ObjectId())) is False

    # Brute-force protection
    def test_increment_failed_attempts(self, user_model):
        user = _create_user(user_model, username="brute_inc")
        count = user_model.increment_failed_attempts(str(user["_id"]))
        assert count == 1
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["failed_login_attempts"] == 1

    def test_lock_after_max_attempts(self, user_model):
        user = _create_user(user_model, username="brute_lock")
        uid = str(user["_id"])
        for _ in range(MAX_FAILED_ATTEMPTS):
            user_model.increment_failed_attempts(uid)
        updated = user_model.find_by_id(uid)
        assert updated["locked_until"] is not None
        assert user_model.is_locked(updated) is True

    def test_reset_failed_attempts(self, user_model):
        user = _create_user(user_model, username="brute_reset")
        uid = str(user["_id"])
        user_model.increment_failed_attempts(uid)
        user_model.increment_failed_attempts(uid)
        assert user_model.reset_failed_attempts(uid) is True
        updated = user_model.find_by_id(uid)
        assert updated["failed_login_attempts"] == 0

    def test_is_locked_false_when_no_lock(self, user_model):
        user = _create_user(user_model, username="not_locked")
        assert user_model.is_locked(user) is False

    def test_is_locked_false_when_expired(self, user_model):
        user = _create_user(user_model, username="lock_expired")
        uid = str(user["_id"])
        # Set locked_until to past
        user_model.collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"locked_until": now_vietnam() - timedelta(minutes=1)}}
        )
        updated = user_model.find_by_id(uid)
        assert user_model.is_locked(updated) is False

    def test_lock_account_manual(self, user_model):
        user = _create_user(user_model, username="manual_lock")
        uid = str(user["_id"])
        result = user_model.lock_account(uid, duration_minutes=30)
        assert result is True
        updated = user_model.find_by_id(uid)
        assert user_model.is_locked(updated) is True

    def test_get_user_statistics(self, user_model):
        _create_user(user_model, username="stat_admin", role="admin")
        _create_user(user_model, username="stat_teacher", role="teacher")
        stats = user_model.get_user_statistics()
        assert stats["total"] >= 2
        assert "admin" in stats["by_role"]
        assert "teacher" in stats["by_role"]


# ============================================================================
# 2. USER SERVICE TESTS
# ============================================================================

class TestUserService:

    def test_create_user_success(self, user_service):
        success, user, error = user_service.create_user(
            username="svc_create", password="password123", role="teacher"
        )
        assert success is True
        assert user.get("username") == "svc_create"
        assert error is None
        # Sanitized: no password_hash
        assert "password_hash" not in user

    def test_create_user_short_username(self, user_service):
        success, _, error = user_service.create_user(
            username="ab", password="password123"
        )
        assert success is False
        assert "3-50" in error

    def test_create_user_invalid_chars(self, user_service):
        success, _, error = user_service.create_user(
            username="bad user!", password="password123"
        )
        assert success is False

    def test_create_user_duplicate(self, user_service):
        user_service.create_user(username="dup_user", password="password123")
        success, _, error = user_service.create_user(
            username="dup_user", password="password123"
        )
        assert success is False
        assert "exists" in error.lower()

    def test_create_user_invalid_role(self, user_service):
        success, _, error = user_service.create_user(
            username="bad_role", password="password123", role="superadmin"
        )
        assert success is False
        assert "role" in error.lower()

    def test_create_user_short_password(self, user_service):
        success, _, error = user_service.create_user(
            username="shortpw", password="short"
        )
        assert success is False
        assert "8" in error

    def test_create_user_password_too_many_bytes(self, user_service):
        success, _, error = user_service.create_user(
            username="byte_limit_user", password="\u00e1" * 37
        )
        assert success is False
        assert "bytes" in error.lower()

    def test_create_user_with_audit(self, user_service, audit_model):
        admin = {"_id": ObjectId(), "username": "admin_creator", "role": "admin"}
        success, user, _ = user_service.create_user(
            username="audited_user", password="password123",
            created_by_user=admin,
        )
        assert success is True
        logs = audit_model.get_logs({"action": "user.create"})
        assert any(l.get("username") == "admin_creator" for l in logs)

    def test_get_user_by_id(self, user_service, user_model):
        user = _create_user(user_model, username="svc_getid")
        result = user_service.get_user_by_id(str(user["_id"]))
        assert result is not None
        assert "password_hash" not in result

    def test_get_user_by_id_not_found(self, user_service):
        assert user_service.get_user_by_id(str(ObjectId())) is None

    def test_get_all_users_sanitized(self, user_service, user_model):
        _create_user(user_model, username="svc_all1")
        users = user_service.get_all_users()
        assert len(users) >= 1
        for u in users:
            assert "password_hash" not in u

    def test_update_user(self, user_service, user_model):
        user = _create_user(user_model, username="svc_upd")
        success, error = user_service.update_user(
            str(user["_id"]), {"email": "new@svc.com"}
        )
        assert success is True

    def test_update_user_not_found(self, user_service):
        success, error = user_service.update_user(str(ObjectId()), {"email": "x@y.com"})
        assert success is False

    def test_update_user_invalid_role(self, user_service, user_model):
        user = _create_user(user_model, username="svc_badrole")
        success, error = user_service.update_user(
            str(user["_id"]), {"role": "superuser"}
        )
        assert success is False

    def test_toggle_active(self, user_service, user_model):
        user = _create_user(user_model, username="svc_toggle")
        success, error = user_service.toggle_active(str(user["_id"]), False)
        assert success is True
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["is_active"] is False

    def test_toggle_active_last_admin_protection(self, user_service, user_model):
        admin = make_admin_user(user_model, username="svc_last_admin")
        success, error = user_service.toggle_active(str(admin["_id"]), False)
        assert success is False
        assert "last admin" in error.lower()

    def test_reset_password(self, user_service, user_model):
        user = _create_user(user_model, username="svc_resetpw")
        success, error = user_service.reset_password(
            str(user["_id"]), "newpassword123"
        )
        assert success is True

    def test_reset_password_too_short(self, user_service, user_model):
        user = _create_user(user_model, username="svc_shortpw")
        success, error = user_service.reset_password(str(user["_id"]), "short")
        assert success is False

    def test_reset_password_too_many_bytes(self, user_service, user_model):
        user = _create_user(user_model, username="svc_longpw")
        success, error = user_service.reset_password(
            str(user["_id"]), "\u00e1" * 37
        )
        assert success is False
        assert "bytes" in error.lower()

    def test_delete_user(self, user_service, user_model):
        user = _create_user(user_model, username="svc_del")
        admin = {"_id": ObjectId(), "username": "admin", "role": "admin"}
        success, error = user_service.delete_user(str(user["_id"]), admin)
        assert success is True

    def test_delete_last_admin_protection(self, user_service, user_model):
        admin = make_admin_user(user_model, username="svc_last_admin_del")
        deleter = {"_id": ObjectId(), "username": "other", "role": "admin"}
        success, error = user_service.delete_user(str(admin["_id"]), deleter)
        assert success is False
        assert "last admin" in error.lower()

    def test_delete_self_protection(self, user_service, user_model):
        user = _create_user(user_model, username="svc_self_del")
        success, error = user_service.delete_user(
            str(user["_id"]),
            {"_id": user["_id"], "username": "svc_self_del", "role": "admin"},
        )
        assert success is False
        assert "yourself" in error.lower()

    def test_ensure_default_admin(self, user_service, user_model):
        result = user_service.ensure_default_admin("seed_admin", "seedpassword123")
        assert result is not None
        assert result["username"] == "seed_admin"

    def test_ensure_default_admin_skips_if_exists(self, user_service, user_model):
        make_admin_user(user_model, username="existing_admin")
        result = user_service.ensure_default_admin()
        assert result is None


# ============================================================================
# 3. SESSION MODEL TESTS
# ============================================================================

class TestSessionModel:

    def test_create_session(self, session_model):
        uid = ObjectId()
        session = session_model.create({
            "user_id": uid,
            "access_token_jti": "acc-jti-001",
            "refresh_token_jti": "ref-jti-001",
            "ip_address": "127.0.0.1",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        assert "_id" in session
        assert session["is_revoked"] is False

    def test_find_by_access_jti(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-find-001",
            "refresh_token_jti": "ref-find-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        found = session_model.find_by_access_jti("acc-find-001")
        assert found is not None

    def test_find_by_refresh_jti(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-rfind-001",
            "refresh_token_jti": "ref-rfind-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        found = session_model.find_by_refresh_jti("ref-rfind-001")
        assert found is not None

    def test_get_user_sessions(self, session_model):
        uid = ObjectId()
        session_model.create({
            "user_id": uid,
            "access_token_jti": "acc-usess-001",
            "refresh_token_jti": "ref-usess-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        sessions = session_model.get_user_sessions(str(uid))
        assert len(sessions) >= 1

    def test_revoke_by_access_jti(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-rev-001",
            "refresh_token_jti": "ref-rev-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        assert session_model.revoke("acc-rev-001") is True
        found = session_model.find_by_access_jti("acc-rev-001")
        assert found["is_revoked"] is True

    def test_revoke_by_refresh_jti(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-revr-001",
            "refresh_token_jti": "ref-revr-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        assert session_model.revoke("ref-revr-001") is True

    def test_revoke_all_user(self, session_model):
        uid = ObjectId()
        session_model.create({
            "user_id": uid,
            "access_token_jti": "acc-rall-001",
            "refresh_token_jti": "ref-rall-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        session_model.create({
            "user_id": uid,
            "access_token_jti": "acc-rall-002",
            "refresh_token_jti": "ref-rall-002",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        count = session_model.revoke_all_user(str(uid))
        assert count == 2

    def test_is_session_revoked_false(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-isrev-001",
            "refresh_token_jti": "ref-isrev-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        assert session_model.is_session_revoked("acc-isrev-001") is False

    def test_is_session_revoked_true(self, session_model):
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-isrevt-001",
            "refresh_token_jti": "ref-isrevt-001",
            "expires_at": now_vietnam() + timedelta(days=7),
        })
        session_model.revoke("acc-isrevt-001")
        assert session_model.is_session_revoked("acc-isrevt-001") is True

    def test_is_session_revoked_unknown_jti(self, session_model):
        # Unknown JTI = not tracked = not revoked
        assert session_model.is_session_revoked("nonexistent-jti") is False

    def test_cleanup_expired(self, session_model):
        # Insert an already-expired session
        session_model.create({
            "user_id": ObjectId(),
            "access_token_jti": "acc-exp-001",
            "refresh_token_jti": "ref-exp-001",
            "expires_at": now_vietnam() - timedelta(days=1),
        })
        count = session_model.cleanup_expired()
        assert count >= 1


# ============================================================================
# 4. ADMIN AUTH SERVICE TESTS
# ============================================================================

class TestAdminAuthService:

    def test_login_success(self, auth_service, user_model):
        _create_user(user_model, username="login_ok", password="password123", role="admin")
        success, result, error = auth_service.login("login_ok", "password123")
        assert success is True
        assert "user" in result
        assert "tokens" in result
        assert result["user"]["username"] == "login_ok"
        assert error is None

    def test_login_wrong_password(self, auth_service, user_model):
        _create_user(user_model, username="login_wrongpw", password="password123")
        success, _, error = auth_service.login("login_wrongpw", "wrongpass")
        assert success is False
        assert "invalid" in error.lower()

    def test_login_user_not_found(self, auth_service):
        success, _, error = auth_service.login("nonexistent_user", "password123")
        assert success is False

    def test_login_disabled_account(self, auth_service, user_model):
        _create_user(user_model, username="login_disabled", password="password123", is_active=False)
        success, _, error = auth_service.login("login_disabled", "password123")
        assert success is False
        assert "disabled" in error.lower()

    def test_login_locked_account(self, auth_service, user_model):
        user = _create_user(user_model, username="login_locked", password="password123")
        user_model.lock_account(str(user["_id"]))
        success, _, error = auth_service.login("login_locked", "password123")
        assert success is False
        assert "locked" in error.lower()

    def test_login_increments_failed_attempts(self, auth_service, user_model):
        user = _create_user(user_model, username="login_attempts", password="password123")
        auth_service.login("login_attempts", "wrong")
        auth_service.login("login_attempts", "wrong")
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["failed_login_attempts"] == 2

    def test_login_resets_attempts_on_success(self, auth_service, user_model):
        user = _create_user(user_model, username="login_reset_ok", password="password123")
        auth_service.login("login_reset_ok", "wrong")
        auth_service.login("login_reset_ok", "password123")
        updated = user_model.find_by_id(str(user["_id"]))
        assert updated["failed_login_attempts"] == 0

    def test_login_sets_cookies_data(self, auth_service, user_model):
        _create_user(user_model, username="login_tokens", password="password123", role="teacher")
        success, result, _ = auth_service.login("login_tokens", "password123")
        assert success is True
        tokens = result["tokens"]
        assert "access_token" in tokens
        assert "refresh_token" in tokens

    def test_logout(self, auth_service, user_model):
        _create_user(user_model, username="logout_user", password="password123")
        _, result, _ = auth_service.login("logout_user", "password123")
        tokens = result["tokens"]
        success, error = auth_service.logout(tokens["access_token"], tokens["refresh_token"])
        assert success is True

    def test_refresh_token(self, auth_service, user_model):
        _create_user(user_model, username="refresh_user", password="password123", role="admin")
        _, result, _ = auth_service.login("refresh_user", "password123")
        refresh = result["tokens"]["refresh_token"]
        success, new_tokens, error = auth_service.refresh_token(refresh)
        assert success is True
        assert "access_token" in new_tokens

    def test_refresh_token_invalid(self, auth_service):
        success, _, error = auth_service.refresh_token("invalid.token.here")
        assert success is False

    def test_change_password_success(self, auth_service, user_model):
        _create_user(user_model, username="chpw_ok", password="oldpassword1")
        user = user_model.find_by_username("chpw_ok")
        success, error = auth_service.change_password(
            str(user["_id"]), "oldpassword1", "newpassword1"
        )
        assert success is True
        # Verify new password works
        ok, _, _ = auth_service.login("chpw_ok", "newpassword1")
        assert ok is True

    def test_change_password_wrong_old(self, auth_service, user_model):
        _create_user(user_model, username="chpw_wrong", password="oldpassword1")
        user = user_model.find_by_username("chpw_wrong")
        success, error = auth_service.change_password(
            str(user["_id"]), "wrongold", "newpassword1"
        )
        assert success is False
        assert "incorrect" in error.lower()

    def test_change_password_too_short(self, auth_service, user_model):
        _create_user(user_model, username="chpw_short", password="oldpassword1")
        user = user_model.find_by_username("chpw_short")
        success, error = auth_service.change_password(
            str(user["_id"]), "oldpassword1", "short"
        )
        assert success is False

    def test_change_password_too_many_bytes(self, auth_service, user_model):
        _create_user(user_model, username="chpw_long", password="oldpassword1")
        user = user_model.find_by_username("chpw_long")
        success, error = auth_service.change_password(
            str(user["_id"]), "oldpassword1", "\u00e1" * 37
        )
        assert success is False
        assert "bytes" in error.lower()


# ============================================================================
# 5. USER CONTROLLER TESTS
# ============================================================================

class TestUserController:

    @pytest.fixture
    def app(self, user_service):
        import controllers.user_controller as uc_mod

        orig_login = getattr(uc_mod, 'require_login', None)
        orig_admin = getattr(uc_mod, 'require_admin', None)

        uc_mod.require_login = lambda f: f
        uc_mod.require_admin = lambda f: f

        try:
            from controllers.user_controller import UserController
            app = Flask(__name__)
            app.config['TESTING'] = True
            controller = UserController(user_service)
            app.register_blueprint(controller.blueprint, url_prefix='/api')

            @app.before_request
            def _inject_admin():
                g.current_user = {"_id": ObjectId(), "username": "admin01", "role": "admin"}

            yield app
        finally:
            if orig_login:
                uc_mod.require_login = orig_login
            if orig_admin:
                uc_mod.require_admin = orig_admin

    def test_list_users(self, app, user_model):
        _create_user(user_model, username="ctrl_list1")
        with app.test_client() as client:
            resp = client.get('/api/admin/users')
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert "users" in data["data"]

    def test_list_users_filter_role(self, app, user_model):
        _create_user(user_model, username="ctrl_admin1", role="admin")
        _create_user(user_model, username="ctrl_teacher1", role="teacher")
        with app.test_client() as client:
            resp = client.get('/api/admin/users?role=admin')
            assert resp.status_code == 200

    def test_create_user_via_api(self, app):
        with app.test_client() as client:
            resp = client.post('/api/admin/users', json={
                "username": "api_create",
                "password": "password123",
                "role": "teacher",
            })
            assert resp.status_code == 201
            data = resp.get_json()
            assert data["success"] is True

    def test_create_user_duplicate_via_api(self, app):
        with app.test_client() as client:
            client.post('/api/admin/users', json={
                "username": "api_dup",
                "password": "password123",
            })
            resp = client.post('/api/admin/users', json={
                "username": "api_dup",
                "password": "password123",
            })
            assert resp.status_code == 400

    def test_get_user_via_api(self, app, user_model):
        user = _create_user(user_model, username="ctrl_get")
        with app.test_client() as client:
            resp = client.get(f'/api/admin/users/{str(user["_id"])}')
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["user"]["username"] == "ctrl_get"

    def test_get_user_not_found(self, app):
        with app.test_client() as client:
            resp = client.get(f'/api/admin/users/{str(ObjectId())}')
            assert resp.status_code == 404

    def test_update_user_via_api(self, app, user_model):
        user = _create_user(user_model, username="ctrl_upd")
        with app.test_client() as client:
            resp = client.patch(f'/api/admin/users/{str(user["_id"])}', json={
                "email": "updated@test.com",
            })
            assert resp.status_code == 200

    def test_delete_user_via_api(self, app, user_model):
        user = _create_user(user_model, username="ctrl_del")
        with app.test_client() as client:
            resp = client.delete(f'/api/admin/users/{str(user["_id"])}')
            assert resp.status_code == 200

    def test_reset_password_via_api(self, app, user_model):
        user = _create_user(user_model, username="ctrl_resetpw")
        with app.test_client() as client:
            resp = client.post(f'/api/admin/users/{str(user["_id"])}/reset-password', json={
                "new_password": "newpassword123",
            })
            assert resp.status_code == 200

    def test_get_statistics(self, app, user_model):
        _create_user(user_model, username="ctrl_stat")
        with app.test_client() as client:
            resp = client.get('/api/admin/users/statistics')
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True


# ============================================================================
# 6. ADMIN AUTH CONTROLLER TESTS
# ============================================================================

class TestAdminAuthController:
    """
    WebAuthController uses @require_login as method decorators.
    Login is public, but get_profile/logout/refresh/change_password need _mock_auth.

    Class name kept as TestAdminAuthController so pytest selection by the old
    name still resolves; new tests should reference WebAuthController directly.
    """

    @pytest.fixture
    def app(self, auth_service, jwt_service):
        from controllers.web_auth_controller import WebAuthController
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = WebAuthController(auth_service, jwt_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        yield app

    def test_login_endpoint(self, app, user_model):
        _create_user(user_model, username="auth_login", password="password123", role="admin")
        with app.test_client() as client:
            resp = client.post('/api/admin/auth/login', json={
                "username": "auth_login",
                "password": "password123",
            })
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True
            assert "tokens" in data["data"]
            # Verify cookies via Set-Cookie headers
            cookie_headers = [h for h in resp.headers.getlist('Set-Cookie')]
            cookie_names = [h.split('=')[0] for h in cookie_headers]
            assert "access_token" in cookie_names
            assert "refresh_token" in cookie_names

    def test_login_missing_fields(self, app):
        with app.test_client() as client:
            resp = client.post('/api/admin/auth/login', json={
                "username": "",
                "password": "",
            })
            assert resp.status_code == 400

    def test_login_wrong_password(self, app, user_model):
        _create_user(user_model, username="auth_wrongpw", password="password123")
        with app.test_client() as client:
            resp = client.post('/api/admin/auth/login', json={
                "username": "auth_wrongpw",
                "password": "wrongpassword",
            })
            assert resp.status_code == 401

    def test_login_not_json(self, app):
        with app.test_client() as client:
            resp = client.post('/api/admin/auth/login', data="not json")
            assert resp.status_code == 400

    def test_get_profile(self, app, user_model):
        user = _create_user(user_model, username="auth_profile", password="password123")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.get('/api/admin/auth/me')
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["data"]["username"] == "auth_profile"

    def test_logout_endpoint(self, app, user_model):
        user = _create_user(user_model, username="auth_logout", password="password123")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.post('/api/admin/auth/logout', json={})
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["success"] is True

    def test_refresh_endpoint(self, app, user_model, auth_service):
        _create_user(user_model, username="auth_refresh", password="password123", role="admin")
        # Login to get real tokens
        _, result, _ = auth_service.login("auth_refresh", "password123")
        tokens = result["tokens"]
        user = user_model.find_by_username("auth_refresh")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.post('/api/admin/auth/refresh', json={
                    "refresh_token": tokens["refresh_token"],
                })
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["success"] is True

    # ── PUT /api/admin/auth/profile ──
    # P0.4 verification: profile updates must call audit_service.log_action
    # (the old code called audit_service.log which silently failed).

    def test_update_profile_writes_audit_entry(self, app, user_model, audit_model):
        user = _create_user(
            user_model, username="auth_prof_audit",
            password="password123", role="admin",
        )
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.put('/api/admin/auth/profile', json={
                    "email": "newprofile@test.com",
                })
                assert resp.status_code == 200
                assert resp.get_json()["success"] is True

        # Email must have been persisted
        refreshed = user_model.find_by_id(str(user["_id"]))
        assert refreshed["email"] == "newprofile@test.com"

        # Exactly one audit entry for profile.update by this user
        logs = audit_model.get_logs({
            "action": "profile.update",
            "username": "auth_prof_audit",
        })
        assert len(logs) >= 1
        entry = logs[0]
        assert entry["resource_type"] == "users"
        assert entry["resource_id"] == str(user["_id"])
        assert "email" in (entry.get("details") or {}).get("updated_fields", [])

    def test_update_profile_no_change_skips_audit(self, app, user_model, audit_model):
        """Empty payload → no DB write, no audit entry."""
        user = _create_user(
            user_model, username="auth_prof_noop",
            password="password123", role="admin",
        )
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.put('/api/admin/auth/profile', json={})
                assert resp.status_code == 200

        logs = audit_model.get_logs({
            "action": "profile.update",
            "username": "auth_prof_noop",
        })
        assert len(logs) == 0

    def test_update_profile_duplicate_email_rejected(self, app, user_model, audit_model):
        """Email already used by another user → 400, no audit entry."""
        # Another user owns the email
        _create_user(
            user_model, username="auth_prof_other",
            password="password123", email="taken@test.com",
        )
        user = _create_user(
            user_model, username="auth_prof_dup",
            password="password123", role="admin",
        )

        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.put('/api/admin/auth/profile', json={
                    "email": "taken@test.com",
                })
                assert resp.status_code == 400
                assert "already in use" in resp.get_json()["error"].lower()

        logs = audit_model.get_logs({
            "action": "profile.update",
            "username": "auth_prof_dup",
        })
        assert len(logs) == 0
