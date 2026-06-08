"""
Test Suite: Audit Model, Service, Controller
=============================================
1. AuditModel  - log, get_logs, get_user_activity, count_logs
2. AuditService - log_action, get_logs, get_user_activity, count_logs, serialization
3. AuditController - list_logs, user_activity (permission checks)

Run:
  cd server && python -m pytest tests/test_audit.py -v
"""

import pytest
import sys
import os
from bson import ObjectId
from unittest.mock import patch
from flask import Flask, g

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.audit_model import AuditModel
from services.audit_service import AuditService
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


TEST_DB = 'test_saint_audit'


@pytest.fixture
def db(mongo_client):
    from bson.codec_options import CodecOptions
    codec = CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)
    database = mongo_client.get_database(TEST_DB, codec_options=codec)
    yield database
    mongo_client.drop_database(TEST_DB)


@pytest.fixture
def audit_model(db):
    return AuditModel(db)


@pytest.fixture
def audit_service(audit_model):
    return AuditService(audit_model)


# ============================================================================
# HELPERS
# ============================================================================

def make_admin():
    return {"_id": ObjectId(), "username": "admin01", "role": "admin"}


def make_teacher(tid=None):
    return {"_id": tid or ObjectId(), "username": "teacher01", "role": "teacher"}


def _mock_auth(user):
    return patch.multiple(
        'middleware.rbac',
        _extract_token=lambda: 'fake-token',
        _validate_admin_token=lambda token: (True, user, None),
    )


# ============================================================================
# 1. AUDIT MODEL TESTS
# ============================================================================

class TestAuditModel:

    def test_log_creates_entry(self, audit_model):
        entry = audit_model.log({
            "user_id": ObjectId(),
            "username": "admin01",
            "role": "admin",
            "action": "user.create",
            "resource_type": "users",
            "resource_id": str(ObjectId()),
            "details": {"created_username": "teacher01"},
            "ip_address": "127.0.0.1",
        })
        assert "_id" in entry
        assert entry["action"] == "user.create"
        assert "timestamp" in entry

    def test_log_sets_timestamp(self, audit_model):
        entry = audit_model.log({
            "user_id": ObjectId(),
            "username": "test",
            "action": "auth.login",
            "resource_type": "auth",
        })
        assert entry.get("timestamp") is not None

    def test_get_logs_empty(self, audit_model):
        logs = audit_model.get_logs()
        assert isinstance(logs, list)

    def test_get_logs_returns_entries(self, audit_model):
        uid = ObjectId()
        audit_model.log({"user_id": uid, "username": "a", "action": "test.action1", "resource_type": "test"})
        audit_model.log({"user_id": uid, "username": "a", "action": "test.action2", "resource_type": "test"})
        logs = audit_model.get_logs()
        assert len(logs) >= 2

    def test_get_logs_with_filter(self, audit_model):
        audit_model.log({"user_id": ObjectId(), "username": "x", "action": "filter.target", "resource_type": "special"})
        audit_model.log({"user_id": ObjectId(), "username": "y", "action": "filter.other", "resource_type": "normal"})
        logs = audit_model.get_logs({"resource_type": "special"})
        actions = [l["action"] for l in logs]
        assert "filter.target" in actions

    def test_get_logs_limit(self, audit_model):
        for i in range(5):
            audit_model.log({"user_id": ObjectId(), "username": "u", "action": f"limit.{i}", "resource_type": "test"})
        logs = audit_model.get_logs(limit=2)
        assert len(logs) == 2

    def test_get_logs_skip(self, audit_model):
        uid = ObjectId()
        for i in range(5):
            audit_model.log({"user_id": uid, "username": "u", "action": f"skip.{i}", "resource_type": "test"})
        all_logs = audit_model.get_logs({"action": {"$regex": "^skip\\."}})
        skipped = audit_model.get_logs({"action": {"$regex": "^skip\\."}}, skip=2)
        assert len(skipped) == len(all_logs) - 2

    def test_get_logs_sorted_desc(self, audit_model):
        audit_model.log({"user_id": ObjectId(), "username": "first", "action": "sort.1", "resource_type": "test"})
        audit_model.log({"user_id": ObjectId(), "username": "second", "action": "sort.2", "resource_type": "test"})
        logs = audit_model.get_logs({"action": {"$regex": "^sort\\."}})
        # Most recent first
        assert logs[0]["action"] == "sort.2"

    def test_get_user_activity(self, audit_model):
        uid = ObjectId()
        audit_model.log({"user_id": uid, "username": "target", "action": "ua.action1", "resource_type": "test"})
        audit_model.log({"user_id": ObjectId(), "username": "other", "action": "ua.action2", "resource_type": "test"})
        activity = audit_model.get_user_activity(str(uid))
        assert len(activity) >= 1
        assert all(a["user_id"] == uid for a in activity)

    def test_get_user_activity_limit(self, audit_model):
        uid = ObjectId()
        for i in range(5):
            audit_model.log({"user_id": uid, "username": "u", "action": f"ual.{i}", "resource_type": "test"})
        activity = audit_model.get_user_activity(str(uid), limit=2)
        assert len(activity) == 2

    def test_count_logs(self, audit_model):
        audit_model.log({"user_id": ObjectId(), "username": "u", "action": "cnt.1", "resource_type": "count_test"})
        audit_model.log({"user_id": ObjectId(), "username": "u", "action": "cnt.2", "resource_type": "count_test"})
        count = audit_model.count_logs({"resource_type": "count_test"})
        assert count >= 2

    def test_count_logs_no_filter(self, audit_model):
        audit_model.log({"user_id": ObjectId(), "username": "u", "action": "any", "resource_type": "test"})
        count = audit_model.count_logs()
        assert count >= 1


# ============================================================================
# 2. AUDIT SERVICE TESTS
# ============================================================================

class TestAuditService:

    def test_log_action_basic(self, audit_service, audit_model):
        user = make_admin()
        audit_service.log_action(
            user=user,
            action="user.create",
            resource_type="users",
            resource_id=str(ObjectId()),
            details={"created_username": "newteacher"},
            ip_address="10.0.0.1",
        )
        logs = audit_model.get_logs({"action": "user.create"})
        assert len(logs) >= 1

    def test_log_action_auto_ip(self, audit_service, audit_model):
        """When no ip_address provided and outside request context, uses 'unknown'."""
        user = make_teacher()
        audit_service.log_action(
            user=user,
            action="test.auto_ip",
            resource_type="test",
        )
        logs = audit_model.get_logs({"action": "test.auto_ip"})
        assert len(logs) >= 1
        assert logs[0].get("ip_address") == "unknown"

    def test_log_action_with_flask_request(self, audit_service, audit_model):
        """Within Flask request context, auto-detects IP."""
        app = Flask(__name__)
        user = make_admin()
        with app.test_request_context(environ_base={'REMOTE_ADDR': '192.168.1.100'}):
            audit_service.log_action(
                user=user,
                action="test.flask_ip",
                resource_type="test",
            )
        logs = audit_model.get_logs({"action": "test.flask_ip"})
        assert logs[0].get("ip_address") == "192.168.1.100"

    def test_log_action_stores_user_info(self, audit_service, audit_model):
        user = make_teacher()
        audit_service.log_action(
            user=user,
            action="test.user_info",
            resource_type="test",
        )
        logs = audit_model.get_logs({"action": "test.user_info"})
        entry = logs[0]
        assert entry["username"] == "teacher01"
        assert entry["role"] == "teacher"
        assert entry["user_id"] == user["_id"]

    def test_get_logs_serialized(self, audit_service, audit_model):
        user = make_admin()
        audit_service.log_action(user=user, action="test.serial", resource_type="test")
        logs = audit_service.get_logs({"action": "test.serial"})
        assert len(logs) >= 1
        # _id and user_id should be strings
        assert isinstance(logs[0]["_id"], str)
        assert isinstance(logs[0]["user_id"], str)

    def test_get_user_activity_serialized(self, audit_service, audit_model):
        user = make_admin()
        audit_service.log_action(user=user, action="test.ua_serial", resource_type="test")
        activity = audit_service.get_user_activity(str(user["_id"]))
        assert len(activity) >= 1
        assert isinstance(activity[0]["_id"], str)

    def test_count_logs(self, audit_service, audit_model):
        user = make_admin()
        audit_service.log_action(user=user, action="test.count_svc", resource_type="count_svc")
        count = audit_service.count_logs({"resource_type": "count_svc"})
        assert count >= 1

    def test_log_action_never_raises(self, audit_service):
        """Audit logging should never block the main operation."""
        # Pass garbage user - should not raise
        audit_service.log_action(
            user={},
            action="test.safe",
            resource_type="test",
        )

    def test_log_action_with_resource_id(self, audit_service, audit_model):
        user = make_admin()
        rid = ObjectId()
        audit_service.log_action(
            user=user,
            action="test.with_rid",
            resource_type="test",
            resource_id=str(rid),
        )
        logs = audit_model.get_logs({"action": "test.with_rid"})
        assert logs[0]["resource_id"] == str(rid)

    def test_log_action_without_resource_id(self, audit_service, audit_model):
        user = make_admin()
        audit_service.log_action(
            user=user,
            action="test.no_rid",
            resource_type="test",
        )
        logs = audit_model.get_logs({"action": "test.no_rid"})
        assert logs[0]["resource_id"] is None


# ============================================================================
# 3. AUDIT CONTROLLER TESTS
# ============================================================================

class TestAuditController:
    """
    AuditController uses @require_login and @require_permission as method decorators,
    so they are bound at class definition time. We must patch the middleware internals
    (_extract_token, _validate_admin_token) so the real decorators pass.
    """

    @pytest.fixture
    def app(self, audit_service):
        from controllers.audit_controller import AuditController
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = AuditController(audit_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        yield app

    def test_list_logs(self, app, audit_service):
        admin = make_admin()
        audit_service.log_action(user=admin, action="ctrl.list", resource_type="ctrl_test")
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/admin/audit')
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["success"] is True
                assert "logs" in data["data"]
                assert "total" in data["data"]

    def test_list_logs_with_action_filter(self, app, audit_service):
        admin = make_admin()
        audit_service.log_action(user=admin, action="ctrl.filter_target", resource_type="ctrl_test")
        audit_service.log_action(user=admin, action="ctrl.other", resource_type="ctrl_test")
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/admin/audit?action=ctrl.filter_target')
                assert resp.status_code == 200
                data = resp.get_json()
                logs = data["data"]["logs"]
                assert all(l["action"] == "ctrl.filter_target" for l in logs)

    def test_list_logs_with_resource_type_filter(self, app, audit_service):
        admin = make_admin()
        audit_service.log_action(user=admin, action="ctrl.rt", resource_type="special_rt")
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/admin/audit?resource_type=special_rt')
                assert resp.status_code == 200
                data = resp.get_json()
                logs = data["data"]["logs"]
                assert len(logs) >= 1

    def test_list_logs_with_username_filter(self, app, audit_service):
        user = {"_id": ObjectId(), "username": "unique_user_xyz", "role": "admin"}
        audit_service.log_action(user=user, action="ctrl.un", resource_type="test")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.get('/api/admin/audit?username=unique_user_xyz')
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["data"]["total"] >= 1

    def test_list_logs_pagination(self, app, audit_service):
        admin = make_admin()
        for i in range(5):
            audit_service.log_action(user=admin, action=f"ctrl.page.{i}", resource_type="page_test")
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/admin/audit?limit=2&skip=0')
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["data"]["limit"] == 2
                assert len(data["data"]["logs"]) <= 2

    def test_user_activity(self, app, audit_service):
        uid = ObjectId()
        user = {"_id": uid, "username": "activity_user", "role": "admin"}
        audit_service.log_action(user=user, action="ctrl.activity", resource_type="test")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.get(f'/api/admin/audit/user/{str(uid)}')
                assert resp.status_code == 200
                data = resp.get_json()
                assert data["success"] is True
                assert "logs" in data["data"]

    def test_user_activity_limit(self, app, audit_service):
        uid = ObjectId()
        user = {"_id": uid, "username": "lim_user", "role": "admin"}
        for i in range(5):
            audit_service.log_action(user=user, action=f"ctrl.alim.{i}", resource_type="test")
        with _mock_auth(user):
            with app.test_client() as client:
                resp = client.get(f'/api/admin/audit/user/{str(uid)}?limit=2')
                assert resp.status_code == 200
                data = resp.get_json()
                assert len(data["data"]["logs"]) <= 2
