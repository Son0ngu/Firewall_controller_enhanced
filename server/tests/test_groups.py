"""
Comprehensive Test Suite: Group Management
============================================
Tests toàn bộ chức năng Group:
1. GroupModel     - CRUD operations trực tiếp trên MongoDB
2. GroupService   - Business logic, ObjectId serialization, validation
3. GroupController - HTTP endpoints, RBAC teacher/admin filtering
4. Agent Policy   - Policy wiring qua group context

Sử dụng REAL MongoDB (test database) thay vì mock để đảm bảo
integration đúng. Database tự cleanup sau mỗi test.

Run:
  cd server && python -m pytest tests/test_groups.py -v
  cd server && python -m pytest tests/test_groups.py -v -k "test_model"
  cd server && python -m pytest tests/test_groups.py -v -k "test_service"
  cd server && python -m pytest tests/test_groups.py -v -k "test_controller"
"""

import pytest
import sys
import os
import json
from unittest.mock import MagicMock, patch
from bson import ObjectId
from flask import Flask, g

# Add server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.group_model import GroupModel
from models.agent_model import AgentModel
from services.group_service import GroupService
from services.rbac_service import RBACService
from controllers.group_controller import GroupController


# ============================================================================
# FIXTURES - Database & Models (real MongoDB)
# ============================================================================

@pytest.fixture(scope='session')
def mongo_client():
    """Create MongoDB client using same config as server (.env)."""
    from pymongo import MongoClient
    from dotenv import load_dotenv
    import os

    # Load .env from server directory
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path)

    uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    yield client
    client.close()


TEST_DB_NAME = 'test_saint_groups'


@pytest.fixture
def db(mongo_client):
    """Fresh test database - dropped after each test."""
    database = mongo_client[TEST_DB_NAME]
    yield database
    mongo_client.drop_database(TEST_DB_NAME)


@pytest.fixture
def group_model(db):
    return GroupModel(db)


@pytest.fixture
def agent_model(db):
    return AgentModel(db)


@pytest.fixture
def group_service(group_model, agent_model):
    return GroupService(group_model, agent_model)


@pytest.fixture
def rbac_service(group_model, agent_model):
    return RBACService(group_model, agent_model)


# ============================================================================
# FIXTURES - Users
# ============================================================================

ADMIN_ID = ObjectId("650000000000000000000001")
TEACHER_A_ID = ObjectId("650000000000000000000002")
TEACHER_B_ID = ObjectId("650000000000000000000003")


@pytest.fixture
def admin_user():
    return {
        "_id": ADMIN_ID,
        "username": "admin",
        "role": "admin",
        "is_active": True,
    }


@pytest.fixture
def teacher_a():
    return {
        "_id": TEACHER_A_ID,
        "username": "teacher_a",
        "role": "teacher",
        "is_active": True,
    }


@pytest.fixture
def teacher_b():
    return {
        "_id": TEACHER_B_ID,
        "username": "teacher_b",
        "role": "teacher",
        "is_active": True,
    }


# ============================================================================
# FIXTURES - Flask App & Controller
# ============================================================================

@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret'
    return app


@pytest.fixture
def group_controller(group_service, rbac_service):
    return GroupController(group_service, rbac_service)


@pytest.fixture
def client(app, group_controller):
    """Flask test client with group blueprint registered."""
    app.register_blueprint(group_controller.blueprint, url_prefix='/api')
    return app.test_client()


# ============================================================================
# 1. MODEL TESTS - GroupModel CRUD trực tiếp trên MongoDB
# ============================================================================

class TestGroupModel:
    """Test GroupModel - thao tác trực tiếp MongoDB collection."""

    def test_model_create_group_basic(self, group_model):
        """Tạo group cơ bản - phải có đầy đủ fields."""
        group = group_model.create_group("Lop 10A", "Mo ta", [])
        assert group["name"] == "Lop 10A"
        assert group["description"] == "Mo ta"
        assert group["whitelist"] == []
        assert group["whitelist_version"] == 1
        assert group["is_system"] is False
        assert "_id" in group
        assert group["created_at"] is not None
        assert group["updated_at"] is not None

    def test_model_create_group_with_owner(self, group_model):
        """Tạo group với created_by - cho RBAC ownership."""
        group = group_model.create_group("Lop 10B", "", [], created_by=TEACHER_A_ID)
        assert group["created_by"] == TEACHER_A_ID
        assert isinstance(group["created_by"], ObjectId)

    def test_model_create_group_with_whitelist(self, group_model):
        """Tạo group kèm whitelist entries."""
        wl = [{"domain": "google.com", "type": "domain"}]
        group = group_model.create_group("Lop WL", "", wl)
        assert len(group["whitelist"]) == 1
        assert group["whitelist"][0]["domain"] == "google.com"

    def test_model_create_duplicate_name_fails(self, group_model):
        """Tạo 2 group cùng tên - MongoDB unique index phải reject."""
        group_model.create_group("DuplicateName", "", [])
        with pytest.raises(Exception):
            group_model.create_group("DuplicateName", "", [])

    def test_model_find_by_id(self, group_model):
        """Tìm group bằng ID - cả string và ObjectId."""
        created = group_model.create_group("FindMe", "", [])
        gid = str(created["_id"])

        found = group_model.find_by_id(gid)
        assert found is not None
        assert found["name"] == "FindMe"

    def test_model_find_by_id_not_found(self, group_model):
        """Tìm group không tồn tại - trả None."""
        found = group_model.find_by_id(str(ObjectId()))
        assert found is None

    def test_model_find_by_id_invalid(self, group_model):
        """ID không hợp lệ - trả None thay vì crash."""
        found = group_model.find_by_id("invalid-id")
        assert found is None

    def test_model_list_groups_empty(self, group_model):
        """List groups khi DB rỗng - trả empty list."""
        # Drop the pending group if exists
        group_model.collection.delete_many({})
        groups = group_model.list_groups()
        assert groups == []

    def test_model_list_groups_all(self, group_model):
        """List tất cả groups - không filter."""
        group_model.create_group("G1", "", [])
        group_model.create_group("G2", "", [])
        groups = group_model.list_groups()
        names = [g["name"] for g in groups]
        assert "G1" in names
        assert "G2" in names

    def test_model_list_groups_with_filter(self, group_model):
        """List groups với query filter - chỉ trả groups match."""
        group_model.create_group("TeacherA_G1", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("TeacherB_G1", "", [], created_by=TEACHER_B_ID)

        filtered = group_model.list_groups({"created_by": TEACHER_A_ID})
        assert len(filtered) == 1
        assert filtered[0]["name"] == "TeacherA_G1"

    def test_model_update_group_name(self, group_model):
        """Update tên group."""
        created = group_model.create_group("OldName", "", [])
        gid = str(created["_id"])

        updated = group_model.update_group(gid, {"name": "NewName"})
        assert updated["name"] == "NewName"
        assert updated["updated_at"] != created["updated_at"]

    def test_model_update_group_description(self, group_model):
        """Update description."""
        created = group_model.create_group("DescTest", "old desc", [])
        gid = str(created["_id"])

        updated = group_model.update_group(gid, {"description": "new desc"})
        assert updated["description"] == "new desc"

    def test_model_update_group_whitelist(self, group_model):
        """Update whitelist entries."""
        created = group_model.create_group("WLUpdate", "", [])
        gid = str(created["_id"])

        new_wl = [{"domain": "example.com", "type": "domain"}]
        updated = group_model.update_group(gid, {
            "whitelist": new_wl,
            "whitelist_version": 2
        })
        assert len(updated["whitelist"]) == 1
        assert updated["whitelist_version"] == 2

    def test_model_update_group_whitelist_normalizes_string_id(self, group_model):
        """PATCH payload from frontend sends _id as string; DB must keep ObjectId."""
        entry_oid = ObjectId()
        created = group_model.create_group("WLStringId", "", [])
        gid = str(created["_id"])

        updated = group_model.update_group(gid, {
            "whitelist": [{
                "_id": str(entry_oid),
                "value": "example.com",
                "type": "domain",
            }]
        })

        assert updated["whitelist"][0]["_id"] == entry_oid
        assert isinstance(updated["whitelist"][0]["_id"], ObjectId)

    def test_model_update_group_whitelist_stamps_missing_id(self, group_model):
        """New embedded entries from group PATCH receive a real ObjectId."""
        created = group_model.create_group("WLMissingId", "", [])
        gid = str(created["_id"])

        updated = group_model.update_group(gid, {
            "whitelist": [{"value": "new-entry.com", "type": "domain"}]
        })

        assert isinstance(updated["whitelist"][0]["_id"], ObjectId)

    def test_model_update_group_layout(self, group_model):
        """Update layout (room layout config)."""
        created = group_model.create_group("LayoutTest", "", [])
        gid = str(created["_id"])

        layout = {"rows": 4, "cols": 5}
        updated = group_model.update_group(gid, {"layout": layout})
        assert updated["layout"] == layout

    def test_model_update_nonexistent_group(self, group_model):
        """Update group không tồn tại - trả None."""
        result = group_model.update_group(str(ObjectId()), {"name": "Ghost"})
        assert result is None

    def test_model_delete_group(self, group_model):
        """Xóa group - trả True."""
        created = group_model.create_group("DeleteMe", "", [])
        gid = str(created["_id"])

        assert group_model.delete_group(gid) is True
        assert group_model.find_by_id(gid) is None

    def test_model_delete_nonexistent_group(self, group_model):
        """Xóa group không tồn tại - trả False."""
        assert group_model.delete_group(str(ObjectId())) is False

    def test_model_bump_whitelist_version(self, group_model):
        """Bump whitelist version - tăng 1."""
        created = group_model.create_group("BumpTest", "", [])
        gid = str(created["_id"])
        assert created["whitelist_version"] == 1

        bumped = group_model.bump_whitelist_version(gid)
        assert bumped["whitelist_version"] == 2

        bumped2 = group_model.bump_whitelist_version(gid)
        assert bumped2["whitelist_version"] == 3

    def test_model_ensure_pending_group_created(self, group_model):
        """Ensure pending group - tạo nếu chưa có."""
        # Call ensure_pending_group explicitly (also called in __init__)
        pending = group_model.ensure_pending_group()
        assert pending is not None
        assert pending["is_system"] is True
        assert pending["name"] == "pending"

    def test_model_ensure_pending_group_idempotent(self, group_model):
        """Ensure pending group - gọi lại không tạo duplicate."""
        p1 = group_model.ensure_pending_group()
        p2 = group_model.ensure_pending_group()
        assert p1["_id"] == p2["_id"]


# ============================================================================
# 2. SERVICE TESTS - GroupService business logic
# ============================================================================

class TestGroupService:
    """Test GroupService - business logic + ObjectId serialization."""

    def test_service_list_groups_serialization(self, group_service, group_model):
        """List groups - _id và created_by phải là string, không phải ObjectId."""
        group_model.create_group("SerG1", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("SerG2", "", [], created_by=TEACHER_B_ID)

        groups = group_service.list_groups()
        for g in groups:
            assert isinstance(g["_id"], str), f"_id should be str, got {type(g['_id'])}"
            if g.get("created_by"):
                assert isinstance(g["created_by"], str), \
                    f"created_by should be str, got {type(g['created_by'])}"

    def test_service_list_groups_with_filter(self, group_service, group_model):
        """List groups với teacher filter - chỉ trả groups thuộc teacher."""
        group_model.create_group("SvFilterA", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("SvFilterB", "", [], created_by=TEACHER_B_ID)

        filtered = group_service.list_groups(query_filter={"created_by": TEACHER_A_ID})
        assert all(g["created_by"] == str(TEACHER_A_ID) for g in filtered)
        names = [g["name"] for g in filtered]
        assert "SvFilterA" in names
        assert "SvFilterB" not in names

    def test_service_create_group(self, group_service):
        """Tạo group qua service - _id phải là string."""
        group = group_service.create_group("SvcNew", "desc", [])
        assert isinstance(group["_id"], str)
        assert group["name"] == "SvcNew"

    def test_service_create_group_with_owner(self, group_service):
        """Tạo group với owner - created_by phải là string sau serialize."""
        group = group_service.create_group("SvcOwned", "", [], created_by=TEACHER_A_ID)
        assert isinstance(group["created_by"], str)
        assert group["created_by"] == str(TEACHER_A_ID)

    def test_service_get_group(self, group_service, group_model):
        """Get single group - serialized correctly."""
        created = group_model.create_group("SvcGet", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        group = group_service.get_group(gid)
        assert group["name"] == "SvcGet"
        assert isinstance(group["_id"], str)
        assert isinstance(group["created_by"], str)

    def test_service_get_group_not_found(self, group_service):
        """Get group không tồn tại - raise ValueError."""
        with pytest.raises(ValueError, match="Group not found"):
            group_service.get_group(str(ObjectId()))

    def test_service_update_group(self, group_service, group_model):
        """Update group - serialized correctly."""
        created = group_model.create_group("SvcUpd", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        updated = group_service.update_group(gid, {"name": "SvcUpdated"})
        assert updated["name"] == "SvcUpdated"
        assert isinstance(updated["_id"], str)
        if updated.get("created_by"):
            assert isinstance(updated["created_by"], str)

    def test_service_update_group_not_found(self, group_service):
        """Update group không tồn tại - raise ValueError."""
        with pytest.raises(ValueError, match="Group not found"):
            group_service.update_group(str(ObjectId()), {"name": "Ghost"})

    def test_service_update_whitelist_bumps_version(self, group_service, group_model):
        """Update whitelist - version tự tăng."""
        created = group_model.create_group("SvcWLBump", "", [])
        gid = str(created["_id"])

        updated = group_service.update_group(gid, {
            "whitelist": [{"domain": "test.com"}]
        })
        assert updated["whitelist_version"] == 2

    def test_service_update_system_group_flag_rejected(self, group_service, group_model):
        """Không cho phép thay đổi is_system flag."""
        # The pending group is a system group
        pending = group_model.ensure_pending_group()
        gid = str(pending["_id"])

        with pytest.raises(ValueError, match="System group flags cannot be changed"):
            group_service.update_group(gid, {"is_system": False})

    def test_service_delete_group(self, group_service, group_model):
        """Xóa group thành công."""
        created = group_model.create_group("SvcDel", "", [])
        gid = str(created["_id"])

        result = group_service.delete_group(gid)
        assert result is True

        with pytest.raises(ValueError):
            group_service.get_group(gid)

    def test_service_delete_group_not_found(self, group_service):
        """Xóa group không tồn tại - raise ValueError."""
        with pytest.raises(ValueError, match="Group not found"):
            group_service.delete_group(str(ObjectId()))

    def test_service_delete_system_group_rejected(self, group_service, group_model):
        """Không cho phép xóa system group (pending)."""
        pending = group_model.ensure_pending_group()
        gid = str(pending["_id"])

        with pytest.raises(ValueError, match="Cannot delete system groups"):
            group_service.delete_group(gid)

    def test_service_delete_group_with_agents_moves_to_pending(self, group_service, group_model, agent_model):
        """Group có agents thì khi xóa, agents được dời sang pending trước.

        Hành vi mới: thay vì raise ValueError, service tự đảm bảo không mồ côi agent
        bằng cách bulk-move sang pending group rồi xóa group cũ.
        """
        # Ensure the pending system group exists so the migration path can run
        pending = group_model.ensure_pending_group()
        pending_id = str(pending["_id"])

        created = group_model.create_group("HasAgents", "", [])
        gid = str(created["_id"])

        agent_model.collection.insert_one({
            "agent_id": "test-agent-001",
            "hostname": "PC-1",
            "group_id": gid,
        })

        # Should succeed (no ValueError) and reassign the agent to pending
        result = group_service.delete_group(gid)
        assert result is True

        relocated = agent_model.collection.find_one({"agent_id": "test-agent-001"})
        assert relocated is not None
        assert relocated["group_id"] == pending_id

    def test_service_bump_whitelist_version(self, group_service, group_model):
        """Bump whitelist version qua service."""
        created = group_model.create_group("SvcBump", "", [])
        gid = str(created["_id"])

        bumped = group_service.bump_group_whitelist_version(gid)
        assert bumped["whitelist_version"] == 2
        assert isinstance(bumped["_id"], str)

    def test_service_get_pending_group_id(self, group_service):
        """Get pending group ID - string format."""
        pid = group_service.get_pending_group_id()
        assert isinstance(pid, str)
        assert len(pid) == 24  # ObjectId hex length

    def test_service_json_serializable(self, group_service, group_model):
        """Tất cả output của service phải JSON serializable - không còn ObjectId."""
        group_model.create_group("JsonTest", "desc", [{"domain": "x.com"}], created_by=TEACHER_A_ID)

        groups = group_service.list_groups()
        # Sẽ raise TypeError nếu có ObjectId chưa convert
        json_str = json.dumps(groups, default=str)
        assert json_str is not None

        # Stricter check - không dùng default=str
        for g in groups:
            for key, val in g.items():
                assert not isinstance(val, ObjectId), \
                    f"Field '{key}' is still ObjectId: {val}"


# ============================================================================
# 3. CONTROLLER TESTS - HTTP endpoints + RBAC
# ============================================================================

class TestGroupController:
    """Test GroupController - HTTP endpoints qua Flask test client.

    Sử dụng patch middleware.rbac._validate_admin_token để giả lập
    authentication - inject_current_user decorator sẽ gọi hàm này
    và set g.current_user tự động.
    """

    def _mock_auth(self, user):
        """Return patch context manager that fakes auth for given user."""
        return patch.multiple(
            'middleware.rbac',
            _extract_token=lambda: 'fake-token',
            _validate_admin_token=lambda token: (True, user, None),
        )

    def test_controller_web_routes_require_login(self, client, group_model):
        """Unauthenticated web-facing group routes must not expose data."""
        group = group_model.create_group("PrivateGroup", "", [])
        gid = str(group["_id"])

        cases = [
            ("get", "/api/groups", None),
            ("get", f"/api/groups/{gid}", None),
            ("patch", f"/api/groups/{gid}", {"name": "NoAuth"}),
            ("delete", f"/api/groups/{gid}", None),
            ("post", f"/api/groups/{gid}/teachers", {"teacher_ids": []}),
        ]

        for method_name, path, payload in cases:
            method = getattr(client, method_name)
            kwargs = {"json": payload} if payload is not None else {}
            resp = method(path, **kwargs)

            assert resp.status_code == 401, path
            assert resp.get_json()["error"] == "Authentication required"

    # ── LIST GROUPS ──

    def test_controller_list_groups_admin(self, app, client, group_model, admin_user):
        """Admin list groups - thấy tất cả."""
        group_model.create_group("CtrlA1", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("CtrlB1", "", [], created_by=TEACHER_B_ID)

        with self._mock_auth(admin_user):
            resp = client.get('/api/groups')

        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        names = [g["name"] for g in data["data"]]
        assert "CtrlA1" in names
        assert "CtrlB1" in names

    def test_controller_list_groups_teacher_filtered(self, app, client, group_model, teacher_a):
        """Teacher list groups - chỉ thấy groups mình tạo."""
        group_model.create_group("TeacherAGroup", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("TeacherBGroup", "", [], created_by=TEACHER_B_ID)

        with self._mock_auth(teacher_a):
            resp = client.get('/api/groups')

        assert resp.status_code == 200
        data = resp.get_json()
        names = [g["name"] for g in data["data"]]
        assert "TeacherAGroup" in names
        assert "TeacherBGroup" not in names

    def test_controller_list_groups_teacher_empty(self, app, client, group_model, teacher_b):
        """Teacher mới - chưa tạo group nào, list trả rỗng (trừ pending)."""
        group_model.create_group("OtherGroup", "", [], created_by=TEACHER_A_ID)

        with self._mock_auth(teacher_b):
            resp = client.get('/api/groups')

        data = resp.get_json()
        # Teacher B chỉ thấy groups có created_by = TEACHER_B_ID hoặc no owner
        for g in data["data"]:
            if g.get("created_by"):
                assert g["created_by"] == str(TEACHER_B_ID)

    # ── GET SINGLE GROUP ──

    def test_controller_get_group_admin(self, app, client, group_model, admin_user):
        """Admin get bất kỳ group nào - OK."""
        created = group_model.create_group("AdminGet", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        with self._mock_auth(admin_user):
            resp = client.get(f'/api/groups/{gid}')

        assert resp.status_code == 200
        assert resp.get_json()["data"]["name"] == "AdminGet"

    def test_controller_get_group_teacher_own(self, app, client, group_model, teacher_a):
        """Teacher get group mình tạo - OK."""
        created = group_model.create_group("MyGroup", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.get(f'/api/groups/{gid}')

        assert resp.status_code == 200
        assert resp.get_json()["data"]["name"] == "MyGroup"

    def test_controller_get_group_teacher_forbidden(self, app, client, group_model, teacher_a):
        """Teacher get group của teacher khác - 403."""
        created = group_model.create_group("NotMine", "", [], created_by=TEACHER_B_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.get(f'/api/groups/{gid}')

        assert resp.status_code == 403

    def test_controller_get_group_not_found(self, app, client, admin_user):
        """Get group không tồn tại - 404."""
        with self._mock_auth(admin_user):
            resp = client.get(f'/api/groups/{str(ObjectId())}')

        assert resp.status_code == 404

    # ── CREATE GROUP ──

    def test_controller_create_group_admin(self, app, client, admin_user):
        """Admin tạo group - created_by = admin ID."""
        with self._mock_auth(admin_user):
            resp = client.post('/api/groups', json={
                "name": "AdminCreated",
                "description": "Test"
            })

        assert resp.status_code == 201
        data = resp.get_json()["data"]
        assert data["name"] == "AdminCreated"
        assert data["created_by"] == str(ADMIN_ID)

    def test_controller_create_group_teacher_forbidden(self, app, client, teacher_a):
        """Teacher KHÔNG được tạo group (admin-only lifecycle) - 403."""
        with self._mock_auth(teacher_a):
            resp = client.post('/api/groups', json={
                "name": "TeacherCreated",
                "description": "My class"
            })

        assert resp.status_code == 403

    def test_controller_create_group_no_name(self, app, client, admin_user):
        """Tạo group thiếu name - 400."""
        with self._mock_auth(admin_user):
            resp = client.post('/api/groups', json={"description": "no name"})

        assert resp.status_code == 400
        assert resp.get_json()["error"] == "Name is required"

    def test_controller_create_group_with_whitelist(self, app, client, admin_user):
        """Tạo group kèm whitelist."""
        with self._mock_auth(admin_user):
            resp = client.post('/api/groups', json={
                "name": "WLGroup",
                "whitelist": [{"domain": "edu.vn", "type": "domain"}]
            })

        assert resp.status_code == 201
        assert len(resp.get_json()["data"]["whitelist"]) == 1

    def test_controller_create_group_duplicate_name(self, app, client, group_model, admin_user):
        """Tạo group trùng tên - 400."""
        group_model.create_group("DupCtrl", "", [])

        with self._mock_auth(admin_user):
            resp = client.post('/api/groups', json={"name": "DupCtrl"})

        assert resp.status_code == 400

    # ── UPDATE GROUP ──

    def test_controller_update_group_admin(self, app, client, group_model, admin_user):
        """Admin update bất kỳ group - OK."""
        created = group_model.create_group("UpdAdmin", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        with self._mock_auth(admin_user):
            resp = client.patch(f'/api/groups/{gid}', json={"name": "UpdAdminNew"})

        assert resp.status_code == 200
        assert resp.get_json()["data"]["name"] == "UpdAdminNew"

    def test_controller_update_group_teacher_own_forbidden(self, app, client, group_model, teacher_a):
        """Teacher update group mình tạo - OK."""
        created = group_model.create_group("UpdTeacher", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.patch(f'/api/groups/{gid}', json={"description": "updated"})

        assert resp.status_code == 403

    def test_controller_update_group_teacher_forbidden(self, app, client, group_model, teacher_a):
        """Teacher update group của teacher khác - 403."""
        created = group_model.create_group("UpdForbid", "", [], created_by=TEACHER_B_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.patch(f'/api/groups/{gid}', json={"name": "Hacked"})

        assert resp.status_code == 403

    # ── DELETE GROUP ──

    def test_controller_delete_group_admin(self, app, client, group_model, admin_user):
        """Admin xóa group - OK."""
        created = group_model.create_group("DelAdmin", "", [])
        gid = str(created["_id"])

        with self._mock_auth(admin_user):
            resp = client.delete(f'/api/groups/{gid}')

        assert resp.status_code == 200
        assert resp.get_json()["success"] is True

    def test_controller_delete_group_teacher_own_forbidden(self, app, client, group_model, teacher_a):
        """Teacher xóa group mình tạo - OK."""
        created = group_model.create_group("DelTeacher", "", [], created_by=TEACHER_A_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.delete(f'/api/groups/{gid}')

        assert resp.status_code == 403

    def test_controller_delete_group_teacher_forbidden(self, app, client, group_model, teacher_a):
        """Teacher xóa group của teacher khác - 403."""
        created = group_model.create_group("DelForbid", "", [], created_by=TEACHER_B_ID)
        gid = str(created["_id"])

        with self._mock_auth(teacher_a):
            resp = client.delete(f'/api/groups/{gid}')

        assert resp.status_code == 403

    def test_controller_delete_system_group_rejected(self, app, client, group_model, admin_user):
        """Xóa system group (pending) - 400."""
        pending = group_model.ensure_pending_group()
        gid = str(pending["_id"])

        with self._mock_auth(admin_user):
            resp = client.delete(f'/api/groups/{gid}')

        assert resp.status_code == 400
        assert "system" in resp.get_json()["error"].lower()


# ============================================================================
# 4. RBAC SERVICE TESTS - Permission & ownership logic for groups
# ============================================================================

class TestRBACGroupFiltering:
    """Test RBACService - group-related filtering logic."""

    def test_rbac_admin_sees_all_groups(self, rbac_service, admin_user):
        """Admin - get_group_query_filter trả None (no filter)."""
        qf = rbac_service.get_group_query_filter(admin_user)
        assert qf is None

    def test_rbac_teacher_filter_by_ownership(self, rbac_service, teacher_a):
        """Teacher - filter groups by teacher_ids (current) + created_by (legacy fallback)."""
        qf = rbac_service.get_group_query_filter(teacher_a)
        assert qf == {"$or": [
            {"teacher_ids": TEACHER_A_ID},
            {"created_by": TEACHER_A_ID},
        ]}

    def test_rbac_can_access_group_admin(self, rbac_service, admin_user):
        """Admin can access any group."""
        group = {"_id": ObjectId(), "created_by": TEACHER_B_ID}
        assert rbac_service.can_access_group(admin_user, group) is True

    def test_rbac_can_access_group_teacher_own(self, rbac_service, teacher_a):
        """Teacher can access own group."""
        group = {"_id": ObjectId(), "created_by": TEACHER_A_ID}
        assert rbac_service.can_access_group(teacher_a, group) is True

    def test_rbac_can_access_group_teacher_other(self, rbac_service, teacher_a):
        """Teacher cannot access other teacher's group."""
        group = {"_id": ObjectId(), "created_by": TEACHER_B_ID}
        assert rbac_service.can_access_group(teacher_a, group) is False

    def test_rbac_can_access_group_no_owner(self, rbac_service, teacher_a):
        """Teacher cannot access group with no created_by (legacy)."""
        group = {"_id": ObjectId()}
        assert rbac_service.can_access_group(teacher_a, group) is False

    def test_rbac_is_owner(self, rbac_service):
        """is_owner - match by string comparison."""
        resource = {"created_by": TEACHER_A_ID}
        assert rbac_service.is_owner(str(TEACHER_A_ID), resource) is True
        assert rbac_service.is_owner(str(TEACHER_B_ID), resource) is False

    def test_rbac_filter_groups_in_memory(self, rbac_service, admin_user, teacher_a):
        """filter_groups_for_user - admin gets all, teacher gets own."""
        groups = [
            {"_id": "1", "name": "A", "created_by": TEACHER_A_ID},
            {"_id": "2", "name": "B", "created_by": TEACHER_B_ID},
        ]

        admin_result = rbac_service.filter_groups_for_user(admin_user, groups)
        assert len(admin_result) == 2

        teacher_result = rbac_service.filter_groups_for_user(teacher_a, groups)
        assert len(teacher_result) == 1
        assert teacher_result[0]["name"] == "A"

    def test_rbac_get_teacher_group_ids(self, rbac_service, group_model, teacher_a, admin_user):
        """get_teacher_group_ids - teacher gets list, admin gets None."""
        group_model.create_group("RBACG1", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("RBACG2", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("RBACG3", "", [], created_by=TEACHER_B_ID)

        # Admin
        assert rbac_service.get_teacher_group_ids(admin_user) is None

        # Teacher A - should have 2 groups
        ids = rbac_service.get_teacher_group_ids(teacher_a)
        assert isinstance(ids, list)
        assert len(ids) == 2

    def test_rbac_validate_group_ids_ownership(self, rbac_service, group_model, teacher_a, admin_user):
        """validate_group_ids_ownership - teacher chỉ sở hữu groups mình tạo."""
        g1 = group_model.create_group("OwnA", "", [], created_by=TEACHER_A_ID)
        g2 = group_model.create_group("OwnB", "", [], created_by=TEACHER_B_ID)
        gid1, gid2 = str(g1["_id"]), str(g2["_id"])

        # Admin - always valid
        valid, invalid = rbac_service.validate_group_ids_ownership(admin_user, [gid1, gid2])
        assert valid is True

        # Teacher A - owns gid1 but not gid2
        valid, invalid = rbac_service.validate_group_ids_ownership(teacher_a, [gid1])
        assert valid is True

        valid, invalid = rbac_service.validate_group_ids_ownership(teacher_a, [gid2])
        assert valid is False
        assert gid2 in invalid


# ============================================================================
# 5. INTEGRATION TESTS - Cross-layer scenarios
# ============================================================================

class TestGroupIntegration:
    """Integration tests - full flow qua nhiều layer."""

    def test_create_then_list_then_delete(self, group_service):
        """Full lifecycle: create → list → delete."""
        created = group_service.create_group("Lifecycle", "test")
        gid = created["_id"]

        groups = group_service.list_groups()
        names = [g["name"] for g in groups]
        assert "Lifecycle" in names

        group_service.delete_group(gid)

        groups = group_service.list_groups()
        names = [g["name"] for g in groups]
        assert "Lifecycle" not in names

    def test_teacher_isolation_full_flow(self, group_service, rbac_service, group_model, teacher_a, teacher_b):
        """Teacher A tạo group, Teacher B không thấy và không access được."""
        # Teacher A creates
        group_model.create_group("IsoA", "", [], created_by=TEACHER_A_ID)
        group_model.create_group("IsoB", "", [], created_by=TEACHER_B_ID)

        # Teacher A filter
        filter_a = rbac_service.get_group_query_filter(teacher_a)
        groups_a = group_service.list_groups(query_filter=filter_a)
        names_a = [g["name"] for g in groups_a]
        assert "IsoA" in names_a
        assert "IsoB" not in names_a

        # Teacher B filter
        filter_b = rbac_service.get_group_query_filter(teacher_b)
        groups_b = group_service.list_groups(query_filter=filter_b)
        names_b = [g["name"] for g in groups_b]
        assert "IsoB" in names_b
        assert "IsoA" not in names_b

    def test_update_whitelist_version_consistency(self, group_service, group_model):
        """Update whitelist qua service - version tăng đúng."""
        created = group_model.create_group("VerConsist", "", [])
        gid = str(created["_id"])

        # Update whitelist 3 lần
        for i in range(3):
            group_service.update_group(gid, {
                "whitelist": [{"domain": f"v{i+1}.com"}]
            })

        group = group_service.get_group(gid)
        assert group["whitelist_version"] == 4  # 1 (initial) + 3 bumps
        assert group["whitelist"][0]["domain"] == "v3.com"

    def test_json_response_no_objectid(self, app, client, group_model, admin_user):
        """API response phải JSON-safe - không có ObjectId nào leak."""
        group_model.create_group("JsonSafe", "test", [], created_by=TEACHER_A_ID)

        with patch.multiple(
            'middleware.rbac',
            _extract_token=lambda: 'fake-token',
            _validate_admin_token=lambda token: (True, admin_user, None),
        ):
            resp = client.get('/api/groups')

        assert resp.status_code == 200
        # If this doesn't raise, all values are JSON-serializable
        raw = resp.data.decode()
        parsed = json.loads(raw)
        assert parsed["success"] is True
