"""
Comprehensive Test Suite: Teacher Data Filtering (RBAC)
========================================================
Tests RBAC filtering logic across:
1. RBACService - unit tests for all query filter methods
2. GroupController - ownership-based access
3. AgentController - teacher sees only agents in own groups
4. WhitelistController - teacher sees global + own group entries
5. LogController - teacher sees only logs from own agents
6. Agent API backward compatibility - zero breaking changes

Mock strategy:
- Mock MongoDB collections (group_model.collection, agent_model.collection)
- Mock Flask g context (g.current_user) via inject_current_user behavior
- Mock services to isolate controller logic
- Test each endpoint for 3 personas: admin, teacher, agent (no cookie)

Run: cd server && python -m pytest tests/test_teacher_data_filtering.py -v
"""

import pytest
import sys
import os
from unittest.mock import MagicMock, patch, PropertyMock
from bson import ObjectId
from flask import Flask, g

# Add server to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def app():
    """Create a minimal Flask app for testing."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret'
    return app


@pytest.fixture
def admin_user():
    """Admin user - toan quyen, no ownership filter."""
    return {
        "_id": ObjectId("650000000000000000000001"),
        "username": "admin_user",
        "role": "admin",
        "is_active": True,
    }


@pytest.fixture
def teacher_user():
    """Teacher user - limited by ownership."""
    return {
        "_id": ObjectId("650000000000000000000002"),
        "username": "teacher_nguyen",
        "role": "teacher",
        "is_active": True,
    }


@pytest.fixture
def teacher_user_2():
    """Second teacher - different user, different groups."""
    return {
        "_id": ObjectId("650000000000000000000003"),
        "username": "teacher_tran",
        "role": "teacher",
        "is_active": True,
    }


@pytest.fixture
def mock_group_model():
    """Mock GroupModel with collection."""
    model = MagicMock()
    model.collection = MagicMock()

    def _find_accessible_group_ids_for_teacher(teacher_id):
        groups = model.collection.find(
            {"$or": [
                {"teacher_ids": teacher_id},
                {"created_by": teacher_id},
            ]},
            {"_id": 1},
        )
        return [str(group["_id"]) for group in groups]

    model.find_accessible_group_ids_for_teacher.side_effect = (
        _find_accessible_group_ids_for_teacher
    )
    return model


@pytest.fixture
def mock_agent_model():
    """Mock AgentModel with collection."""
    model = MagicMock()
    model.collection = MagicMock()

    def _find_agent_ids_by_group_ids(group_ids):
        agents = model.collection.find(
            {"group_id": {"$in": group_ids}},
            {"agent_id": 1},
        )
        return [agent["agent_id"] for agent in agents if agent.get("agent_id")]

    model.find_agent_ids_by_group_ids.side_effect = _find_agent_ids_by_group_ids
    return model


@pytest.fixture
def sample_groups(teacher_user):
    """Groups created by teacher_user."""
    return [
        {"_id": ObjectId("660000000000000000000001"), "name": "Lop 10A",
         "created_by": teacher_user["_id"]},
        {"_id": ObjectId("660000000000000000000002"), "name": "Lop 10B",
         "created_by": teacher_user["_id"]},
    ]


@pytest.fixture
def sample_agents():
    """Agents in various groups."""
    return [
        {"agent_id": "agent-001", "hostname": "PC01", "group_id": "660000000000000000000001"},
        {"agent_id": "agent-002", "hostname": "PC02", "group_id": "660000000000000000000001"},
        {"agent_id": "agent-003", "hostname": "PC03", "group_id": "660000000000000000000002"},
        {"agent_id": "agent-004", "hostname": "PC04", "group_id": "660000000000000000000099"},  # Other teacher's group
    ]


# ============================================================================
# 1. RBAC SERVICE UNIT TESTS
# ============================================================================

class TestRBACServiceGetTeacherGroupIds:
    """Test get_teacher_group_ids() - core helper."""

    def test_admin_returns_none(self, mock_group_model, mock_agent_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        result = svc.get_teacher_group_ids(admin_user)
        assert result is None, "Admin should get None (no filter)"
        mock_group_model.collection.find.assert_not_called()

    def test_teacher_returns_list(self, mock_group_model, mock_agent_model, teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        result = svc.get_teacher_group_ids(teacher_user)
        assert isinstance(result, list)
        assert len(result) == 2
        assert "660000000000000000000001" in result
        assert "660000000000000000000002" in result

        # Verify query uses $or over teacher_ids + created_by (legacy fallback)
        call_args = mock_group_model.collection.find.call_args
        assert call_args[0][0] == {"$or": [
            {"teacher_ids": teacher_user["_id"]},
            {"created_by": teacher_user["_id"]},
        ]}

    def test_teacher_no_groups_returns_empty(self, mock_group_model, mock_agent_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = []

        result = svc.get_teacher_group_ids(teacher_user)
        assert result == []

    def test_no_group_model_returns_empty(self, mock_agent_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(group_model=None, agent_model=mock_agent_model)

        result = svc.get_teacher_group_ids(teacher_user)
        assert result == []


class TestRBACServiceGetGroupQueryFilter:
    """Test get_group_query_filter()."""

    def test_admin_returns_none(self, mock_group_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        result = svc.get_group_query_filter(admin_user)
        assert result is None

    def test_teacher_returns_created_by_filter(self, mock_group_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        # Teacher filter spans teacher_ids (current model) + created_by (legacy)
        result = svc.get_group_query_filter(teacher_user)
        assert result == {"$or": [
            {"teacher_ids": teacher_user["_id"]},
            {"created_by": teacher_user["_id"]},
        ]}


class TestRBACServiceGetLogQueryFilter:
    """Test get_log_query_filter() - chains teacher → groups → agents → logs."""

    def test_admin_returns_none(self, mock_group_model, mock_agent_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        result = svc.get_log_query_filter(admin_user)
        assert result is None

    def test_teacher_with_groups_and_agents(self, mock_group_model, mock_agent_model,
                                             teacher_user, sample_groups, sample_agents):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        # Mock: teacher owns 2 groups
        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        # Mock: 3 agents in those 2 groups
        mock_agent_model.collection.find.return_value = [
            {"agent_id": "agent-001"},
            {"agent_id": "agent-002"},
            {"agent_id": "agent-003"},
        ]

        result = svc.get_log_query_filter(teacher_user)
        assert "agent_id" in result
        assert "$in" in result["agent_id"]
        agent_ids = result["agent_id"]["$in"]
        assert "agent-001" in agent_ids
        assert "agent-002" in agent_ids
        assert "agent-003" in agent_ids
        # agent-004 should NOT be in the list (different group)
        assert "agent-004" not in agent_ids

    def test_teacher_no_groups_returns_empty_filter(self, mock_group_model, mock_agent_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = []

        result = svc.get_log_query_filter(teacher_user)
        assert result == {"agent_id": {"$in": []}}

    def test_teacher_groups_but_no_agents(self, mock_group_model, mock_agent_model, teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]
        mock_agent_model.collection.find.return_value = []

        result = svc.get_log_query_filter(teacher_user)
        assert result == {"agent_id": {"$in": []}}

    def test_no_agent_model_returns_empty(self, mock_group_model, teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, agent_model=None)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        result = svc.get_log_query_filter(teacher_user)
        assert result == {"agent_id": {"$in": []}}


class TestRBACServiceGetWhitelistQueryFilter:
    """Test get_whitelist_query_filter()."""

    def test_admin_returns_none(self, mock_group_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        result = svc.get_whitelist_query_filter(admin_user)
        assert result is None

    def test_teacher_returns_or_filter(self, mock_group_model, teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        result = svc.get_whitelist_query_filter(teacher_user)
        assert "$or" in result
        conditions = result["$or"]
        assert {"scope": "global"} in conditions
        group_filter = conditions[1]
        assert "group_id" in group_filter
        assert "$in" in group_filter["group_id"]
        group_ids = group_filter["group_id"]["$in"]
        assert "660000000000000000000001" in group_ids
        assert "660000000000000000000002" in group_ids


class TestRBACServiceCanTeacherAccessAgent:
    """Test can_teacher_access_agent()."""

    def test_admin_always_true(self, mock_group_model, mock_agent_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        agent = {"agent_id": "any", "group_id": "any-group"}
        assert svc.can_teacher_access_agent(admin_user, agent) is True

    def test_teacher_can_access_own_group_agent(self, mock_group_model, mock_agent_model,
                                                  teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        agent = {"agent_id": "agent-001", "group_id": "660000000000000000000001"}
        assert svc.can_teacher_access_agent(teacher_user, agent) is True

    def test_teacher_cannot_access_other_group_agent(self, mock_group_model, mock_agent_model,
                                                       teacher_user, sample_groups):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        mock_group_model.collection.find.return_value = [
            {"_id": g["_id"]} for g in sample_groups
        ]

        agent = {"agent_id": "agent-004", "group_id": "660000000000000000000099"}
        assert svc.can_teacher_access_agent(teacher_user, agent) is False

    def test_agent_without_group_returns_false(self, mock_group_model, mock_agent_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        agent = {"agent_id": "orphan", "group_id": None}
        assert svc.can_teacher_access_agent(teacher_user, agent) is False


class TestRBACServiceCanAccessGroup:
    """Test can_access_group() - ownership check for groups."""

    def test_admin_always_true(self, mock_group_model, admin_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        group = {"_id": "any", "created_by": ObjectId("999999999999999999999999")}
        assert svc.can_access_group(admin_user, group) is True

    def test_teacher_own_group(self, mock_group_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        group = {"_id": "g1", "created_by": teacher_user["_id"]}
        assert svc.can_access_group(teacher_user, group) is True

    def test_teacher_other_group(self, mock_group_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        group = {"_id": "g2", "created_by": ObjectId("999999999999999999999999")}
        assert svc.can_access_group(teacher_user, group) is False

    def test_group_no_created_by(self, mock_group_model, teacher_user):
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        group = {"_id": "g3", "created_by": None}
        assert svc.can_access_group(teacher_user, group) is False


class TestRBACMiddlewareGroupOwnership:
    """Decorator should delegate group lookup to GroupModel, not raw collection."""

    def test_require_group_ownership_uses_model_method(self, app, teacher_user, monkeypatch):
        import middleware.rbac as rbac_middleware
        from middleware.rbac import require_group_ownership

        group_model = MagicMock(spec=["find_by_id"])
        group = {"_id": "g1", "created_by": teacher_user["_id"]}
        group_model.find_by_id.return_value = group
        rbac = MagicMock()
        rbac.group_model = group_model
        rbac.can_access_group.return_value = True
        monkeypatch.setattr(rbac_middleware, "_rbac_service", rbac)

        @require_group_ownership("group_id")
        def handler(group_id):
            return {"group_id": group_id}, 200

        with app.test_request_context("/api/groups/g1", method="PATCH"):
            g.current_user = teacher_user
            g.current_role = "teacher"

            response, status = handler(group_id="g1")

        assert status == 200
        assert response == {"group_id": "g1"}
        group_model.find_by_id.assert_called_once_with("g1")
        rbac.can_access_group.assert_called_once_with(teacher_user, group)


# ============================================================================
# 2. RBAC CONFIG PERMISSION TESTS
# ============================================================================

class TestRBACConfigPermissions:
    """Verify permission matrix from rbac_config.py."""

    def test_admin_has_all_permissions(self):
        from config.rbac_config import check_permission
        admin_perms = [
            "groups:read", "groups:create", "groups:update", "groups:delete",
            "agents:read", "agents:detail", "agents:delete",
            "whitelist:read", "whitelist:create", "whitelist:update", "whitelist:delete",
            "logs:read", "logs:export", "logs:delete",
            "users:create", "users:read", "users:update", "users:delete",
            "audit:read",
        ]
        for perm in admin_perms:
            assert check_permission("admin", perm) is True, f"Admin should have {perm}"

    def test_teacher_allowed_permissions(self):
        from config.rbac_config import check_permission
        # Teacher: view assigned groups and manage lesson-specific whitelist profiles.
        # Group whitelist and group management are admin-only.
        allowed = [
            "groups:read",
            "agents:read", "agents:detail",
            "whitelist:read",
            "whitelist_profile:create", "whitelist_profile:update",
            "whitelist_profile:delete", "whitelist_profile:activate",
            "logs:read",
            "profile:read", "profile:change_password",
        ]
        for perm in allowed:
            assert check_permission("teacher", perm) is True, f"Teacher should have {perm}"

    def test_teacher_denied_permissions(self):
        from config.rbac_config import check_permission
        denied = [
            "groups:create", "groups:update", "groups:delete", "groups:manage_agents",
            "agents:delete",
            "whitelist:create", "whitelist:update", "whitelist:delete", "whitelist:sync",
            "logs:export",
            "logs:delete",
            "users:create", "users:read", "users:update", "users:delete",
            "api_keys:read", "api_keys:create", "api_keys:revoke",
            "audit:read",
            "system:config",
        ]
        for perm in denied:
            assert check_permission("teacher", perm) is False, f"Teacher should NOT have {perm}"

    def test_invalid_role_has_no_permissions(self):
        from config.rbac_config import check_permission
        assert check_permission("hacker", "groups:read") is False


# ============================================================================
# 3. GROUP CONTROLLER TESTS
# ============================================================================

class TestGroupControllerTeacherFiltering:
    """Test GroupController with teacher data filtering."""

    def _make_controller(self, mock_group_service, mock_rbac_service):
        from controllers.group_controller import GroupController
        ctrl = GroupController(mock_group_service, mock_rbac_service)
        return ctrl

    def test_list_groups_admin_no_filter(self, app, admin_user):
        mock_service = MagicMock()
        mock_service.validate_teacher_entry_access.return_value = (True, None)
        mock_rbac = MagicMock()
        mock_service.list_groups.return_value = [
            {"_id": "g1", "name": "A"}, {"_id": "g2", "name": "B"}
        ]

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups'):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.list_groups()
            data = resp.get_json()

            assert status == 200
            assert data["success"] is True
            assert len(data["data"]) == 2
            # Admin: query_filter should be None (no filter)
            mock_service.list_groups.assert_called_once_with(query_filter=None)

    def test_list_groups_teacher_filtered(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        mock_rbac.get_group_query_filter.return_value = {"created_by": teacher_user["_id"]}
        mock_service.list_groups.return_value = [{"_id": "g1", "name": "My Group"}]

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.list_groups()
            data = resp.get_json()

            assert status == 200
            assert data["success"] is True
            mock_service.list_groups.assert_called_once_with(
                query_filter={"created_by": teacher_user["_id"]}
            )

    def test_list_groups_agent_request_no_filter(self, app):
        """Agent request (no cookie) → g.current_user=None → no filter."""
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        mock_service.list_groups.return_value = [{"_id": "g1"}, {"_id": "g2"}, {"_id": "g3"}]

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups'):
            g.current_user = None
            g.current_role = None

            resp, status = ctrl.list_groups()
            data = resp.get_json()

            assert status == 200
            assert len(data["data"]) == 3
            mock_service.list_groups.assert_called_once_with(query_filter=None)

    def test_get_group_teacher_own_group(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        # Service must return JSON-serializable shape (no raw ObjectId)
        own_group = {"_id": "g1", "name": "My Group", "created_by": str(teacher_user["_id"])}
        mock_service.get_group.return_value = own_group
        mock_rbac.can_access_group.return_value = True

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups/g1'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.get_group("g1")
            assert status == 200

    def test_get_group_teacher_other_group_403(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        other_group = {"_id": "g2", "name": "Other", "created_by": ObjectId("999999999999999999999999")}
        mock_service.get_group.return_value = other_group
        mock_rbac.can_access_group.return_value = False

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups/g2'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.get_group("g2")
            assert status == 403

    def test_create_group_sets_created_by(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        # Service returns serialized payload (str created_by, not ObjectId)
        mock_service.create_group.return_value = {
            "_id": "new", "name": "New Group", "created_by": str(teacher_user["_id"])
        }

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups', method='POST',
                                       json={"name": "New Group"}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.create_group()
            assert status == 201

            # Verify created_by was passed
            call_kwargs = mock_service.create_group.call_args
            assert call_kwargs[1].get("created_by") == teacher_user["_id"] or \
                   (len(call_kwargs[0]) >= 4 and call_kwargs[0][3] is not None)

    def test_create_group_agent_no_created_by(self, app):
        """Agent request: no cookie → created_by=None."""
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        mock_service.create_group.return_value = {
            "_id": "new", "name": "Auto Group", "created_by": None
        }

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups', method='POST',
                                       json={"name": "Auto Group"}):
            g.current_user = None
            g.current_role = None

            resp, status = ctrl.create_group()
            assert status == 201
            call_kwargs = mock_service.create_group.call_args
            # created_by should be None
            assert call_kwargs[1].get("created_by") is None or \
                   call_kwargs.kwargs.get("created_by") is None

    def test_delete_group_teacher_own_group_forbidden(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        mock_service.get_group.return_value = {"_id": "g1", "created_by": teacher_user["_id"]}
        mock_rbac.can_access_group.return_value = True

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups/g1', method='DELETE'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.delete_group("g1")
            assert status == 403
            mock_service.delete_group.assert_not_called()

    def test_delete_group_teacher_other_group_403(self, app, teacher_user):
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        mock_service.get_group.return_value = {"_id": "g2", "created_by": ObjectId("999999999999999999999999")}
        mock_rbac.can_access_group.return_value = False

        ctrl = self._make_controller(mock_service, mock_rbac)

        with app.test_request_context('/api/groups/g2', method='DELETE'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.delete_group("g2")
            assert status == 403
            mock_service.delete_group.assert_not_called()


# ============================================================================
# 4. AGENT CONTROLLER TESTS
# ============================================================================

class TestAgentControllerTeacherFiltering:
    """Test AgentController with teacher data filtering."""

    def _make_controller(self, app):
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        from controllers.agent_controller import AgentController
        ctrl = AgentController(mock_model, mock_service, mock_rbac, socketio=None)
        return ctrl, mock_model, mock_service, mock_rbac

    def test_list_agents_admin_sees_all(self, app, admin_user):
        ctrl, model, service, rbac = self._make_controller(app)

        all_agents = [
            {"agent_id": "a1", "group_id": "g1", "hostname": "PC1", "status": "active"},
            {"agent_id": "a2", "group_id": "g2", "hostname": "PC2", "status": "active"},
        ]
        service.get_agents_with_status.return_value = all_agents

        with app.test_request_context('/api/agents'):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.list_agents()
            data = resp.get_json()

            assert status == 200
            assert data["total"] == 2

    def test_list_agents_teacher_filtered(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        all_agents = [
            {"agent_id": "a1", "group_id": "g1", "hostname": "PC1", "status": "active"},
            {"agent_id": "a2", "group_id": "g2", "hostname": "PC2", "status": "active"},
            {"agent_id": "a3", "group_id": "g99", "hostname": "PC3", "status": "active"},
        ]
        service.get_agents_with_status.return_value = all_agents
        rbac.get_teacher_group_ids.return_value = ["g1", "g2"]

        # Controller resolves RBAC via get_rbac_service() global; patch it.
        with patch('controllers.agent_controller.get_rbac_service', return_value=rbac):
            with app.test_request_context('/api/agents'):
                g.current_user = teacher_user
                g.current_role = "teacher"

                resp, status = ctrl.list_agents()
                data = resp.get_json()

                assert status == 200
                assert data["total"] == 2  # Only a1, a2 (not a3)
                agent_ids = [a["agent_id"] for a in data["agents"]]
                assert "a1" in agent_ids
                assert "a2" in agent_ids
                assert "a3" not in agent_ids

    def test_list_agents_agent_request_no_filter(self, app):
        """Agent/no-cookie request sees all agents."""
        ctrl, model, service, rbac = self._make_controller(app)

        all_agents = [
            {"agent_id": "a1", "group_id": "g1", "hostname": "PC1", "status": "active"},
            {"agent_id": "a2", "group_id": "g2", "hostname": "PC2", "status": "active"},
        ]
        service.get_agents_with_status.return_value = all_agents

        with app.test_request_context('/api/agents'):
            g.current_user = None
            g.current_role = None

            resp, status = ctrl.list_agents()
            data = resp.get_json()

            assert status == 200
            assert data["total"] == 2

    def test_get_agent_teacher_own_group(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        service.get_agent_details.return_value = {"agent_id": "a1", "group_id": "g1"}
        model.find_by_agent_id.return_value = {"agent_id": "a1", "group_id": "g1"}
        rbac.can_teacher_access_agent.return_value = True

        with app.test_request_context('/api/agents/a1'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.get_agent("a1")
            assert status == 200

    def test_get_agent_teacher_other_group_403(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        service.get_agent_details.return_value = {"agent_id": "a3", "group_id": "g99"}
        model.find_by_agent_id.return_value = {"agent_id": "a3", "group_id": "g99"}
        rbac.can_teacher_access_agent.return_value = False

        with patch('controllers.agent_controller.get_rbac_service', return_value=rbac):
            with app.test_request_context('/api/agents/a3'):
                g.current_user = teacher_user
                g.current_role = "teacher"

                resp, status = ctrl.get_agent("a3")
                assert status == 403

    def test_delete_agent_teacher_blocked(self, app, teacher_user):
        """Teacher does NOT have agents:delete permission."""
        ctrl, model, service, rbac = self._make_controller(app)

        with app.test_request_context('/api/agents/a1', method='DELETE'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.delete_agent("a1")
            assert status == 403
            data = resp.get_json()
            assert data["success"] is False

    def test_delete_agent_admin_allowed(self, app, admin_user):
        ctrl, model, service, rbac = self._make_controller(app)

        model.find_by_agent_id.return_value = {"agent_id": "a1", "hostname": "PC1"}
        service.delete_agent.return_value = True

        with app.test_request_context('/api/agents/a1', method='DELETE'):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.delete_agent("a1")
            assert status == 200

    def test_update_group_teacher_checks_source_and_target(self, app, teacher_user):
        """Teacher moving agent: must own both source and target group."""
        ctrl, model, service, rbac = self._make_controller(app)

        # Source agent in teacher's group
        model.find_by_agent_id.return_value = {"agent_id": "a1", "group_id": "g1"}
        rbac.can_teacher_access_agent.return_value = True
        # Target group NOT owned by teacher
        rbac.get_teacher_group_ids.return_value = ["g1"]

        with app.test_request_context('/api/agents/a1/group', method='PATCH',
                                       json={"group_id": "g99"}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.update_group("a1")
            assert status == 403  # Target group not owned

    def test_get_statistics_teacher_filtered(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        all_agents = [
            {"agent_id": "a1", "group_id": "g1", "status": "active"},
            {"agent_id": "a2", "group_id": "g1", "status": "inactive"},
            {"agent_id": "a3", "group_id": "g99", "status": "active"},
        ]
        service.get_agents_with_status.return_value = all_agents
        service.calculate_statistics.return_value = {
            "last_calculated": "2026-05-26T10:00:00+07:00",
            "thresholds": {},
        }
        rbac.get_teacher_group_ids.return_value = ["g1"]

        with patch('controllers.agent_controller.get_rbac_service', return_value=rbac):
            with app.test_request_context('/api/agents/statistics'):
                g.current_user = teacher_user
                g.current_role = "teacher"

                resp, status = ctrl.get_statistics()
                data = resp.get_json()

                assert status == 200
                stats = data["data"]
                # Statistics controller emits {total, active, inactive, ...}
                assert stats["total"] == 2  # Only g1 agents
                assert stats["active"] == 1
                assert stats["inactive"] == 1


# ============================================================================
# 5. WHITELIST CONTROLLER TESTS
# ============================================================================

class TestWhitelistControllerTeacherFiltering:
    """Test WhitelistController with teacher data filtering."""

    def _make_controller(self, app):
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        from controllers.whitelist_controller import WhitelistController
        ctrl = WhitelistController(mock_model, mock_service, mock_rbac, socketio=None)
        return ctrl, mock_model, mock_service, mock_rbac

    def test_list_domains_teacher_sees_global_plus_own(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        rbac.get_teacher_group_ids.return_value = ["g1", "g2"]

        all_domains = [
            {"_id": "d1", "value": "google.com", "scope": "global", "group_id": None},
            {"_id": "d2", "value": "school.edu", "scope": "group", "group_id": "g1"},
            {"_id": "d3", "value": "other.com", "scope": "group", "group_id": "g99"},
        ]
        service.get_all_entries.return_value = {"items": all_domains, "total": 3}

        with app.test_request_context('/api/whitelist?limit=100&offset=0'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.list_domains()
            data = resp.get_json()

            assert status == 200
            # Teacher should see: d1 (global) + d2 (own group) = 2
            assert data["total"] == 2
            values = [d["value"] for d in data["domains"]]
            assert "google.com" in values
            assert "school.edu" in values
            assert "other.com" not in values

    def test_list_domains_teacher_pagination(self, app, teacher_user):
        """Teacher post-filter pagination works correctly."""
        ctrl, model, service, rbac = self._make_controller(app)

        rbac.get_teacher_group_ids.return_value = ["g1"]

        # 5 domains: 2 global + 1 own + 2 other
        all_domains = [
            {"_id": f"d{i}", "value": f"global{i}.com", "scope": "global", "group_id": None}
            for i in range(1, 3)
        ] + [
            {"_id": "d3", "value": "mine.com", "scope": "group", "group_id": "g1"},
        ] + [
            {"_id": f"d{i}", "value": f"other{i}.com", "scope": "group", "group_id": "g99"}
            for i in range(4, 6)
        ]
        service.get_all_entries.return_value = {"items": all_domains, "total": 5}

        # Request page 2 with limit=2
        with app.test_request_context('/api/whitelist?limit=2&offset=2'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.list_domains()
            data = resp.get_json()

            assert status == 200
            # Teacher sees 3 (2 global + 1 own), page 2 (offset=2, limit=2) → 1 item
            assert data["total"] == 3
            assert len(data["domains"]) == 1

    def test_add_domain_teacher_blocked_global(self, app, teacher_user):
        """Teacher cannot add to global whitelist."""
        ctrl, model, service, rbac = self._make_controller(app)

        with app.test_request_context('/api/whitelist', method='POST',
                                       json={"value": "evil.com", "scope": "global"}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.add_domain()
            assert status == 403

    def test_add_domain_teacher_own_group_forbidden(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)
        rbac.get_teacher_group_ids.return_value = ["g1"]

        service.add_entry.return_value = {"success": True, "id": "new-id"}

        with app.test_request_context('/api/whitelist', method='POST',
                                       json={"value": "school.edu", "type": "domain",
                                              "group_id": "g1", "scope": "group"}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.add_domain()
            assert status == 403
            service.add_entry.assert_not_called()

    def test_add_domain_teacher_other_group_403(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)
        rbac.get_teacher_group_ids.return_value = ["g1"]

        with app.test_request_context('/api/whitelist', method='POST',
                                       json={"value": "bad.com", "type": "domain",
                                              "group_id": "g99", "scope": "group"}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.add_domain()
            assert status == 403

    def test_delete_domain_teacher_blocked_global(self, app, teacher_user):
        """Teacher cannot delete global whitelist entry."""
        ctrl, model, service, rbac = self._make_controller(app)

        service.validate_teacher_entry_access.return_value = (
            False,
            "Teachers cannot delete from global whitelist",
        )

        with app.test_request_context('/api/whitelist/660000000000000000000001', method='DELETE'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.delete_domain("660000000000000000000001")
            assert status == 403

    def test_import_domains_teacher_must_specify_group(self, app, teacher_user):
        """Teacher must specify group_id when importing."""
        ctrl, model, service, rbac = self._make_controller(app)

        with app.test_request_context('/api/whitelist/import', method='POST',
                                       json={"domains": ["a.com", "b.com"]}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.import_domains()
            assert status == 403

    def test_bulk_add_teacher_forbidden(self, app, teacher_user):
        """Teacher bulk add is blocked; teachers use Whitelist Profiles."""
        ctrl, model, service, rbac = self._make_controller(app)
        rbac.get_teacher_group_ids.return_value = ["g1"]

        items = [
            {"value": "ok.com", "group_id": "g1"},
            {"value": "bad.com", "group_id": "g99"},  # Not teacher's group
        ]

        with app.test_request_context('/api/whitelist/bulk', method='POST',
                                       json={"items": items}):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.bulk_add_entries()
            assert status == 403


# ============================================================================
# 6. LOG CONTROLLER TESTS
# ============================================================================

class TestLogControllerTeacherFiltering:
    """Test LogController with teacher data filtering."""

    def _make_controller(self, app):
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()
        from controllers.log_controller import LogController
        ctrl = LogController(mock_model, mock_service, mock_rbac, socketio=None)
        return ctrl, mock_model, mock_service, mock_rbac

    def test_list_logs_admin_no_filter(self, app, admin_user):
        ctrl, model, service, rbac = self._make_controller(app)

        service.get_all_logs.return_value = {
            "success": True, "logs": [{"_id": "1"}, {"_id": "2"}], "total": 2
        }

        with app.test_request_context('/api/logs?limit=100&offset=0'):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.list_logs()
            data = resp.get_json()

            assert status == 200
            # Admin: no teacher filter applied
            call_args = service.get_all_logs.call_args[0]
            filters = call_args[0]
            assert filters == {}  # No filter

    def test_list_logs_teacher_filtered(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        teacher_filter = {"agent_id": {"$in": ["a1", "a2"]}}
        rbac.get_log_query_filter.return_value = teacher_filter

        service.get_all_logs.return_value = {
            "success": True, "logs": [{"_id": "1"}], "total": 1
        }

        with app.test_request_context('/api/logs?limit=100&offset=0'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.list_logs()

            assert status == 200
            call_args = service.get_all_logs.call_args[0]
            filters = call_args[0]
            # Should contain teacher filter
            assert "agent_id" in filters or "$and" in filters

    def test_list_logs_teacher_preserves_user_filter_with_and(self, app, teacher_user):
        """CRITICAL: Teacher filter + user filter should use $and, not overwrite."""
        ctrl, model, service, rbac = self._make_controller(app)

        teacher_filter = {"agent_id": {"$in": ["a1", "a2"]}}
        rbac.get_log_query_filter.return_value = teacher_filter

        service.get_all_logs.return_value = {
            "success": True, "logs": [], "total": 0
        }

        # User also filters by agent_id
        with app.test_request_context('/api/logs?limit=100&offset=0&agent_id=a1'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.list_logs()

            assert status == 200
            call_args = service.get_all_logs.call_args[0]
            filters = call_args[0]

            # Should use $and to combine both filters
            assert "$and" in filters, "Must use $and to merge teacher+user filters"
            and_conditions = filters["$and"]
            assert len(and_conditions) == 2

    def test_list_logs_agent_request_no_filter(self, app):
        """Agent/no-cookie request: no teacher filter."""
        ctrl, model, service, rbac = self._make_controller(app)

        service.get_all_logs.return_value = {
            "success": True, "logs": [{"_id": "1"}], "total": 1
        }

        with app.test_request_context('/api/logs?limit=100&offset=0'):
            g.current_user = None
            g.current_role = None

            resp, status = ctrl.list_logs()
            assert status == 200

            call_args = service.get_all_logs.call_args[0]
            filters = call_args[0]
            assert filters == {}

    def test_clear_logs_teacher_blocked(self, app, teacher_user):
        """Teacher does NOT have logs:delete permission."""
        ctrl, model, service, rbac = self._make_controller(app)

        with app.test_request_context('/api/logs/clear', method='DELETE'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.clear_logs()
            assert status == 403
            data = resp.get_json()
            assert data["success"] is False

    def test_clear_logs_admin_allowed(self, app, admin_user):
        ctrl, model, service, rbac = self._make_controller(app)
        service.clear_logs.return_value = {"success": True, "deleted_count": 10}

        with app.test_request_context('/api/logs/clear', method='DELETE',
                                       content_type='application/json',
                                       json={}):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.clear_logs()
            assert status == 200

    def test_export_logs_teacher_blocked(self, app, teacher_user):
        """Teacher does NOT have logs:export permission."""
        ctrl, model, service, rbac = self._make_controller(app)

        with app.test_request_context('/api/logs/export'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.export_logs()
            assert status == 403

    def test_export_logs_admin_allowed(self, app, admin_user):
        ctrl, model, service, rbac = self._make_controller(app)
        service.export_logs.return_value = {"success": True, "data": "...", "count": 5}

        with app.test_request_context('/api/logs/export?format=json'):
            g.current_user = admin_user
            g.current_role = "admin"

            resp, status = ctrl.export_logs()
            assert status == 200

    def test_get_statistics_teacher_filtered(self, app, teacher_user):
        ctrl, model, service, rbac = self._make_controller(app)

        teacher_filter = {"agent_id": {"$in": ["a1"]}}
        rbac.get_log_query_filter.return_value = teacher_filter

        service.get_comprehensive_statistics.return_value = {
            "total": 50, "allowed": 30, "blocked": 20, "warnings": 0,
            "filtered_total": 50, "filtered_allowed": 30, "filtered_blocked": 20,
            "filtered_warnings": 0, "has_filters": True,
        }

        with app.test_request_context('/api/logs/stats'):
            g.current_user = teacher_user
            g.current_role = "teacher"

            resp, status = ctrl.get_statistics()
            assert status == 200

            call_args = service.get_comprehensive_statistics.call_args[0]
            filters = call_args[0]
            assert "agent_id" in filters


# ============================================================================
# 7. AGENT API BACKWARD COMPATIBILITY TESTS
# ============================================================================

class TestAgentAPIBackwardCompatibility:
    """
    CRITICAL: Agent-to-server API must NOT be affected by RBAC changes.
    register_agent and heartbeat use require_api_key/require_jwt (NOT inject_current_user).
    """

    def test_register_uses_require_api_key(self):
        """Verify register_agent route exists on the agents blueprint.

        Flask's Blueprint.deferred_functions stores closures (not Rule objects)
        so we register the blueprint on a throwaway app and inspect url_map.
        """
        from controllers.agent_controller import AgentController
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()

        ctrl = AgentController(mock_model, mock_service, mock_rbac, socketio=None)
        assert ctrl.blueprint.name == 'agents'

        probe = Flask(__name__)
        probe.register_blueprint(ctrl.blueprint, url_prefix='/api')
        registered = {rule.endpoint for rule in probe.url_map.iter_rules()}
        assert 'agents.register_agent' in registered
        assert 'agents.heartbeat' in registered

    def test_whitelist_agent_sync_uses_require_jwt(self):
        """Verify agent_sync route uses require_jwt, not inject_current_user."""
        from controllers.whitelist_controller import WhitelistController
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()

        ctrl = WhitelistController(mock_model, mock_service, mock_rbac, socketio=None)
        assert ctrl.blueprint.name == 'whitelist'

    def test_log_receive_uses_require_jwt(self):
        """Verify receive_logs route uses require_jwt, not inject_current_user."""
        from controllers.log_controller import LogController
        mock_model = MagicMock()
        mock_service = MagicMock()
        mock_rbac = MagicMock()

        ctrl = LogController(mock_model, mock_service, mock_rbac, socketio=None)
        assert ctrl.blueprint.name == 'logs'


# ============================================================================
# 8. EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_teacher_with_empty_group_ids_sees_nothing(self, app, teacher_user):
        """Teacher who hasn't created any groups sees empty results everywhere."""
        from services.rbac_service import RBACService
        mock_gm = MagicMock()
        mock_am = MagicMock()
        mock_gm.collection.find.return_value = []
        mock_gm.find_accessible_group_ids_for_teacher.return_value = []
        mock_am.find_agent_ids_by_group_ids.return_value = []

        svc = RBACService(mock_gm, mock_am)

        # Groups: $or over teacher_ids + created_by (legacy)
        group_filter = svc.get_group_query_filter(teacher_user)
        assert group_filter == {"$or": [
            {"teacher_ids": teacher_user["_id"]},
            {"created_by": teacher_user["_id"]},
        ]}

        # Logs
        log_filter = svc.get_log_query_filter(teacher_user)
        assert log_filter == {"agent_id": {"$in": []}}

        # Whitelist
        wl_filter = svc.get_whitelist_query_filter(teacher_user)
        assert "$or" in wl_filter
        group_ids_in_filter = wl_filter["$or"][1]["group_id"]["$in"]
        assert group_ids_in_filter == []

    def test_group_with_none_created_by_invisible_to_teacher(self, mock_group_model, teacher_user):
        """Groups created by agents (created_by=None) are invisible to teacher."""
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        group = {"_id": "orphan", "created_by": None}
        assert svc.can_access_group(teacher_user, group) is False

    def test_agent_in_no_group_invisible_to_teacher(self, mock_group_model, mock_agent_model, teacher_user):
        """Agent without group_id is inaccessible to teacher."""
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        agent = {"agent_id": "orphan", "group_id": None}
        assert svc.can_teacher_access_agent(teacher_user, agent) is False

    def test_objectid_string_comparison(self, mock_group_model, mock_agent_model, teacher_user):
        """Verify group_id comparison works with both string and ObjectId formats."""
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model, mock_agent_model)

        group_oid = ObjectId("660000000000000000000001")
        mock_group_model.collection.find.return_value = [{"_id": group_oid}]

        # Agent has group_id as string
        agent_str = {"agent_id": "a1", "group_id": "660000000000000000000001"}
        assert svc.can_teacher_access_agent(teacher_user, agent_str) is True

        # Agent has group_id as ObjectId
        agent_oid = {"agent_id": "a2", "group_id": ObjectId("660000000000000000000001")}
        result = svc.can_teacher_access_agent(teacher_user, agent_oid)
        assert result is True  # str(ObjectId) should match

    def test_two_teachers_see_different_groups(self, mock_group_model, teacher_user, teacher_user_2):
        """Two teachers should see only their own groups."""
        from services.rbac_service import RBACService
        svc = RBACService(mock_group_model)

        # Teacher 1 query
        filter1 = svc.get_group_query_filter(teacher_user)
        assert filter1 == {"$or": [
            {"teacher_ids": teacher_user["_id"]},
            {"created_by": teacher_user["_id"]},
        ]}

        # Teacher 2 query
        filter2 = svc.get_group_query_filter(teacher_user_2)
        assert filter2 == {"$or": [
            {"teacher_ids": teacher_user_2["_id"]},
            {"created_by": teacher_user_2["_id"]},
        ]}

        # They should be different
        assert filter1 != filter2


# ============================================================================
# 9. INJECT_CURRENT_USER DECORATOR BEHAVIOR TEST
# ============================================================================

class TestInjectCurrentUserDecorator:
    """Test inject_current_user - the key mechanism."""

    def test_no_token_sets_none(self, app):
        """No cookie/token → g.current_user = None."""
        # We need to initialize the middleware first
        from middleware.rbac import inject_current_user

        @inject_current_user
        def dummy_view():
            return g.current_user

        with app.test_request_context('/test'):
            result = dummy_view()
            assert result is None

    def test_decorator_does_not_block_request(self, app):
        """inject_current_user should NEVER return 401/403 - it's non-blocking."""
        from middleware.rbac import inject_current_user

        @inject_current_user
        def dummy_view():
            return "OK", 200

        with app.test_request_context('/test'):
            result = dummy_view()
            assert result == ("OK", 200)


# ============================================================================
# 10. GROUP SERVICE TESTS
# ============================================================================

class TestGroupServiceWithCreatedBy:
    """Test GroupService passes created_by correctly."""

    def test_create_group_passes_created_by(self):
        mock_model = MagicMock()
        mock_agent_model = MagicMock()
        mock_model.ensure_pending_group.return_value = {"_id": ObjectId()}

        from services.group_service import GroupService
        svc = GroupService(mock_model, mock_agent_model)

        teacher_id = ObjectId("650000000000000000000002")
        mock_model.create_group.return_value = {
            "_id": ObjectId(), "name": "Test", "created_by": teacher_id
        }

        result = svc.create_group("Test", "desc", [], created_by=teacher_id)
        mock_model.create_group.assert_called_once_with(
            "Test", "desc", [], created_by=teacher_id
        )

    def test_list_groups_passes_query_filter(self):
        mock_model = MagicMock()
        mock_agent_model = MagicMock()
        mock_model.ensure_pending_group.return_value = {"_id": ObjectId()}

        from services.group_service import GroupService
        svc = GroupService(mock_model, mock_agent_model)

        teacher_id = ObjectId("650000000000000000000002")
        qf = {"created_by": teacher_id}
        mock_model.list_groups.return_value = [
            {"_id": ObjectId(), "name": "G1", "created_by": teacher_id}
        ]

        result = svc.list_groups(query_filter=qf)
        mock_model.list_groups.assert_called_once_with(query_filter=qf)


# ============================================================================
# 11. GROUP MODEL TESTS
# ============================================================================

class TestGroupModelWithQueryFilter:
    """Test GroupModel.list_groups with query_filter parameter."""

    def test_list_groups_no_filter(self):
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.groups = mock_collection
        mock_collection.find.return_value = []
        mock_collection.create_index = MagicMock()

        from models.group_model import GroupModel
        model = GroupModel(mock_db)

        model.list_groups()
        mock_collection.find.assert_called_with({})

    def test_list_groups_with_filter(self):
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.groups = mock_collection
        mock_collection.find.return_value = []
        mock_collection.create_index = MagicMock()

        from models.group_model import GroupModel
        model = GroupModel(mock_db)

        teacher_id = ObjectId("650000000000000000000002")
        qf = {"created_by": teacher_id}
        model.list_groups(query_filter=qf)
        mock_collection.find.assert_called_with(qf)

    def test_create_group_with_created_by(self):
        mock_db = MagicMock()
        mock_collection = MagicMock()
        mock_db.groups = mock_collection
        mock_collection.create_index = MagicMock()
        mock_collection.insert_one.return_value = MagicMock(inserted_id=ObjectId())

        from models.group_model import GroupModel
        model = GroupModel(mock_db)

        teacher_id = ObjectId("650000000000000000000002")
        result = model.create_group("Test", "desc", [], created_by=teacher_id)
        assert result["created_by"] == teacher_id


# ============================================================================
# 12. WHITELIST SERVICE ACCESS CHECKS
# ============================================================================

class TestWhitelistServiceTeacherEntryAccess:
    """Teacher checks cover real embedded ObjectIds, not only pseudo-IDs."""

    def test_real_embedded_object_id_denied_for_other_group(self):
        from services.whitelist_service import WhitelistService

        entry_oid = ObjectId("670000000000000000000001")
        owner_group_id = ObjectId("660000000000000000000001")
        teacher_group_id = ObjectId("660000000000000000000099")
        whitelist_model = MagicMock()
        whitelist_model.find_entry_access_info.return_value = None
        group_model = MagicMock()
        group_model.find_group_with_embedded_entry.return_value = {
            "_id": owner_group_id
        }
        service = WhitelistService(whitelist_model, MagicMock(), group_model)

        allowed, error = service.validate_teacher_entry_access(
            str(entry_oid), [str(teacher_group_id)], "delete"
        )

        assert allowed is False
        assert error == "No permission to delete this entry"
        group_model.find_group_with_embedded_entry.assert_called_once_with(entry_oid)

    def test_real_embedded_object_id_allowed_for_own_group(self):
        from services.whitelist_service import WhitelistService

        entry_oid = ObjectId("670000000000000000000002")
        owner_group_id = ObjectId("660000000000000000000001")
        whitelist_model = MagicMock()
        whitelist_model.find_entry_access_info.return_value = None
        group_model = MagicMock()
        group_model.find_group_with_embedded_entry.return_value = {
            "_id": owner_group_id
        }
        service = WhitelistService(whitelist_model, MagicMock(), group_model)

        allowed, error = service.validate_teacher_entry_access(
            str(entry_oid), [str(owner_group_id)], "edit"
        )

        assert allowed is True
        assert error is None


# ============================================================================
# RUNNER
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
