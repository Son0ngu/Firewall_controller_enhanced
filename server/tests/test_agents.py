"""
Comprehensive Test Suite: Agent Management
============================================
Tests toàn bộ chức năng Agent gửi lên server:
1. AgentModel      - CRUD, find, heartbeat update, statistics
2. AgentService    - Registration, heartbeat, status, group move, policy check
3. AgentController - HTTP endpoints, RBAC teacher isolation, agent-to-server flow
4. Cross-Teacher   - Agent không bị gửi nhầm teacher, không cross-leak
5. Edge Cases      - undefined fields, missing data, device_id conflict

Sử dụng REAL MongoDB (test database) để integration test chính xác.

Run:
  cd server && python -m pytest tests/test_agents.py -v
  cd server && python -m pytest tests/test_agents.py -v -k "test_model"
  cd server && python -m pytest tests/test_agents.py -v -k "test_cross_teacher"
"""

import pytest
import sys
import os
import uuid
import json
import secrets
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from bson import ObjectId

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from models.agent_model import AgentModel
from models.group_model import GroupModel
from services.agent_service import AgentService
from services.rbac_service import RBACService
from time_utils import now_vietnam


# ============================================================================
# FIXTURES - Database
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


TEST_DB = 'test_saint_agents'


@pytest.fixture
def db(mongo_client):
    from bson.codec_options import CodecOptions
    from time_utils import VIETNAM_TZ
    codec = CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)
    database = mongo_client.get_database(TEST_DB, codec_options=codec)
    yield database
    mongo_client.drop_database(TEST_DB)


@pytest.fixture
def agent_model(db):
    return AgentModel(db)


@pytest.fixture
def group_model(db):
    return GroupModel(db)


@pytest.fixture
def agent_service(agent_model, group_model):
    return AgentService(agent_model, group_model, socketio=None, jwt_service=None)


@pytest.fixture
def rbac_service(group_model, agent_model):
    return RBACService(group_model, agent_model)


# ============================================================================
# FIXTURES - Users & Constants
# ============================================================================

ADMIN_ID = ObjectId("650000000000000000000001")
TEACHER_A_ID = ObjectId("650000000000000000000002")
TEACHER_B_ID = ObjectId("650000000000000000000003")


@pytest.fixture
def admin_user():
    return {"_id": ADMIN_ID, "username": "admin", "role": "admin", "is_active": True}


@pytest.fixture
def teacher_a():
    return {"_id": TEACHER_A_ID, "username": "teacher_a", "role": "teacher", "is_active": True}


@pytest.fixture
def teacher_b():
    return {"_id": TEACHER_B_ID, "username": "teacher_b", "role": "teacher", "is_active": True}


def make_agent_data(hostname="PC-01", device_id=None, ip="192.168.1.10"):
    """Helper - tạo agent registration data."""
    return {
        "hostname": hostname,
        "device_id": device_id or str(uuid.uuid4()),
        "ip_address": ip,
        "platform": "Windows",
        "os_info": {"os": "Windows 11"},
        "agent_version": "1.0.0",
    }


def insert_agent(agent_model, group_id, hostname="PC-01", device_id=None, agent_id=None):
    """Helper - insert agent trực tiếp vào DB."""
    aid = agent_id or str(uuid.uuid4())
    did = device_id or str(uuid.uuid4())
    token = secrets.token_hex(32)
    data = {
        "agent_id": aid,
        "device_id": did,
        "hostname": hostname,
        "display_name": hostname,
        "ip_address": "192.168.1.10",
        "platform": "Windows",
        "agent_token": token,
        "group_id": group_id,
        "status": "active",
        "last_heartbeat": now_vietnam(),
    }
    agent_model.register_agent(data)
    return {**data, "agent_token": token}


# ============================================================================
# 1. MODEL TESTS - AgentModel CRUD
# ============================================================================

class TestAgentModel:

    def test_model_register_agent(self, agent_model):
        """Register agent - insert vào DB, trả về đủ fields."""
        data = {
            "agent_id": str(uuid.uuid4()),
            "device_id": str(uuid.uuid4()),
            "hostname": "PC-Test",
            "ip_address": "10.0.0.1",
            "group_id": "some-group",
        }
        result = agent_model.register_agent(data)
        assert result["agent_id"] == data["agent_id"]
        assert result["hostname"] == "PC-Test"
        assert result["status"] == "pending"
        assert result["registered_date"] is not None
        assert "_id" in result

    def test_model_find_by_agent_id(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "FindMe", "ip_address": "10.0.0.2",
        })
        found = agent_model.find_by_agent_id(aid)
        assert found is not None
        assert found["hostname"] == "FindMe"

    def test_model_find_by_agent_id_not_found(self, agent_model):
        assert agent_model.find_by_agent_id("nonexistent") is None

    def test_model_find_by_device_id(self, agent_model):
        did = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": did,
            "hostname": "DeviceFind", "ip_address": "10.0.0.3",
        })
        found = agent_model.find_by_device_id(did)
        assert found is not None
        assert found["hostname"] == "DeviceFind"

    def test_model_find_by_device_id_not_found(self, agent_model):
        assert agent_model.find_by_device_id("no-such-device") is None

    def test_model_duplicate_agent_id_fails(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "A", "ip_address": "1.1.1.1",
        })
        with pytest.raises(Exception):
            agent_model.register_agent({
                "agent_id": aid, "device_id": str(uuid.uuid4()),
                "hostname": "B", "ip_address": "2.2.2.2",
            })

    def test_model_duplicate_device_id_fails(self, agent_model):
        did = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": did,
            "hostname": "A", "ip_address": "1.1.1.1",
        })
        with pytest.raises(Exception):
            agent_model.register_agent({
                "agent_id": str(uuid.uuid4()), "device_id": did,
                "hostname": "B", "ip_address": "2.2.2.2",
            })

    def test_model_update_agent(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "Old", "ip_address": "10.0.0.4",
        })
        result = agent_model.update_agent(aid, {"hostname": "New"})
        assert result is True
        found = agent_model.find_by_agent_id(aid)
        assert found["hostname"] == "New"

    def test_model_update_agent_not_found(self, agent_model):
        assert agent_model.update_agent("no-agent", {"hostname": "X"}) is False

    def test_model_update_agent_group(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "GroupMove", "ip_address": "10.0.0.5",
            "group_id": "old-group",
        })
        result = agent_model.update_agent_group(aid, "new-group", "active")
        assert result is True
        found = agent_model.find_by_agent_id(aid)
        assert found["group_id"] == "new-group"
        assert found["status"] == "active"

    def test_model_update_heartbeat(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "HB", "ip_address": "10.0.0.6",
        })
        result = agent_model.update_heartbeat(aid, {
            "last_heartbeat": now_vietnam().isoformat(),
            "status": "active",
        })
        assert result is True

    def test_model_delete_agent(self, agent_model):
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "Del", "ip_address": "10.0.0.7",
        })
        assert agent_model.delete_agent(aid) is True
        assert agent_model.find_by_agent_id(aid) is None

    def test_model_delete_nonexistent(self, agent_model):
        assert agent_model.delete_agent("no-agent") is False

    def test_model_count_by_group(self, agent_model):
        gid = "count-group"
        for i in range(3):
            agent_model.register_agent({
                "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
                "hostname": f"C{i}", "ip_address": f"10.0.1.{i}",
                "group_id": gid,
            })
        assert agent_model.count_by_group(gid) == 3
        assert agent_model.count_by_group("empty-group") == 0

    def test_model_get_all_agents(self, agent_model):
        for i in range(5):
            agent_model.register_agent({
                "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
                "hostname": f"All{i}", "ip_address": f"10.0.2.{i}",
            })
        agents = agent_model.get_all_agents()
        assert len(agents) == 5

    def test_model_get_all_agents_with_filter(self, agent_model):
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
            "hostname": "FilterA", "ip_address": "10.0.3.1", "group_id": "grpA",
        })
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
            "hostname": "FilterB", "ip_address": "10.0.3.2", "group_id": "grpB",
        })
        agents = agent_model.get_all_agents({"group_id": "grpA"})
        assert len(agents) == 1
        assert agents[0]["hostname"] == "FilterA"

    def test_model_get_agent_statistics(self, agent_model):
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
            "hostname": "StatA", "ip_address": "10.0.4.1",
            "last_heartbeat": now_vietnam(),
        })
        stats = agent_model.get_agent_statistics()
        assert stats["total"] >= 1
        assert "active" in stats
        assert "offline" in stats


# ============================================================================
# 2. SERVICE TESTS - AgentService business logic
# ============================================================================

class TestAgentServiceRegistration:
    """Registration flow - new agent, duplicate device_id, missing fields."""

    def test_register_new_agent(self, agent_service):
        """Register brand new agent - trả về agent_id, token, pending status."""
        data = make_agent_data("NewPC", ip="192.168.10.1")
        result = agent_service.register_agent(data, "192.168.10.1")

        assert "agent_id" in result
        assert "token" in result
        assert result["status"] == "pending"
        assert result["message"] == "Agent registered successfully"

    def test_register_duplicate_device_id_updates(self, agent_service):
        """Register cùng device_id → update existing, không tạo mới."""
        did = str(uuid.uuid4())
        data1 = make_agent_data("PC-V1", device_id=did, ip="192.168.10.2")
        r1 = agent_service.register_agent(data1, "192.168.10.2")

        data2 = make_agent_data("PC-V2", device_id=did, ip="192.168.10.3")
        r2 = agent_service.register_agent(data2, "192.168.10.3")

        # Same agent_id
        assert r1["agent_id"] == r2["agent_id"]
        assert "updated" in r2["message"]

    def test_register_missing_hostname_fails(self, agent_service):
        """Register thiếu hostname - raise ValueError."""
        data = make_agent_data()
        del data["hostname"]
        with pytest.raises(ValueError, match="Hostname is required"):
            agent_service.register_agent(data, "10.0.0.1")

    def test_register_missing_device_id_fails(self, agent_service):
        """Register thiếu device_id - raise ValueError."""
        data = make_agent_data()
        del data["device_id"]
        with pytest.raises(ValueError, match="Device ID is required"):
            agent_service.register_agent(data, "10.0.0.1")

    def test_register_assigns_to_pending_group(self, agent_service, agent_model):
        """New agent tự động vào pending group."""
        data = make_agent_data("PendingPC", ip="192.168.10.5")
        result = agent_service.register_agent(data, "192.168.10.5")

        agent = agent_model.find_by_agent_id(result["agent_id"])
        pending_id = str(agent_service.pending_group["_id"])
        assert agent["group_id"] == pending_id

    def test_register_localhost_ip_replaced(self, agent_service, agent_model):
        """Agent gửi ip 127.0.0.1 nhưng client_ip khác → dùng client_ip."""
        data = make_agent_data("LocalPC", ip="192.168.10.6")
        data["ip_address"] = "127.0.0.1"
        result = agent_service.register_agent(data, "10.20.30.40")

        agent = agent_model.find_by_agent_id(result["agent_id"])
        assert agent["ip_address"] == "10.20.30.40"


class TestAgentServiceHeartbeat:
    """Heartbeat processing - token validation, device_id mismatch, status."""

    def _register_agent(self, agent_service):
        data = make_agent_data("HB-PC", ip="192.168.20.1")
        result = agent_service.register_agent(data, "192.168.20.1")
        return result

    def test_heartbeat_valid(self, agent_service):
        """Heartbeat hợp lệ - trả về status, next_heartbeat."""
        reg = self._register_agent(agent_service)
        hb = agent_service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": now_vietnam().isoformat(), "status": "active"},
            "192.168.20.1"
        )
        assert hb["agent_id"] == reg["agent_id"]
        assert "next_heartbeat" in hb
        assert "server_time" in hb
        assert hb["force_sync"] is False
        assert hb["policy_mode"] == "none"

    def test_heartbeat_unknown_agent(self, agent_service):
        """Heartbeat từ agent không tồn tại - raise."""
        with pytest.raises(ValueError, match="Unknown agent"):
            agent_service.process_heartbeat(
                "fake-agent-id", "fake-token", {}, "10.0.0.1"
            )

    def test_heartbeat_invalid_token(self, agent_service):
        """Heartbeat với sai token - raise."""
        reg = self._register_agent(agent_service)
        with pytest.raises(ValueError, match="Invalid token"):
            agent_service.process_heartbeat(
                reg["agent_id"], "wrong-token", {}, "10.0.0.1"
            )

    def test_heartbeat_device_id_mismatch(self, agent_service, agent_model):
        """Heartbeat gửi device_id khác với DB - raise."""
        reg = self._register_agent(agent_service)
        agent = agent_model.find_by_agent_id(reg["agent_id"])
        stored_device_id = agent["device_id"]

        with pytest.raises(ValueError, match="Device ID mismatch"):
            agent_service.process_heartbeat(
                reg["agent_id"], reg["token"],
                {"device_id": "DIFFERENT-DEVICE", "timestamp": now_vietnam().isoformat()},
                "10.0.0.1"
            )

    def test_heartbeat_pending_status_preserved(self, agent_service, agent_model):
        """Agent pending - heartbeat không thay đổi status thành active."""
        reg = self._register_agent(agent_service)
        # Agent is pending after registration
        agent = agent_model.find_by_agent_id(reg["agent_id"])
        assert agent["status"] == "pending"

        hb = agent_service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": now_vietnam().isoformat(), "status": "active"},
            "10.0.0.1"
        )
        # Should still be pending
        assert hb["status"] == "pending"


class TestAgentServiceStatus:
    """Status calculation - active/inactive/offline thresholds."""

    def test_status_active(self, agent_service, agent_model, group_model):
        """Agent heartbeat < 5 min ago → active."""
        gid = str(group_model.create_group("StatusGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "ActivePC")
        # Set status to active and heartbeat to just 1 second ago
        recent = now_vietnam() - timedelta(seconds=1)
        agent_model.collection.update_one(
            {"agent_id": agent["agent_id"]},
            {"$set": {"status": "active", "last_heartbeat": recent}}
        )

        agents = agent_service.get_agents_with_status()
        found = next(a for a in agents if a["agent_id"] == agent["agent_id"])
        assert found["status"] == "active"

    def test_status_inactive(self, agent_service, agent_model, group_model):
        """Agent heartbeat 10 min ago → inactive."""
        gid = str(group_model.create_group("InactGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "InactivePC")
        old_time = now_vietnam() - timedelta(minutes=10)
        agent_model.collection.update_one(
            {"agent_id": agent["agent_id"]},
            {"$set": {"last_heartbeat": old_time, "status": "active"}}
        )

        agents = agent_service.get_agents_with_status()
        found = next(a for a in agents if a["agent_id"] == agent["agent_id"])
        assert found["status"] == "inactive"

    def test_status_offline(self, agent_service, agent_model, group_model):
        """Agent heartbeat > 30 min ago → offline."""
        gid = str(group_model.create_group("OffGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "OfflinePC")
        old_time = now_vietnam() - timedelta(hours=2)
        agent_model.collection.update_one(
            {"agent_id": agent["agent_id"]},
            {"$set": {"last_heartbeat": old_time, "status": "active"}}
        )

        agents = agent_service.get_agents_with_status()
        found = next(a for a in agents if a["agent_id"] == agent["agent_id"])
        assert found["status"] == "offline"

    def test_status_no_heartbeat(self, agent_service, agent_model, group_model):
        """Agent không có heartbeat → offline."""
        gid = str(group_model.create_group("NoHBGrp", "")["_id"])
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "NoHB", "ip_address": "10.0.5.1",
            "group_id": gid, "status": "active",
        })
        # Remove heartbeat
        agent_model.collection.update_one(
            {"agent_id": aid},
            {"$unset": {"last_heartbeat": ""}}
        )

        agents = agent_service.get_agents_with_status()
        found = next(a for a in agents if a["agent_id"] == aid)
        assert found["status"] == "offline"

    def test_statistics(self, agent_service, agent_model, group_model):
        """Statistics - đếm đúng active/inactive/offline/pending."""
        gid = str(group_model.create_group("StatGrp", "")["_id"])

        # Active agent - fresh heartbeat
        a1 = insert_agent(agent_model, gid, "StatA")
        agent_model.update_agent(a1["agent_id"], {
            "status": "active",
            "last_heartbeat": now_vietnam(),
        })

        # Offline agent (old heartbeat)
        a2 = insert_agent(agent_model, gid, "StatB")
        agent_model.collection.update_one(
            {"agent_id": a2["agent_id"]},
            {"$set": {"last_heartbeat": now_vietnam() - timedelta(hours=5), "status": "active"}}
        )

        stats = agent_service.calculate_statistics()
        assert stats["total"] >= 2
        assert stats["active"] >= 1


class TestAgentServiceGroupMove:
    """Move agent between groups - status transitions."""

    def test_move_to_active_group(self, agent_service, agent_model, group_model):
        """Move agent from pending → active group → status becomes active."""
        active_grp = group_model.create_group("ActiveGrp", "")
        pending_gid = str(agent_service.pending_group["_id"])
        agent = insert_agent(agent_model, pending_gid, "MovePC")
        agent_model.update_agent(agent["agent_id"], {"status": "pending"})

        result = agent_service.move_agent_to_group(
            agent["agent_id"], str(active_grp["_id"])
        )
        assert result["group_id"] == str(active_grp["_id"])
        assert result["status"] == "active"

    def test_move_to_pending_group(self, agent_service, agent_model, group_model):
        """Move agent back to pending group → status becomes pending."""
        active_grp = group_model.create_group("ActiveGrp2", "")
        agent = insert_agent(agent_model, str(active_grp["_id"]), "BackPC")

        pending_gid = str(agent_service.pending_group["_id"])
        result = agent_service.move_agent_to_group(agent["agent_id"], pending_gid)
        assert result["status"] == "pending"

    def test_move_to_nonexistent_group(self, agent_service, agent_model, group_model):
        """Move to group không tồn tại - raise."""
        gid = str(group_model.create_group("MvGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "BadMovePC")

        with pytest.raises(ValueError, match="Group not found"):
            agent_service.move_agent_to_group(agent["agent_id"], str(ObjectId()))

    def test_move_nonexistent_agent(self, agent_service, group_model):
        """Move agent không tồn tại - raise."""
        grp = group_model.create_group("MvGrp2", "")
        with pytest.raises(ValueError, match="Agent not found"):
            agent_service.move_agent_to_group("fake-agent", str(grp["_id"]))


# ============================================================================
# 3. CROSS-TEACHER ISOLATION TESTS
# ============================================================================

class TestCrossTeacherIsolation:
    """
    Test agent KHÔNG thể bị truy cập cross-teacher.
    Teacher A chỉ thấy agents trong groups mình tạo.
    Teacher B không thể thấy/thao tác agents của Teacher A.
    """

    def test_teacher_sees_only_own_agents(
        self, rbac_service, agent_model, group_model, teacher_a, teacher_b
    ):
        """Teacher A thấy agents trong group mình, không thấy của Teacher B."""
        grp_a = group_model.create_group("ClassA", "", [], created_by=TEACHER_A_ID)
        grp_b = group_model.create_group("ClassB", "", [], created_by=TEACHER_B_ID)

        insert_agent(agent_model, str(grp_a["_id"]), "PC-A1")
        insert_agent(agent_model, str(grp_a["_id"]), "PC-A2")
        insert_agent(agent_model, str(grp_b["_id"]), "PC-B1")

        # Teacher A filter
        group_ids_a = rbac_service.get_teacher_group_ids(teacher_a)
        filter_a = {"group_id": {"$in": group_ids_a}}
        agents_a = agent_model.get_all_agents(filter_a)
        hostnames_a = [a["hostname"] for a in agents_a]
        assert "PC-A1" in hostnames_a
        assert "PC-A2" in hostnames_a
        assert "PC-B1" not in hostnames_a

        # Teacher B filter
        group_ids_b = rbac_service.get_teacher_group_ids(teacher_b)
        filter_b = {"group_id": {"$in": group_ids_b}}
        agents_b = agent_model.get_all_agents(filter_b)
        hostnames_b = [a["hostname"] for a in agents_b]
        assert "PC-B1" in hostnames_b
        assert "PC-A1" not in hostnames_b

    def test_admin_sees_all_agents(self, rbac_service, agent_model, group_model, admin_user):
        """Admin thấy tất cả agents, không bị filter."""
        grp_a = group_model.create_group("AdminAllA", "", [], created_by=TEACHER_A_ID)
        grp_b = group_model.create_group("AdminAllB", "", [], created_by=TEACHER_B_ID)
        insert_agent(agent_model, str(grp_a["_id"]), "AA1")
        insert_agent(agent_model, str(grp_b["_id"]), "AB1")

        group_ids = rbac_service.get_teacher_group_ids(admin_user)
        assert group_ids is None  # Admin → no filter

        all_agents = agent_model.get_all_agents()
        hostnames = [a["hostname"] for a in all_agents]
        assert "AA1" in hostnames
        assert "AB1" in hostnames

    def test_teacher_cannot_access_other_teacher_agent(
        self, rbac_service, agent_model, group_model, teacher_a
    ):
        """Teacher A không thể access agent trong group của Teacher B."""
        grp_b = group_model.create_group("ForbidGrp", "", [], created_by=TEACHER_B_ID)
        agent = insert_agent(agent_model, str(grp_b["_id"]), "ForbidPC")

        found = agent_model.find_by_agent_id(agent["agent_id"])
        can_access = rbac_service.can_teacher_access_agent(teacher_a, found)
        assert can_access is False

    def test_teacher_can_access_own_agent(
        self, rbac_service, agent_model, group_model, teacher_a
    ):
        """Teacher A có thể access agent trong group mình tạo."""
        grp_a = group_model.create_group("OwnGrp", "", [], created_by=TEACHER_A_ID)
        agent = insert_agent(agent_model, str(grp_a["_id"]), "OwnPC")

        found = agent_model.find_by_agent_id(agent["agent_id"])
        can_access = rbac_service.can_teacher_access_agent(teacher_a, found)
        assert can_access is True

    def test_agent_in_pending_group_not_owned(self, rbac_service, agent_model, group_model, teacher_a):
        """Agent trong pending group (system) - teacher không có quyền."""
        pending = group_model.ensure_pending_group()
        agent = insert_agent(agent_model, str(pending["_id"]), "PendingPC")

        found = agent_model.find_by_agent_id(agent["agent_id"])
        can_access = rbac_service.can_teacher_access_agent(teacher_a, found)
        assert can_access is False

    def test_teacher_empty_groups_sees_nothing(self, rbac_service, agent_model, group_model, teacher_b):
        """Teacher chưa tạo group nào - thấy 0 agents."""
        # Create agents in teacher_a's groups
        grp_a = group_model.create_group("SomeGrp", "", [], created_by=TEACHER_A_ID)
        insert_agent(agent_model, str(grp_a["_id"]), "SomePC")

        group_ids_b = rbac_service.get_teacher_group_ids(teacher_b)
        assert group_ids_b == []

        filter_b = {"group_id": {"$in": group_ids_b}}
        agents_b = agent_model.get_all_agents(filter_b)
        assert len(agents_b) == 0


# ============================================================================
# 4. EDGE CASES - undefined, null, conflict
# ============================================================================

class TestAgentEdgeCases:

    def test_agent_with_none_fields(self, agent_model):
        """Agent với fields None/undefined - không crash."""
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid,
            "device_id": str(uuid.uuid4()),
            "hostname": "NullPC",
            "ip_address": None,
            "platform": None,
            "os_info": None,
            "agent_version": None,
        })
        found = agent_model.find_by_agent_id(aid)
        assert found is not None
        assert found["hostname"] == "NullPC"
        assert found["ip_address"] is None

    def test_agent_empty_string_fields(self, agent_model):
        """Agent với empty string - vẫn lưu được."""
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid,
            "device_id": str(uuid.uuid4()),
            "hostname": "",
            "ip_address": "",
        })
        found = agent_model.find_by_agent_id(aid)
        assert found is not None
        assert found["hostname"] == ""

    def test_heartbeat_with_no_timestamp(self, agent_service):
        """Heartbeat không có timestamp - server dùng now_vietnam()."""
        data = make_agent_data("NoTsPC", ip="10.0.6.1")
        reg = agent_service.register_agent(data, "10.0.6.1")

        hb = agent_service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {},  # No timestamp
            "10.0.6.1"
        )
        assert hb["agent_id"] == reg["agent_id"]

    def test_heartbeat_with_future_timestamp(self, agent_service):
        """Heartbeat với timestamp tương lai - vẫn xử lý, clamp to 0."""
        data = make_agent_data("FuturePC", ip="10.0.6.2")
        reg = agent_service.register_agent(data, "10.0.6.2")

        future = (now_vietnam() + timedelta(hours=1)).isoformat()
        hb = agent_service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": future},
            "10.0.6.2"
        )
        assert hb["agent_id"] == reg["agent_id"]

    def test_register_same_hostname_different_device(self, agent_service, agent_model):
        """2 agents cùng hostname nhưng khác device_id - tạo 2 agents riêng."""
        d1 = make_agent_data("SameHost", device_id="dev-AAA", ip="10.0.7.1")
        d2 = make_agent_data("SameHost", device_id="dev-BBB", ip="10.0.7.2")
        r1 = agent_service.register_agent(d1, "10.0.7.1")
        r2 = agent_service.register_agent(d2, "10.0.7.2")

        # Different agent_ids because different device_ids
        assert r1["agent_id"] != r2["agent_id"]

    def test_update_display_name(self, agent_service, agent_model, group_model):
        """Update display name - chỉ thay display_name, giữ hostname."""
        gid = str(group_model.create_group("DnGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "OrigName")

        agent_service.update_display_name(agent["agent_id"], "Máy 01 - Nguyễn Văn A")
        found = agent_model.find_by_agent_id(agent["agent_id"])
        assert found["display_name"] == "Máy 01 - Nguyễn Văn A"
        assert found["hostname"] == "OrigName"

    def test_update_display_name_empty_fails(self, agent_service, agent_model, group_model):
        """Display name rỗng - raise."""
        gid = str(group_model.create_group("DnGrp2", "")["_id"])
        agent = insert_agent(agent_model, gid, "DnPC")

        with pytest.raises(ValueError, match="display_name is required"):
            agent_service.update_display_name(agent["agent_id"], "")

    def test_update_position(self, agent_service, agent_model, group_model):
        """Update vị trí agent trên room layout."""
        gid = str(group_model.create_group("PosGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "PosPC")

        agent_service.update_position(agent["agent_id"], 5)
        found = agent_model.find_by_agent_id(agent["agent_id"])
        assert found["position"] == 5

    def test_update_position_invalid_type_fails(self, agent_service, agent_model, group_model):
        gid = str(group_model.create_group("PosGrpInvalid", "")["_id"])
        agent = insert_agent(agent_model, gid, "PosPCInvalid")

        with pytest.raises(ValueError, match="position must be an integer or null"):
            agent_service.update_position(agent["agent_id"], {"row": 1})

    def test_delete_agent(self, agent_service, agent_model, group_model):
        """Delete agent - xóa khỏi DB."""
        gid = str(group_model.create_group("DelGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "DelPC")

        result = agent_service.delete_agent(agent["agent_id"])
        assert result is True
        assert agent_model.find_by_agent_id(agent["agent_id"]) is None

    def test_delete_nonexistent_agent(self, agent_service):
        """Delete agent không tồn tại - raise."""
        with pytest.raises(ValueError, match="Agent not found"):
            agent_service.delete_agent("fake-id")

    def test_get_agent_details(self, agent_service, agent_model, group_model):
        """Get agent details - đầy đủ fields."""
        gid = str(group_model.create_group("DetGrp", "")["_id"])
        agent = insert_agent(agent_model, gid, "DetailPC")

        details = agent_service.get_agent_details(agent["agent_id"])
        assert details["agent_id"] == agent["agent_id"]
        assert details["hostname"] == "DetailPC"
        assert "server_time" in details

    def test_get_agent_details_not_found(self, agent_service):
        with pytest.raises(ValueError, match="Agent not found"):
            agent_service.get_agent_details("nonexistent")


# ============================================================================
# 5. AGENT POLICY INTERACTION TESTS
# ============================================================================

class TestAgentPolicyInteraction:
    """Test policy ảnh hưởng đến heartbeat response."""

    def test_heartbeat_no_policy_model(self, agent_service):
        """Agent service không có policy_model → force_sync=False."""
        data = make_agent_data("NoPolicyPC", ip="10.0.8.1")
        reg = agent_service.register_agent(data, "10.0.8.1")

        hb = agent_service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": now_vietnam().isoformat()},
            "10.0.8.1"
        )
        assert hb["force_sync"] is False
        assert hb["policy_mode"] == "none"

    def test_heartbeat_with_active_policy(self, agent_model, group_model):
        """Agent có policy isolate → heartbeat trả force_sync=True."""
        mock_policy = MagicMock()
        mock_policy.get_effective_mode.return_value = "isolate"

        service = AgentService(agent_model, group_model, policy_model=mock_policy)
        data = make_agent_data("PolicyPC", ip="10.0.8.2")
        reg = service.register_agent(data, "10.0.8.2")

        hb = service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": now_vietnam().isoformat()},
            "10.0.8.2"
        )
        assert hb["force_sync"] is True
        assert hb["policy_mode"] == "isolate"

    def test_heartbeat_policy_none_no_sync(self, agent_model, group_model):
        """Agent policy = none → force_sync=False."""
        mock_policy = MagicMock()
        mock_policy.get_effective_mode.return_value = "none"

        service = AgentService(agent_model, group_model, policy_model=mock_policy)
        data = make_agent_data("NonePolPC", ip="10.0.8.3")
        reg = service.register_agent(data, "10.0.8.3")

        hb = service.process_heartbeat(
            reg["agent_id"], reg["token"],
            {"timestamp": now_vietnam().isoformat()},
            "10.0.8.3"
        )
        assert hb["force_sync"] is False
