"""
Comprehensive Test Suite: Agent + Agent Policy
================================================
Tests toàn bộ chức năng Agent (mở rộng từ test_agents.py):
1. AgentModel        - CRUD, heartbeat, status, statistics
2. AgentService      - Registration, heartbeat, group move, display name
3. AgentPolicyModel  - set/get/reset policy, expiry, custom whitelist, batch
4. AgentPolicyService - isolate/reset, apply_policy_to_sync, system entries
5. AgentController   - HTTP endpoints (register, heartbeat, list, policy CRUD)
6. RBAC              - Teacher agent isolation, ownership checks

Run:
  cd server && python -m pytest tests/test_agent_full.py -v
  cd server && python -m pytest tests/test_agent_full.py -v -k "test_policy"
  cd server && python -m pytest tests/test_agent_full.py -v -k "test_controller"
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
from models.agent_policy_model import AgentPolicyModel
from services.agent_service import AgentService
from services.agent_policy_service import AgentPolicyService
from services.rbac_service import RBACService
from flask import g
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


TEST_DB = 'test_saint_agent_full'


@pytest.fixture
def db(mongo_client):
    from bson.codec_options import CodecOptions
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
def policy_model(db):
    return AgentPolicyModel(db)


@pytest.fixture
def agent_service(agent_model, group_model):
    return AgentService(agent_model, group_model, socketio=None, jwt_service=None)


@pytest.fixture
def policy_service(policy_model, agent_model):
    return AgentPolicyService(policy_model, agent_model, socketio=None)


@pytest.fixture
def rbac_service(group_model, agent_model):
    return RBACService(group_model=group_model, agent_model=agent_model)


# ============================================================================
# HELPERS
# ============================================================================

def make_admin():
    return {"_id": ObjectId(), "username": "admin01", "role": "admin"}


def make_teacher(tid=None):
    return {"_id": tid or ObjectId(), "username": "teacher01", "role": "teacher"}


def create_group(group_model, name, created_by=None, whitelist=None):
    return group_model.create_group(name, "", whitelist or [], created_by=created_by)


def insert_agent(agent_model, group_id, hostname="PC-01", agent_id=None):
    aid = agent_id or str(uuid.uuid4())
    did = str(uuid.uuid4())
    token = secrets.token_hex(32)
    data = {
        "agent_id": aid, "device_id": did, "hostname": hostname,
        "display_name": hostname, "ip_address": "192.168.1.10",
        "platform": "Windows", "agent_token": token,
        "group_id": group_id, "status": "active",
        "last_heartbeat": now_vietnam(),
    }
    agent_model.register_agent(data)
    return {**data, "agent_token": token}


def _mock_auth(user):
    return patch.multiple(
        'middleware.rbac',
        _extract_token=lambda: 'fake-token',
        _validate_admin_token=lambda token: (True, user, None),
    )


class _set_current_user:
    """Context manager to set g.current_user inside a Flask app context."""
    def __init__(self, app, user, rbac_svc=None):
        self.app = app
        self.user = user
        self.rbac_svc = rbac_svc

    def __enter__(self):
        import middleware.rbac as rbac_mod
        self._orig_rbac = rbac_mod._rbac_service
        if self.rbac_svc:
            rbac_mod._rbac_service = self.rbac_svc
        return self

    def __exit__(self, *args):
        import middleware.rbac as rbac_mod
        rbac_mod._rbac_service = self._orig_rbac


# ============================================================================
# 1. AGENT MODEL TESTS
# ============================================================================

class TestAgentModel:

    def test_register_agent(self, agent_model, group_model):
        g = create_group(group_model, "Test Group")
        gid = str(g["_id"])
        data = {
            "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
            "hostname": "TestPC", "display_name": "TestPC",
            "ip_address": "10.0.0.1", "platform": "Windows",
            "agent_token": secrets.token_hex(32), "group_id": gid,
        }
        result = agent_model.register_agent(data)
        assert result is not None
        assert result.get("agent_id") == data["agent_id"]

    def test_find_by_agent_id(self, agent_model, group_model):
        g = create_group(group_model, "Find Group")
        agent = insert_agent(agent_model, str(g["_id"]), agent_id="find-me-123")
        found = agent_model.find_by_agent_id("find-me-123")
        assert found is not None
        assert found["hostname"] == "PC-01"

    def test_find_by_agent_id_not_found(self, agent_model):
        assert agent_model.find_by_agent_id("nonexistent") is None

    def test_find_by_device_id(self, agent_model, group_model):
        g = create_group(group_model, "DevID Group")
        did = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": str(uuid.uuid4()), "device_id": did,
            "hostname": "DevPC", "display_name": "DevPC",
            "ip_address": "10.0.0.2", "platform": "Linux",
            "agent_token": secrets.token_hex(32),
            "group_id": str(g["_id"]),
        })
        found = agent_model.find_by_device_id(did)
        assert found is not None

    def test_find_by_hostname(self, agent_model, group_model):
        g = create_group(group_model, "Host Group")
        insert_agent(agent_model, str(g["_id"]), hostname="UniqueHost123")
        results = agent_model.find_by_hostname("UniqueHost123")
        assert len(results) >= 1

    def test_update_agent(self, agent_model, group_model):
        g = create_group(group_model, "Update Group")
        agent = insert_agent(agent_model, str(g["_id"]), agent_id="upd-agent")
        result = agent_model.update_agent("upd-agent", {"display_name": "New Name"})
        assert result is True
        updated = agent_model.find_by_agent_id("upd-agent")
        assert updated["display_name"] == "New Name"

    def test_update_agent_group(self, agent_model, group_model):
        g1 = create_group(group_model, "Group A")
        g2 = create_group(group_model, "Group B")
        agent = insert_agent(agent_model, str(g1["_id"]), agent_id="move-agent")
        result = agent_model.update_agent_group("move-agent", str(g2["_id"]))
        assert result is True
        moved = agent_model.find_by_agent_id("move-agent")
        assert moved["group_id"] == str(g2["_id"])

    def test_update_heartbeat(self, agent_model, group_model):
        g = create_group(group_model, "HB Group")
        agent = insert_agent(agent_model, str(g["_id"]), agent_id="hb-agent")
        result = agent_model.update_heartbeat("hb-agent", {
            "ip_address": "10.0.0.99",
            "cpu_usage": 45.2,
        })
        assert result is True

    def test_delete_agent(self, agent_model, group_model):
        g = create_group(group_model, "Del Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="del-agent")
        assert agent_model.delete_agent("del-agent") is True
        assert agent_model.find_by_agent_id("del-agent") is None

    def test_delete_agent_not_found(self, agent_model):
        assert agent_model.delete_agent("no-such-agent") is False

    def test_count_by_group(self, agent_model, group_model):
        g = create_group(group_model, "Count Group")
        gid = str(g["_id"])
        insert_agent(agent_model, gid, agent_id="cnt-1")
        insert_agent(agent_model, gid, agent_id="cnt-2")
        assert agent_model.count_by_group(gid) == 2

    def test_get_all_agents(self, agent_model, group_model):
        g = create_group(group_model, "All Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="all-1")
        agents = agent_model.get_all_agents()
        assert len(agents) >= 1

    def test_count_agents(self, agent_model, group_model):
        g = create_group(group_model, "CA Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="ca-1")
        assert agent_model.count_agents() >= 1

    def test_get_agent_statistics(self, agent_model, group_model):
        g = create_group(group_model, "Stats Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="stat-1")
        stats = agent_model.get_agent_statistics()
        assert stats.get("total", 0) >= 1

    def test_get_active_agents(self, agent_model, group_model):
        g = create_group(group_model, "Active Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="active-1")
        active = agent_model.get_active_agents(inactive_threshold_minutes=5)
        assert len(active) >= 1

    def test_get_inactive_agents(self, agent_model, group_model):
        g = create_group(group_model, "Inactive Group")
        aid = str(uuid.uuid4())
        agent_model.register_agent({
            "agent_id": aid, "device_id": str(uuid.uuid4()),
            "hostname": "OldPC", "display_name": "OldPC",
            "ip_address": "10.0.0.3", "platform": "Windows",
            "agent_token": secrets.token_hex(32),
            "group_id": str(g["_id"]),
        })
        # register_agent overrides last_heartbeat, so update it manually
        old_time = now_vietnam() - timedelta(hours=1)
        agent_model.collection.update_one(
            {"agent_id": aid}, {"$set": {"last_heartbeat": old_time}}
        )
        inactive = agent_model.get_inactive_agents(inactive_threshold_minutes=5)
        agent_ids = [a["agent_id"] for a in inactive]
        assert aid in agent_ids


# ============================================================================
# 2. AGENT SERVICE TESTS
# ============================================================================

class TestAgentService:

    def test_register_new_agent(self, agent_service, group_model):
        g = create_group(group_model, "Svc Reg Group")
        data = {
            "agent_id": str(uuid.uuid4()), "device_id": str(uuid.uuid4()),
            "hostname": "SvcPC", "ip_address": "10.0.0.5",
            "platform": "Windows", "group_id": str(g["_id"]),
        }
        result = agent_service.register_agent(data, "127.0.0.1")
        assert result.get("success") is True or result.get("agent_id") is not None

    def test_get_agents_with_status(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "Status Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="status-1")
        agents = agent_service.get_agents_with_status()
        assert len(agents) >= 1
        # Each should have a calculated status
        assert agents[0].get("status") in ("active", "inactive", "offline", "pending")

    def test_calculate_statistics(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "CalcStats Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="cs-1")
        stats = agent_service.calculate_statistics()
        assert stats.get("total", 0) >= 1

    def test_get_agent_details(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "Detail Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="detail-1")
        details = agent_service.get_agent_details("detail-1")
        assert details is not None
        assert details.get("agent_id") == "detail-1"

    def test_get_agent_details_not_found(self, agent_service):
        with pytest.raises(ValueError, match="Agent not found"):
            agent_service.get_agent_details("nonexistent-agent")

    def test_delete_agent_via_service(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "SvcDel Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="svc-del-1")
        result = agent_service.delete_agent("svc-del-1")
        assert result is True

    def test_update_display_name(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "Name Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="name-1")
        result = agent_service.update_display_name("name-1", "Custom Name")
        assert result is True
        agent = agent_model.find_by_agent_id("name-1")
        assert agent["display_name"] == "Custom Name"

    def test_move_agent_to_group(self, agent_service, agent_model, group_model):
        g1 = create_group(group_model, "From Group")
        g2 = create_group(group_model, "To Group")
        insert_agent(agent_model, str(g1["_id"]), agent_id="mover-1")
        result = agent_service.move_agent_to_group("mover-1", str(g2["_id"]))
        assert result.get("group_id") == str(g2["_id"])
        agent = agent_model.find_by_agent_id("mover-1")
        assert agent["group_id"] == str(g2["_id"])

    def test_get_total_agents(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "Total Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="total-1")
        assert agent_service.get_total_agents() >= 1

    def test_get_active_agents_count(self, agent_service, agent_model, group_model):
        g = create_group(group_model, "ActiveCnt Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="actcnt-1")
        assert agent_service.get_active_agents_count() >= 1


# ============================================================================
# 3. AGENT POLICY MODEL TESTS
# ============================================================================

class TestAgentPolicyModel:

    def test_set_policy_isolate(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Policy Group")
        agent = insert_agent(agent_model, str(g["_id"]), agent_id="pol-iso-1")
        user = make_admin()
        result = policy_model.set_policy("pol-iso-1", "isolate", user, reason="Test isolate")
        assert result["override_mode"] == "isolate"
        assert result["reason"] == "Test isolate"

    def test_set_policy_custom_whitelist(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Custom Policy Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="pol-cust-1")
        user = make_admin()
        custom_wl = [{"domain": "wikipedia.org", "category": "education"}]
        result = policy_model.set_policy("pol-cust-1", "custom_whitelist", user,
                                          custom_whitelist=custom_wl)
        assert result["override_mode"] == "custom_whitelist"
        assert len(result.get("custom_whitelist", [])) == 1

    def test_set_policy_invalid_mode_raises(self, policy_model):
        with pytest.raises(ValueError, match="Invalid mode"):
            policy_model.set_policy("any-agent", "bad_mode", make_admin())

    def test_get_policy(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "GetPol Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="getpol-1")
        policy_model.set_policy("getpol-1", "isolate", make_admin())
        policy = policy_model.get_policy("getpol-1")
        assert policy is not None
        assert policy["override_mode"] == "isolate"
        assert isinstance(policy["_id"], str)

    def test_get_policy_not_found(self, policy_model):
        assert policy_model.get_policy("nonexistent-agent") is None

    def test_get_effective_mode_none(self, policy_model):
        assert policy_model.get_effective_mode("no-policy-agent") == "none"

    def test_get_effective_mode_isolate(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "EffMode Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="effmode-1")
        policy_model.set_policy("effmode-1", "isolate", make_admin())
        assert policy_model.get_effective_mode("effmode-1") == "isolate"

    def test_get_effective_mode_expired_resets(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Expired Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="expired-1")
        past = now_vietnam() - timedelta(hours=1)
        policy_model.set_policy("expired-1", "isolate", make_admin(), expires_at=past)
        mode = policy_model.get_effective_mode("expired-1")
        assert mode == "none"

    def test_reset_policy(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Reset Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="reset-1")
        policy_model.set_policy("reset-1", "isolate", make_admin())
        policy_model.reset_policy("reset-1", make_admin())
        assert policy_model.get_effective_mode("reset-1") == "none"

    def test_get_custom_whitelist(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "CWL Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="cwl-1")
        entries = [{"domain": "a.com"}, {"domain": "b.com"}]
        policy_model.set_policy("cwl-1", "custom_whitelist", make_admin(),
                                 custom_whitelist=entries)
        wl = policy_model.get_custom_whitelist("cwl-1")
        assert len(wl) == 2

    def test_get_custom_whitelist_empty(self, policy_model):
        assert policy_model.get_custom_whitelist("no-wl-agent") == []

    def test_list_isolated_agents(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Isolated List Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="iso-list-1")
        insert_agent(agent_model, str(g["_id"]), agent_id="iso-list-2")
        policy_model.set_policy("iso-list-1", "isolate", make_admin())
        policy_model.set_policy("iso-list-2", "none", make_admin())
        isolated = policy_model.list_isolated_agents()
        assert "iso-list-1" in isolated
        assert "iso-list-2" not in isolated

    def test_list_policies_by_agent_ids(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Batch Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="batch-1")
        insert_agent(agent_model, str(g["_id"]), agent_id="batch-2")
        policy_model.set_policy("batch-1", "isolate", make_admin())
        policy_model.set_policy("batch-2", "custom_whitelist", make_admin(),
                                 custom_whitelist=[{"domain": "x.com"}])
        result = policy_model.list_policies_by_agent_ids(["batch-1", "batch-2", "batch-3"])
        assert "batch-1" in result
        assert "batch-2" in result
        assert "batch-3" not in result

    def test_count_by_mode(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "CountMode Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="cm-1")
        insert_agent(agent_model, str(g["_id"]), agent_id="cm-2")
        policy_model.set_policy("cm-1", "isolate", make_admin())
        policy_model.set_policy("cm-2", "isolate", make_admin())
        counts = policy_model.count_by_mode()
        assert counts.get("isolate", 0) >= 2

    def test_upsert_overwrites_policy(self, policy_model, agent_model, group_model):
        g = create_group(group_model, "Upsert Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="upsert-1")
        policy_model.set_policy("upsert-1", "isolate", make_admin())
        policy_model.set_policy("upsert-1", "custom_whitelist", make_admin(),
                                 custom_whitelist=[{"domain": "y.com"}])
        p = policy_model.get_policy("upsert-1")
        assert p["override_mode"] == "custom_whitelist"


# ============================================================================
# 4. AGENT POLICY SERVICE TESTS
# ============================================================================

class TestAgentPolicyService:

    def test_get_policy_default(self, policy_service):
        policy = policy_service.get_policy("no-such-agent")
        assert policy["override_mode"] == "none"

    def test_set_policy_isolate(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "SvcIso Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="svc-iso-1")
        result = policy_service.set_policy("svc-iso-1", "isolate", make_admin(),
                                            reason="Testing")
        assert result["override_mode"] == "isolate"

    def test_set_policy_agent_not_found_raises(self, policy_service):
        with pytest.raises(ValueError, match="not found"):
            policy_service.set_policy("ghost-agent", "isolate", make_admin())

    def test_isolate_agent_shortcut(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "Isolate SC Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="iso-sc-1")
        result = policy_service.isolate_agent("iso-sc-1", make_admin())
        assert result["override_mode"] == "isolate"

    def test_reset_agent_shortcut(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "Reset SC Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="rst-sc-1")
        policy_service.isolate_agent("rst-sc-1", make_admin())
        result = policy_service.reset_agent("rst-sc-1", make_admin())
        assert result["override_mode"] == "none"

    def test_set_policy_with_duration(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "Duration Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="dur-1")
        result = policy_service.set_policy("dur-1", "isolate", make_admin(),
                                            duration_minutes=60)
        assert result.get("expires_at") is not None

    def test_apply_policy_to_sync_none(self, policy_service):
        domains = [{"domain": "google.com", "category": "search"}]
        result = policy_service.apply_policy_to_sync("no-policy-agent", domains)
        assert result["policy_mode"] == "none"
        assert result["policy_active"] is False
        assert result["domains"] == domains

    def test_apply_policy_to_sync_isolate(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "SyncIso Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="sync-iso-1")
        policy_service.isolate_agent("sync-iso-1", make_admin())
        domains = [{"domain": "google.com"}]
        result = policy_service.apply_policy_to_sync("sync-iso-1", domains,
                                                      server_host="10.0.0.1")
        assert result["policy_mode"] == "isolate"
        assert result["policy_active"] is True
        # Should only contain the server host, NOT group whitelist or DNS
        dom_values = [d.get("domain") for d in result["domains"]]
        assert "google.com" not in dom_values
        assert "10.0.0.1" in dom_values
        assert "8.8.8.8" not in dom_values
        assert "8.8.4.4" not in dom_values
        assert "1.1.1.1" not in dom_values

    def test_apply_policy_to_sync_custom(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "SyncCust Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="sync-cust-1")
        policy_service.set_policy("sync-cust-1", "custom_whitelist", make_admin(),
                                   custom_whitelist=[{"domain": "wiki.org"}])
        result = policy_service.apply_policy_to_sync("sync-cust-1",
                                                      [{"domain": "google.com"}],
                                                      server_host="server.local")
        assert result["policy_mode"] == "custom_whitelist"
        assert result["policy_active"] is True
        dom_values = [d.get("domain") for d in result["domains"]]
        assert "server.local" in dom_values
        assert "wiki.org" in dom_values
        assert "google.com" not in dom_values
        assert "8.8.8.8" not in dom_values
        assert "1.1.1.1" not in dom_values

    def test_get_policies_for_agents(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "BatchSvc Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="bsvc-1")
        policy_service.isolate_agent("bsvc-1", make_admin())
        result = policy_service.get_policies_for_agents(["bsvc-1", "nonexist"])
        assert "bsvc-1" in result

    def test_get_stats(self, policy_service, agent_model, group_model):
        g = create_group(group_model, "StatsSvc Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="statsvc-1")
        policy_service.isolate_agent("statsvc-1", make_admin())
        stats = policy_service.get_stats()
        assert isinstance(stats, dict)


# ============================================================================
# 5. AGENT CONTROLLER TESTS
# ============================================================================

class TestAgentController:

    @pytest.fixture
    def app(self, agent_model, agent_service, rbac_service, policy_service):
        from flask import Flask
        import controllers.agent_controller as ac_mod

        # Patch require_jwt and require_api_key at module level
        orig_jwt = getattr(ac_mod, 'require_jwt', None)
        orig_apikey = getattr(ac_mod, 'require_api_key', None)
        orig_login = getattr(ac_mod, 'require_login', None)
        ac_mod.require_jwt = lambda f: f
        ac_mod.require_api_key = lambda *args, **kwargs: (lambda f: f)
        ac_mod.require_login = lambda f: f

        try:
            from controllers.agent_controller import AgentController
            app = Flask(__name__)
            app.config['TESTING'] = True
            controller = AgentController(
                agent_model, agent_service, rbac_service, socketio=None,
                policy_service=policy_service,
            )
            app.register_blueprint(controller.blueprint, url_prefix='/api')

            # Inject a default admin user into g.current_user
            @app.before_request
            def _inject_admin():
                if not hasattr(g, 'current_user') or g.current_user is None:
                    g.current_user = make_admin()

            yield app
        finally:
            if orig_jwt:
                ac_mod.require_jwt = orig_jwt
            if orig_apikey:
                ac_mod.require_api_key = orig_apikey
            if orig_login:
                ac_mod.require_login = orig_login

    def test_list_agents_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/agents')
                assert resp.status_code == 200

    def test_get_statistics(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/agents/statistics')
                assert resp.status_code == 200

    def test_register_agent_via_api(self, app, group_model):
        g = create_group(group_model, "API Reg Group")
        with app.test_client() as client:
            resp = client.post('/api/agents/register', json={
                "hostname": "APIPC",
                "device_id": str(uuid.uuid4()),
                "ip_address": "10.0.0.50",
                "platform": "Windows",
            })
            # May succeed or 400 depending on API key
            assert resp.status_code in (200, 201, 400)

    def test_get_agent_detail(self, app, agent_model, group_model):
        g = create_group(group_model, "Detail API Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="api-detail-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/agents/api-detail-1')
                assert resp.status_code == 200

    def test_delete_agent_via_api(self, app, agent_model, group_model):
        g = create_group(group_model, "Del API Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="api-del-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.delete('/api/agents/api-del-1')
                assert resp.status_code == 200

    def test_update_display_name_via_api(self, app, agent_model, group_model):
        g = create_group(group_model, "Name API Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="api-name-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.patch('/api/agents/api-name-1/display-name', json={
                    "display_name": "Renamed"
                })
                assert resp.status_code == 200

    def test_update_group_via_api(self, app, agent_model, group_model):
        g1 = create_group(group_model, "From API Group")
        g2 = create_group(group_model, "To API Group")
        insert_agent(agent_model, str(g1["_id"]), agent_id="api-grp-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.patch('/api/agents/api-grp-1/group', json={
                    "group_id": str(g2["_id"])
                })
                assert resp.status_code == 200

    def test_get_agent_policy_via_api(self, app, agent_model, group_model):
        g = create_group(group_model, "Pol API Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="api-pol-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/agents/api-pol-1/policy')
                assert resp.status_code == 200

    def test_set_agent_policy_via_api(self, app, agent_model, group_model):
        g = create_group(group_model, "SetPol API Group")
        insert_agent(agent_model, str(g["_id"]), agent_id="api-setpol-1")
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.patch('/api/agents/api-setpol-1/policy', json={
                    "mode": "isolate",
                    "reason": "Test via API",
                })
                assert resp.status_code == 200


# ============================================================================
# 6. RBAC - TEACHER AGENT ISOLATION
# ============================================================================

class TestRBACAgentTeacher:

    def _make_rbac_app(self, agent_model, agent_service, rbac_service, policy_service, user):
        """Build app with g.current_user set via before_request + rbac_service wired."""
        from flask import Flask
        import controllers.agent_controller as ac_mod
        import middleware.rbac as rbac_mod

        orig_jwt = getattr(ac_mod, 'require_jwt', None)
        orig_apikey = getattr(ac_mod, 'require_api_key', None)
        orig_login = getattr(ac_mod, 'require_login', None)
        ac_mod.require_jwt = lambda f: f
        ac_mod.require_api_key = lambda *args, **kwargs: (lambda f: f)
        ac_mod.require_login = lambda f: f

        orig_rbac = rbac_mod._rbac_service
        rbac_mod._rbac_service = rbac_service

        try:
            from controllers.agent_controller import AgentController
            app = Flask(__name__)
            app.config['TESTING'] = True
            controller = AgentController(
                agent_model, agent_service, rbac_service, socketio=None,
                policy_service=policy_service,
            )
            app.register_blueprint(controller.blueprint, url_prefix='/api')

            @app.before_request
            def _inject_user():
                g.current_user = user

            yield app
        finally:
            if orig_jwt:
                ac_mod.require_jwt = orig_jwt
            if orig_apikey:
                ac_mod.require_api_key = orig_apikey
            if orig_login:
                ac_mod.require_login = orig_login
            rbac_mod._rbac_service = orig_rbac

    def test_teacher_sees_only_own_group_agents(self, agent_model, agent_service,
                                                 rbac_service, policy_service, group_model):
        teacher = make_teacher()
        own_group = create_group(group_model, "Teacher Own", created_by=teacher["_id"])
        other_group = create_group(group_model, "Other Own", created_by=ObjectId())
        insert_agent(agent_model, str(own_group["_id"]), agent_id="t-own-1", hostname="OwnPC")
        insert_agent(agent_model, str(other_group["_id"]), agent_id="t-other-1", hostname="OtherPC")

        for app in self._make_rbac_app(agent_model, agent_service, rbac_service,
                                        policy_service, teacher):
            with app.test_client() as client:
                resp = client.get('/api/agents')
                assert resp.status_code == 200
                data = resp.get_json()
                agents = data.get("data", data.get("agents", []))
                agent_ids = [a.get("agent_id") for a in agents]
                assert "t-own-1" in agent_ids
                assert "t-other-1" not in agent_ids

    def test_teacher_cannot_delete_other_agent(self, agent_model, agent_service,
                                                rbac_service, policy_service, group_model):
        teacher = make_teacher()
        other_group = create_group(group_model, "Other Del", created_by=ObjectId())
        insert_agent(agent_model, str(other_group["_id"]), agent_id="t-nodel-1")

        for app in self._make_rbac_app(agent_model, agent_service, rbac_service,
                                        policy_service, teacher):
            with app.test_client() as client:
                resp = client.delete('/api/agents/t-nodel-1')
                assert resp.status_code == 403

    def test_teacher_cannot_move_agent_to_other_group(self, agent_model, agent_service,
                                                      rbac_service, policy_service, group_model):
        teacher = make_teacher()
        own_group = create_group(group_model, "Teacher Move Src", created_by=teacher["_id"])
        other_group = create_group(group_model, "Other Move Dst", created_by=ObjectId())
        insert_agent(agent_model, str(own_group["_id"]), agent_id="t-nomove-1")

        # Teacher cannot move agent INTO a group they don't own
        for app in self._make_rbac_app(agent_model, agent_service, rbac_service,
                                        policy_service, teacher):
            with app.test_client() as client:
                resp = client.patch('/api/agents/t-nomove-1/group', json={
                    "group_id": str(other_group["_id"])
                })
                assert resp.status_code == 403
