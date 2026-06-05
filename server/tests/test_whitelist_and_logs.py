"""
Comprehensive Test Suite: Whitelist & Log Management
=====================================================
Tests toàn bộ chức năng Whitelist và Log:
1. WhitelistModel    - CRUD, validation, versioning, bulk, scope filtering
2. WhitelistService  - add/delete/update entry, scoped whitelist, agent sync, statistics
3. WhitelistController - HTTP endpoints, RBAC teacher filtering, bulk ops
4. LogModel          - insert/query, count, pagination, summary
5. LogService        - receive_logs, protocol detection, time range, statistics
6. LogController     - HTTP endpoints, RBAC teacher isolation, clear/export blocked
7. CrossTeacher      - Teacher whitelist/log isolation, admin full access

Sử dụng REAL MongoDB (test database) để integration test chính xác.

Run:
  cd server && python -m pytest tests/test_whitelist_and_logs.py -v
  cd server && python -m pytest tests/test_whitelist_and_logs.py -v -k "test_whitelist_model"
  cd server && python -m pytest tests/test_whitelist_and_logs.py -v -k "test_log"
  cd server && python -m pytest tests/test_whitelist_and_logs.py -v -k "test_controller"
  cd server && python -m pytest tests/test_whitelist_and_logs.py -v -k "test_rbac"
"""

import pytest
import sys
import os
import uuid
import json
import secrets
import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from bson import ObjectId

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from models.whitelist_model import WhitelistModel
from models.whitelist_entry_model import WhitelistEntryModel
from models.whitelist_profile_model import WhitelistProfileModel
from models.log_model import LogModel
from models.agent_model import AgentModel
from models.group_model import GroupModel
from services.whitelist_service import WhitelistService
from services.whitelist_profile_service import WhitelistProfileService
from services.log_service import LogService
from services.rbac_service import RBACService
from controllers.whitelist_controller import WhitelistController
from controllers.log_controller import LogController
from time_utils import now_vietnam, VIETNAM_TZ


# ============================================================================
# FIXTURES - Database & Models (real MongoDB)
# ============================================================================

@pytest.fixture(scope='session')
def mongo_client():
    """Create MongoDB client using same config as server (.env)."""
    from pymongo import MongoClient
    from dotenv import load_dotenv

    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path)

    uri = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    client = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    yield client
    client.close()


TEST_DB = 'test_saint_whitelist_logs'


@pytest.fixture
def db(mongo_client):
    """Fresh test database with Vietnam timezone codec - dropped after each test."""
    from bson.codec_options import CodecOptions
    codec = CodecOptions(tz_aware=True, tzinfo=VIETNAM_TZ)
    database = mongo_client.get_database(TEST_DB, codec_options=codec)
    yield database
    mongo_client.drop_database(TEST_DB)


@pytest.fixture
def whitelist_model(db):
    return WhitelistModel(db)


@pytest.fixture
def whitelist_entry_model(db):
    return WhitelistEntryModel(db)


@pytest.fixture
def whitelist_profile_model(db):
    return WhitelistProfileModel(db)


@pytest.fixture
def log_model(db):
    return LogModel(db)


@pytest.fixture
def agent_model(db):
    return AgentModel(db)


@pytest.fixture
def group_model(db):
    return GroupModel(db)


@pytest.fixture
def rbac_service(group_model, agent_model):
    return RBACService(group_model=group_model, agent_model=agent_model)


@pytest.fixture
def whitelist_service(whitelist_model, agent_model, group_model):
    return WhitelistService(whitelist_model, agent_model, group_model, socketio=None)


@pytest.fixture
def whitelist_service_with_entries(whitelist_model, whitelist_entry_model, agent_model, group_model):
    return WhitelistService(
        whitelist_model,
        agent_model,
        group_model,
        socketio=None,
        entry_model=whitelist_entry_model,
    )


@pytest.fixture
def whitelist_profile_service(whitelist_profile_model, group_model):
    return WhitelistProfileService(whitelist_profile_model, group_model, socketio=None)


@pytest.fixture
def whitelist_service_with_profiles(whitelist_model, agent_model, group_model, whitelist_profile_service):
    return WhitelistService(
        whitelist_model,
        agent_model,
        group_model,
        socketio=None,
        profile_service=whitelist_profile_service,
    )


@pytest.fixture
def log_service(log_model, agent_model):
    return LogService(log_model, agent_model=agent_model, socketio=None)


# ============================================================================
# HELPERS
# ============================================================================

def make_admin():
    return {"_id": ObjectId(), "username": "admin01", "role": "admin"}


def make_teacher(teacher_id=None):
    return {"_id": teacher_id or ObjectId(), "username": "teacher01", "role": "teacher"}


def create_group(group_model, name, created_by=None, whitelist=None):
    """Insert a group and return it."""
    return group_model.create_group(name, description="", whitelist=whitelist or [], created_by=created_by)


def insert_agent(agent_model, group_id, hostname="PC-01", agent_id=None):
    """Register an agent in a group."""
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
    """Patch RBAC middleware to simulate authenticated user."""
    return patch.multiple(
        'middleware.rbac',
        _extract_token=lambda: 'fake-token',
        _validate_admin_token=lambda token: (True, user, None),
    )


# ============================================================================
# 1. WHITELIST MODEL TESTS
# ============================================================================

class TestWhitelistModel:
    """Test WhitelistModel CRUD, validation, versioning."""

    def test_insert_entry_domain(self, whitelist_model):
        entry_id = whitelist_model.insert_entry({
            "value": "example.com", "type": "domain", "scope": "global"
        })
        assert entry_id is not None
        entry = whitelist_model.find_entry_by_id(entry_id)
        assert entry["value"] == "example.com"
        assert entry["type"] == "domain"
        assert entry["is_active"] is True

    def test_insert_entry_ip(self, whitelist_model):
        entry_id = whitelist_model.insert_entry({
            "value": "192.168.1.1", "type": "ip", "scope": "global"
        })
        assert entry_id is not None
        entry = whitelist_model.find_entry_by_id(entry_id)
        assert entry["value"] == "192.168.1.1"
        assert entry["type"] == "ip"

    def test_insert_entry_lowercase_trim(self, whitelist_model):
        entry_id = whitelist_model.insert_entry({
            "value": "  EXAMPLE.COM  ", "type": "domain"
        })
        entry = whitelist_model.find_entry_by_id(entry_id)
        assert entry["value"] == "example.com"

    def test_insert_entry_empty_value_raises(self, whitelist_model):
        with pytest.raises(ValueError, match="Value field is required"):
            whitelist_model.insert_entry({"value": "", "type": "domain"})

    def test_find_entry_by_value(self, whitelist_model):
        whitelist_model.insert_entry({"value": "google.com", "type": "domain"})
        found = whitelist_model.find_entry_by_value("google.com")
        assert found is not None
        assert found["value"] == "google.com"

    def test_find_entry_by_value_case_insensitive(self, whitelist_model):
        whitelist_model.insert_entry({"value": "test.com", "type": "domain"})
        found = whitelist_model.find_entry_by_value("TEST.COM")
        assert found is not None

    def test_find_entry_by_value_not_found(self, whitelist_model):
        found = whitelist_model.find_entry_by_value("nonexistent.com")
        assert found is None

    def test_delete_entry(self, whitelist_model):
        entry_id = whitelist_model.insert_entry({"value": "todelete.com", "type": "domain"})
        assert whitelist_model.delete_entry(entry_id) is True
        assert whitelist_model.find_entry_by_id(entry_id) is None

    def test_delete_entry_not_found(self, whitelist_model):
        fake_id = str(ObjectId())
        assert whitelist_model.delete_entry(fake_id) is False

    def test_update_entry(self, whitelist_model):
        entry_id = whitelist_model.insert_entry({"value": "update.com", "type": "domain"})
        result = whitelist_model.update_entry(entry_id, {"category": "security"})
        assert result is True
        updated = whitelist_model.find_entry_by_id(entry_id)
        assert updated["category"] == "security"

    def test_find_all_entries_default_scope(self, whitelist_model):
        whitelist_model.insert_entry({"value": "a.com", "type": "domain", "scope": "global"})
        whitelist_model.insert_entry({"value": "b.com", "type": "domain", "scope": "global"})
        entries = whitelist_model.find_all_entries()
        assert len(entries) >= 2
        for e in entries:
            assert isinstance(e["_id"], str)

    def test_find_all_entries_group_scope(self, whitelist_model):
        gid = str(ObjectId())
        whitelist_model.insert_entry({"value": "grp.com", "type": "domain", "scope": "group", "group_id": gid})
        entries = whitelist_model.find_all_entries({"scope": "group", "group_id": gid})
        assert len(entries) >= 1
        assert entries[0]["value"] == "grp.com"

    def test_global_version_bump(self, whitelist_model):
        v1 = whitelist_model.get_global_version()
        whitelist_model.insert_entry({"value": "bump1.com", "type": "domain", "scope": "global"})
        v2 = whitelist_model.get_global_version()
        assert v2 > v1

    def test_global_version_no_bump_for_group(self, whitelist_model):
        v1 = whitelist_model.get_global_version()
        whitelist_model.insert_entry({"value": "grponly.com", "type": "domain", "scope": "group", "group_id": str(ObjectId())})
        v2 = whitelist_model.get_global_version()
        assert v2 == v1

    def test_bulk_insert_entries(self, whitelist_model):
        entries = [
            {"value": "bulk1.com", "type": "domain"},
            {"value": "bulk2.com", "type": "domain"},
            {"value": "bulk3.com", "type": "domain"},
        ]
        ids = whitelist_model.bulk_insert_entries(entries)
        assert len(ids) == 3

    def test_bulk_insert_empty(self, whitelist_model):
        ids = whitelist_model.bulk_insert_entries([])
        assert ids == []

    def test_validate_domain_valid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("domain", "example.com")
        assert result["valid"] is True

    def test_validate_domain_invalid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("domain", "-invalid-.com")
        assert result["valid"] is False

    def test_validate_ip_valid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("ip", "10.0.0.1")
        assert result["valid"] is True

    def test_validate_ip_invalid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("ip", "999.999.999.999")
        assert result["valid"] is False

    def test_validate_url_valid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("url", "https://example.com/path")
        assert result["valid"] is True

    def test_validate_url_invalid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("url", "not-a-url")
        assert result["valid"] is False

    def test_validate_pattern_valid(self, whitelist_model):
        result = whitelist_model.validate_entry_value("pattern", "*.example.com")
        assert result["valid"] is True

    def test_validate_unknown_type(self, whitelist_model):
        result = whitelist_model.validate_entry_value("ftp", "something")
        assert result["valid"] is False

    def test_get_statistics(self, whitelist_model):
        whitelist_model.insert_entry({"value": "stat1.com", "type": "domain"})
        whitelist_model.insert_entry({"value": "1.2.3.4", "type": "ip"})
        stats = whitelist_model.get_statistics()
        assert stats["total"] >= 2
        assert stats["active"] >= 2
        assert "domain" in stats["by_type"]

    def test_get_entries_for_sync(self, whitelist_model):
        whitelist_model.insert_entry({"value": "sync1.com", "type": "domain", "scope": "global"})
        entries = whitelist_model.get_entries_for_sync(scope="global")
        values = [e["value"] for e in entries]
        assert "sync1.com" in values

    def test_cleanup_expired_entries(self, whitelist_model):
        # Insert an expired entry directly
        past = now_vietnam() - timedelta(days=10)
        whitelist_model.collection.insert_one({
            "value": "expired.com", "type": "domain", "is_active": True,
            "scope": "global", "expiry_date": past,
            "added_date": past, "created_at": past, "updated_at": past,
        })
        cleaned = whitelist_model.cleanup_expired_entries()
        assert cleaned >= 1


# ============================================================================
# 2. WHITELIST SERVICE TESTS
# ============================================================================

class TestWhitelistService:
    """Test WhitelistService business logic."""

    def test_add_entry_domain(self, whitelist_service):
        result = whitelist_service.add_entry(
            {"value": "service-test.com", "type": "domain"}, "127.0.0.1"
        )
        assert "id" in result
        assert result["message"].startswith("Domain")

    def test_add_entry_duplicate_raises(self, whitelist_service):
        whitelist_service.add_entry({"value": "dup.com", "type": "domain"}, "127.0.0.1")
        with pytest.raises(ValueError, match="already exists"):
            whitelist_service.add_entry({"value": "dup.com", "type": "domain"}, "127.0.0.1")

    def test_add_url_entry_stores_canonical_host(self, whitelist_service):
        result = whitelist_service.add_entry({
            "value": (
                "https://login.microsoftonline.com/oauth2/v2.0/authorize"
                "?scope=openid&state=abc"
            ),
            "type": "url",
        }, "127.0.0.1")

        entry = whitelist_service.model.find_entry_by_id(result["id"])
        assert entry["type"] == "domain"
        assert entry["value"] == "login.microsoftonline.com"

    def test_canonical_url_duplicate_raises(self, whitelist_service):
        whitelist_service.add_entry({
            "value": "https://dup-login.example.com/oauth?x=1",
            "type": "url",
        }, "127.0.0.1")

        with pytest.raises(ValueError, match="already exists"):
            whitelist_service.add_entry({
                "value": "dup-login.example.com",
                "type": "domain",
            }, "127.0.0.1")

    def test_add_entry_empty_value_raises(self, whitelist_service):
        with pytest.raises(ValueError, match="Value is required"):
            whitelist_service.add_entry({"value": "", "type": "domain"}, "127.0.0.1")

    def test_add_entry_invalid_domain_raises(self, whitelist_service):
        with pytest.raises(ValueError):
            whitelist_service.add_entry({"value": "-bad-.com", "type": "domain"}, "127.0.0.1")

    def test_get_all_entries(self, whitelist_service):
        whitelist_service.add_entry({"value": "list1.com", "type": "domain"}, "127.0.0.1")
        result = whitelist_service.get_all_entries()
        assert result["success"] is True
        assert len(result["domains"]) >= 1

    def test_delete_entry_via_service(self, whitelist_service):
        result = whitelist_service.add_entry({"value": "del-svc.com", "type": "domain"}, "127.0.0.1")
        entry_id = result["id"]
        assert whitelist_service.delete_entry(entry_id) is True

    def test_delete_entry_not_found_raises(self, whitelist_service):
        with pytest.raises(ValueError, match="Entry not found"):
            whitelist_service.delete_entry(str(ObjectId()))

    def test_update_entry_via_service(self, whitelist_service):
        result = whitelist_service.add_entry({"value": "upd-svc.com", "type": "domain"}, "127.0.0.1")
        entry_id = result["id"]
        success = whitelist_service.update_entry(entry_id, {"category": "updated"})
        assert success is True

    def test_update_entry_canonicalizes_url(self, whitelist_service):
        result = whitelist_service.add_entry({"value": "upd-url.com", "type": "domain"}, "127.0.0.1")
        entry_id = result["id"]

        success = whitelist_service.update_entry(entry_id, {
            "value": "https://updated-login.example.com/path?x=1",
            "type": "url",
        })

        assert success is True
        entry = whitelist_service.model.find_entry_by_id(entry_id)
        assert entry["type"] == "domain"
        assert entry["value"] == "updated-login.example.com"

    def test_get_statistics(self, whitelist_service):
        whitelist_service.add_entry({"value": "stat-svc.com", "type": "domain"}, "127.0.0.1")
        stats = whitelist_service.get_statistics()
        assert stats["total"] >= 1

    def test_get_scoped_whitelist_by_group(self, whitelist_service, group_model, agent_model):
        group = create_group(group_model, "Scoped Test Group", whitelist=[
            {"value": "grp-entry.com", "type": "domain"}
        ])
        gid = str(group["_id"])
        result = whitelist_service.get_scoped_whitelist(group_id=gid)
        assert result["success"] is True
        assert result["group_id"] == gid
        group_values = [e["value"] for e in result["group"]]
        assert "grp-entry.com" in group_values

    def test_get_scoped_whitelist_by_agent(self, whitelist_service, group_model, agent_model):
        group = create_group(group_model, "Agent Scope Group", whitelist=[
            {"value": "agent-scope.com", "type": "domain"}
        ])
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="ScopePC")
        result = whitelist_service.get_scoped_whitelist(agent_id=agent["agent_id"])
        assert result["success"] is True
        group_values = [e["value"] for e in result["group"]]
        assert "agent-scope.com" in group_values

    def test_bulk_add_entries(self, whitelist_service):
        items = [
            {"value": "bulk-svc1.com", "type": "domain"},
            {"value": "bulk-svc2.com", "type": "domain"},
        ]
        result = whitelist_service.bulk_add_entries(items, "127.0.0.1")
        assert result["success"] is True
        assert result["inserted_count"] >= 2

    def test_bulk_add_url_entry_stores_canonical_host(self, whitelist_service):
        result = whitelist_service.bulk_add_entries([{
            "value": "https://bulk-login.example.com/oauth?x=1",
            "type": "url",
        }], "127.0.0.1")

        assert result["success"] is True
        entry = whitelist_service.model.find_entry_by_value("bulk-login.example.com")
        assert entry["type"] == "domain"
        assert entry["value"] == "bulk-login.example.com"

    def test_bulk_add_entries_with_invalid(self, whitelist_service):
        items = [
            {"value": "bulk-ok.com", "type": "domain"},
            {"value": "", "type": "domain"},  # invalid
        ]
        result = whitelist_service.bulk_add_entries(items, "127.0.0.1")
        assert result["inserted_count"] >= 1
        assert result["error_count"] >= 1

    def test_bulk_delete_entries_global(self, whitelist_service):
        r1 = whitelist_service.add_entry({"value": "bdel1.com", "type": "domain"}, "127.0.0.1")
        r2 = whitelist_service.add_entry({"value": "bdel2.com", "type": "domain"}, "127.0.0.1")
        result = whitelist_service.bulk_delete_entries([r1["id"], r2["id"]])
        assert result["success"] is True
        assert result["deleted_count"] == 2

    def test_bulk_delete_group_entries(self, whitelist_service, group_model):
        group = create_group(group_model, "BulkDel Group", whitelist=[
            {"value": "grp-del.com", "type": "domain"},
            {"value": "grp-keep.com", "type": "domain"},
        ])
        gid = str(group["_id"])
        pseudo_id = f"group::{gid}::domain::grp-del.com"
        result = whitelist_service.bulk_delete_entries([pseudo_id])
        assert result["deleted_count"] == 1

    def test_legacy_group_pseudo_id_usage_is_logged_for_bulk_delete(
        self, whitelist_service, group_model, caplog
    ):
        group = create_group(group_model, "Pseudo Log Group", whitelist=[
            {"value": "pseudo-log.com", "type": "domain"},
        ])
        gid = str(group["_id"])
        pseudo_id = f"group::{gid}::domain::pseudo-log.com"

        caplog.set_level(logging.WARNING, logger="services.whitelist_service")
        result = whitelist_service.bulk_delete_entries([pseudo_id])

        assert result["deleted_count"] == 1
        assert "legacy_group_pseudo_id_used" in caplog.text
        assert "operation=bulk_delete" in caplog.text
        assert f"group_id={gid}" in caplog.text

    def test_legacy_group_pseudo_id_usage_is_logged_for_update(
        self, whitelist_service, group_model, caplog
    ):
        group = create_group(group_model, "Pseudo Update Log Group", whitelist=[
            {"value": "pseudo-update-log.com", "type": "domain"},
        ])
        gid = str(group["_id"])
        pseudo_id = f"group::{gid}::domain::pseudo-update-log.com"

        caplog.set_level(logging.WARNING, logger="services.whitelist_service")
        assert whitelist_service.update_entry(pseudo_id, {"is_active": False}) is True

        assert "legacy_group_pseudo_id_used" in caplog.text
        assert "operation=update" in caplog.text
        assert f"group_id={gid}" in caplog.text

    def test_delete_entry_accepts_real_embedded_object_id(self, whitelist_service, group_model):
        group = create_group(group_model, "RealOid Delete Group", whitelist=[
            {"value": "real-oid-delete.com", "type": "domain"},
        ])
        entry_id = str(group["whitelist"][0]["_id"])

        assert whitelist_service.delete_entry(entry_id) is True

        updated_group = group_model.find_by_id(str(group["_id"]))
        values = [
            entry.get("value") if isinstance(entry, dict) else entry
            for entry in updated_group["whitelist"]
        ]
        assert "real-oid-delete.com" not in values

    def test_bulk_add_entries_tolerates_legacy_string_group_whitelist(self, whitelist_service, group_model):
        group = create_group(group_model, "Legacy String Group", whitelist=[])
        group_model.collection.update_one(
            {"_id": group["_id"]},
            {"$set": {"whitelist": ["legacy-string.com"]}},
        )

        result = whitelist_service.bulk_add_entries([
            {
                "value": "legacy-string.com",
                "type": "domain",
                "scope": "group",
                "group_id": str(group["_id"]),
            },
            {
                "value": "fresh-string.com",
                "type": "domain",
                "scope": "group",
                "group_id": str(group["_id"]),
            },
        ], "127.0.0.1")

        assert result["success"] is True
        assert result["inserted_count"] == 1
        updated_group = group_model.find_by_id(str(group["_id"]))
        values = [
            entry.get("value") if isinstance(entry, dict) else entry
            for entry in updated_group["whitelist"]
        ]
        assert values.count("legacy-string.com") == 1
        assert "fresh-string.com" in values

    def test_agent_sync_data_full(self, whitelist_service, group_model, agent_model):
        # Setup: global entry + group with whitelist + agent
        whitelist_service.add_entry({"value": "sync-global.com", "type": "domain"}, "127.0.0.1")
        group = create_group(group_model, "Sync Group", whitelist=[
            {"value": "sync-group.com", "type": "domain"}
        ])
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="SyncPC")

        result = whitelist_service.get_agent_sync_data(agent_id=agent["agent_id"])
        assert result["success"] is True
        assert result["type"] == "full"
        domain_values = [d.get("value") for d in result["domains"]]
        assert "sync-global.com" in domain_values
        assert "sync-group.com" in domain_values

    def test_agent_sync_payload_canonicalizes_legacy_urls(self, whitelist_service, group_model, agent_model):
        whitelist_service.add_entry({
            "value": "https://sync-login.example.com/oauth?x=1",
            "type": "url",
        }, "127.0.0.1")
        group = create_group(group_model, "Legacy URL Sync Group", whitelist=[
            {
                "value": (
                    "https://login.microsoftonline.com/oauth2/v2.0/authorize"
                    "?scope=openid&state=abc"
                ),
                "type": "domain",
            },
            {
                "value": "https://*.microsoftonline.com/oauth?x=1",
                "type": "pattern",
            },
        ])
        agent = insert_agent(agent_model, str(group["_id"]), hostname="UrlSyncPC")

        result = whitelist_service.get_agent_sync_data(agent_id=agent["agent_id"])

        entries = result["domains"]
        by_value = {entry["value"]: entry["type"] for entry in entries}
        assert by_value["sync-login.example.com"] == "domain"
        assert by_value["login.microsoftonline.com"] == "domain"
        assert by_value["*.microsoftonline.com"] == "pattern"
        assert all("://" not in entry["value"] for entry in entries)
        assert all("?" not in entry["value"] for entry in entries)

    def test_agent_sync_active_profile_accepts_domain_key(
        self,
        whitelist_service_with_profiles,
        whitelist_profile_service,
        group_model,
        agent_model,
    ):
        group = create_group(group_model, "Profile Sync Group", whitelist=[
            {"value": "base-profile-sync.com", "type": "domain", "category": "base"}
        ])
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="ProfileSyncPC")

        profile = whitelist_profile_service.create_profile(
            gid,
            ObjectId(),
            "teacher-profile",
            "Lesson Profile",
            domains=[{"domain": "profile-only-sync.com", "category": "lesson"}],
        )
        whitelist_profile_service.activate_profile(profile["_id"])

        result = whitelist_service_with_profiles.get_agent_sync_data(agent_id=agent["agent_id"])

        assert result["success"] is True
        entries = result["domains"]
        values = [entry.get("value") for entry in entries]
        assert "profile-only-sync.com" in values
        assert "base-profile-sync.com" not in values
        profile_entry = next(entry for entry in entries if entry.get("value") == "profile-only-sync.com")
        assert profile_entry["category"] == "lesson"
        assert not str(profile_entry.get("_id")).endswith("::None")

    def test_agent_sync_data_up_to_date(self, whitelist_service, group_model, agent_model):
        group = create_group(group_model, "UpToDate Group")
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="UTD-PC")

        # First call to get versions
        r1 = whitelist_service.get_agent_sync_data(agent_id=agent["agent_id"])
        gv = r1["global_version"]
        grpv = r1["group_version"]

        # Second call with same versions
        r2 = whitelist_service.get_agent_sync_data(
            agent_id=agent["agent_id"], global_version=gv, group_version=grpv
        )
        assert r2.get("up_to_date") is True
        assert len(r2["domains"]) == 0

    def test_agent_sync_no_agent_id_raises(self, whitelist_service):
        result = whitelist_service.get_agent_sync_data(agent_id=None)
        assert result["success"] is False

    def test_group_bulk_add_writes_to_whitelist_entries_first(
        self, whitelist_service_with_entries, whitelist_entry_model, group_model
    ):
        group = create_group(group_model, "Collection First Group", whitelist=[])
        gid = str(group["_id"])

        result = whitelist_service_with_entries.bulk_add_entries([{
            "value": "collection-first.com",
            "type": "domain",
            "scope": "group",
            "group_id": gid,
        }], "127.0.0.1")

        assert result["success"] is True
        entries = whitelist_entry_model.list_group_entries(gid)
        assert len(entries) == 1
        assert entries[0]["value"] == "collection-first.com"
        assert not entries[0]["_id"].startswith("group::")

        updated_group = group_model.find_by_id(gid)
        assert updated_group.get("whitelist") == []

        scoped = whitelist_service_with_entries.get_scoped_whitelist(group_id=gid)
        assert scoped["success"] is True
        assert scoped["group"][0]["value"] == "collection-first.com"
        assert not scoped["group"][0]["_id"].startswith("group::")

    def test_group_collection_read_falls_back_to_embedded_for_unmigrated_group(
        self, whitelist_service_with_entries, group_model
    ):
        group = create_group(group_model, "Embedded Fallback Group", whitelist=[{
            "value": "embedded-fallback.com",
            "type": "domain",
        }])
        gid = str(group["_id"])

        scoped = whitelist_service_with_entries.get_scoped_whitelist(group_id=gid)

        assert scoped["success"] is True
        values = [entry["value"] for entry in scoped["group"]]
        assert "embedded-fallback.com" in values

    def test_group_collection_read_merges_partially_migrated_group(
        self, whitelist_service_with_entries, whitelist_entry_model, group_model
    ):
        group = create_group(group_model, "Partial Migration Group", whitelist=[
            {"value": "embedded-only.com", "type": "domain"},
            {"value": "shared-value.com", "type": "domain", "category": "legacy"},
        ])
        gid = str(group["_id"])
        shared_collection_id = whitelist_entry_model.insert_entry({
            "value": "shared-value.com",
            "type": "domain",
            "category": "collection",
            "scope": "group",
            "group_id": gid,
        })
        whitelist_entry_model.insert_entry({
            "value": "collection-only.com",
            "type": "domain",
            "scope": "group",
            "group_id": gid,
        })

        scoped = whitelist_service_with_entries.get_scoped_whitelist(group_id=gid)

        assert scoped["success"] is True
        values = [entry["value"] for entry in scoped["group"]]
        assert "embedded-only.com" in values
        assert "collection-only.com" in values
        assert values.count("shared-value.com") == 1
        shared = next(entry for entry in scoped["group"] if entry["value"] == "shared-value.com")
        assert shared["_id"] == shared_collection_id
        assert shared["category"] == "collection"

    def test_group_collection_entry_update_and_delete_by_real_id(
        self, whitelist_service_with_entries, whitelist_entry_model, group_model
    ):
        group = create_group(group_model, "Collection Edit Group", whitelist=[])
        gid = str(group["_id"])
        before_version = group["whitelist_version"]

        add_result = whitelist_service_with_entries.add_entry({
            "value": "collection-edit.com",
            "type": "domain",
            "scope": "group",
            "group_id": gid,
        }, "127.0.0.1")
        entry_id = add_result["id"]

        assert whitelist_service_with_entries.update_entry(
            entry_id, {"category": "updated"}
        ) is True
        updated = whitelist_entry_model.find_entry_by_id(entry_id)
        assert updated["category"] == "updated"

        assert whitelist_service_with_entries.delete_entry(entry_id) is True
        assert whitelist_entry_model.find_entry_by_id(entry_id) is None
        updated_group = group_model.find_by_id(gid)
        assert updated_group["whitelist_version"] > before_version


# ============================================================================
# 3. LOG MODEL TESTS
# ============================================================================

class TestLogModel:
    """Test LogModel CRUD, query, statistics."""

    def test_insert_logs(self, log_model):
        logs = [
            {"agent_id": "agent-1", "action": "ALLOWED", "domain": "google.com",
             "level": "INFO", "message": "test log"},
            {"agent_id": "agent-1", "action": "BLOCKED", "domain": "malware.com",
             "level": "WARNING", "message": "blocked"},
        ]
        ids = log_model.insert_logs(logs)
        assert len(ids) == 2

    def test_insert_logs_empty(self, log_model):
        ids = log_model.insert_logs([])
        assert ids == []

    def test_find_all_logs(self, log_model):
        log_model.insert_logs([
            {"agent_id": "agent-2", "action": "ALLOWED", "domain": "test.com"},
        ])
        logs = log_model.find_all_logs()
        assert len(logs) >= 1
        assert isinstance(logs[0]["_id"], str)

    def test_find_all_logs_with_limit(self, log_model):
        log_model.insert_logs([
            {"agent_id": "a", "action": "ALLOWED", "domain": f"d{i}.com"}
            for i in range(10)
        ])
        logs = log_model.find_all_logs(limit=3)
        assert len(logs) == 3

    def test_find_all_logs_with_offset(self, log_model):
        log_model.insert_logs([
            {"agent_id": "a", "action": "ALLOWED", "domain": f"off{i}.com"}
            for i in range(5)
        ])
        all_logs = log_model.find_all_logs(limit=100)
        offset_logs = log_model.find_all_logs(limit=100, offset=2)
        assert len(offset_logs) == len(all_logs) - 2

    def test_count_logs(self, log_model):
        log_model.insert_logs([
            {"agent_id": "cnt", "action": "BLOCKED", "domain": "x.com"},
            {"agent_id": "cnt", "action": "ALLOWED", "domain": "y.com"},
        ])
        total = log_model.count_logs()
        assert total >= 2

    def test_count_logs_with_query(self, log_model):
        log_model.insert_logs([
            {"agent_id": "qcnt", "action": "BLOCKED", "domain": "blocked.com"},
        ])
        count = log_model.count_logs({"agent_id": "qcnt"})
        assert count >= 1

    def test_delete_logs(self, log_model):
        log_model.insert_logs([
            {"agent_id": "del-agent", "action": "ALLOWED", "domain": "d.com"},
        ])
        deleted = log_model.delete_logs({"agent_id": "del-agent"})
        assert deleted >= 1

    def test_delete_logs_all(self, log_model):
        log_model.insert_logs([
            {"agent_id": "x", "action": "ALLOWED", "domain": "all1.com"},
            {"agent_id": "x", "action": "BLOCKED", "domain": "all2.com"},
        ])
        deleted = log_model.delete_logs()
        assert deleted >= 2

    def test_get_total_count(self, log_model):
        log_model.insert_logs([
            {"agent_id": "tc", "action": "ALLOWED", "domain": "tc.com"},
        ])
        total = log_model.get_total_count()
        assert total >= 1

    def test_get_count_by_action(self, log_model):
        log_model.insert_logs([
            {"agent_id": "ba", "action": "BLOCKED", "domain": "ba.com"},
        ])
        count = log_model.get_count_by_action("BLOCKED")
        assert count >= 1

    def test_get_recent_logs(self, log_model):
        log_model.insert_logs([
            {"agent_id": "recent", "action": "ALLOWED", "domain": "recent.com"},
        ])
        recent = log_model.get_recent_logs(limit=5)
        assert len(recent) >= 1
        assert isinstance(recent[0]["_id"], str)

    def test_get_logs_summary(self, log_model):
        log_model.insert_logs([
            {"agent_id": "sum", "action": "ALLOWED", "domain": "sum1.com"},
            {"agent_id": "sum", "action": "BLOCKED", "domain": "sum2.com"},
        ])
        summary = log_model.get_logs_summary()
        assert summary["total_logs"] >= 2
        assert "timezone" in summary

    def test_timestamp_auto_assigned(self, log_model):
        log_model.insert_logs([{"agent_id": "ts", "action": "ALLOWED", "domain": "ts.com"}])
        logs = log_model.find_all_logs({"agent_id": "ts"})
        assert logs[0].get("timestamp") is not None

    def test_server_received_at_set(self, log_model):
        log_model.insert_logs([{"agent_id": "sr", "action": "ALLOWED", "domain": "sr.com"}])
        raw = log_model.collection.find_one({"agent_id": "sr"})
        assert raw.get("server_received_at") is not None


# ============================================================================
# 4. LOG SERVICE TESTS
# ============================================================================

class TestLogService:
    """Test LogService business logic."""

    def test_receive_logs_success(self, log_service):
        data = {"logs": [
            {"action": "ALLOWED", "domain": "google.com", "source_ip": "10.0.0.1"},
            {"action": "BLOCKED", "domain": "evil.com", "port": "443"},
        ]}
        result = log_service.receive_logs(data, agent_id="agent-svc-1")
        assert result["success"] is True
        assert result["processed_count"] == 2

    def test_receive_logs_empty(self, log_service):
        result = log_service.receive_logs({"logs": []})
        assert result["success"] is False
        assert "No logs" in result["error"]

    def test_receive_logs_no_logs_key(self, log_service):
        result = log_service.receive_logs({})
        assert result["success"] is False

    def test_protocol_detection_443(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "domain": "ssl.com", "port": "443"}]}
        log_service.receive_logs(data, agent_id="proto-test")
        logs = log_service.model.find_all_logs({"agent_id": "proto-test"})
        assert logs[0]["protocol"] == "HTTPS"

    def test_protocol_detection_80(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "domain": "http.com", "port": "80"}]}
        log_service.receive_logs(data, agent_id="proto-80")
        logs = log_service.model.find_all_logs({"agent_id": "proto-80"})
        assert logs[0]["protocol"] == "HTTP"

    def test_protocol_detection_53(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "domain": "dns.com", "port": "53"}]}
        log_service.receive_logs(data, agent_id="proto-53")
        logs = log_service.model.find_all_logs({"agent_id": "proto-53"})
        assert logs[0]["protocol"] == "DNS"

    def test_protocol_detection_custom_port(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "domain": "custom.com", "port": "8080"}]}
        log_service.receive_logs(data, agent_id="proto-custom")
        logs = log_service.model.find_all_logs({"agent_id": "proto-custom"})
        assert logs[0]["protocol"] == "TCP/8080"

    def test_action_normalization_allow(self, log_service):
        data = {"logs": [{"action": "ALLOW", "domain": "norm.com"}]}
        log_service.receive_logs(data, agent_id="norm-allow")
        logs = log_service.model.find_all_logs({"agent_id": "norm-allow"})
        assert logs[0]["action"] == "ALLOWED"

    def test_action_normalization_deny(self, log_service):
        data = {"logs": [{"action": "DENY", "domain": "deny.com"}]}
        log_service.receive_logs(data, agent_id="norm-deny")
        logs = log_service.model.find_all_logs({"agent_id": "norm-deny"})
        assert logs[0]["action"] == "BLOCKED"

    def test_get_all_logs_with_filters(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "BLOCKED", "domain": "filter-test.com"},
        ]}, agent_id="filter-agent")
        result = log_service.get_all_logs({"agent_id": "filter-agent"})
        assert result["success"] is True
        assert len(result["logs"]) >= 1

    def test_get_all_logs_time_range(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "ALLOWED", "domain": "time-test.com"},
        ]}, agent_id="time-agent")
        result = log_service.get_all_logs({"time_range": "1h"})
        assert result["success"] is True

    def test_clear_logs(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "ALLOWED", "domain": "clear-test.com"},
        ]}, agent_id="clear-agent")
        result = log_service.clear_logs({"agent_id": "clear-agent"})
        assert result["success"] is True
        assert result["deleted_count"] >= 1

    def test_export_logs_json(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "ALLOWED", "domain": "export.com"},
        ]}, agent_id="export-agent")
        result = log_service.export_logs(format='json')
        assert result["success"] is True
        assert result["format"] == "json"

    def test_export_logs_csv(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "ALLOWED", "domain": "csv.com"},
        ]}, agent_id="csv-agent")
        result = log_service.export_logs(format='csv')
        assert result["success"] is True
        assert result["format"] == "csv"

    def test_comprehensive_statistics(self, log_service):
        log_service.receive_logs({"logs": [
            {"action": "ALLOWED", "domain": "a.com"},
            {"action": "BLOCKED", "domain": "b.com"},
        ]}, agent_id="stats-agent")
        stats = log_service.get_comprehensive_statistics()
        assert stats["success"] is True
        assert stats["total"] >= 2

    def test_source_ip_fallback(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "domain": "srcip.com", "src_ip": "10.1.1.1"}]}
        log_service.receive_logs(data, agent_id="srcip-agent")
        logs = log_service.model.find_all_logs({"agent_id": "srcip-agent"})
        assert logs[0]["source_ip"] == "10.1.1.1"

    def test_destination_fallback(self, log_service):
        data = {"logs": [{"action": "ALLOWED", "dest_ip": "8.8.8.8"}]}
        log_service.receive_logs(data, agent_id="dest-agent")
        logs = log_service.model.find_all_logs({"agent_id": "dest-agent"})
        assert logs[0]["destination"] == "8.8.8.8"


# ============================================================================
# 5. WHITELIST CONTROLLER TESTS
# ============================================================================

class TestWhitelistController:
    """Test WhitelistController HTTP endpoints."""

    @pytest.fixture
    def app(self, whitelist_model, whitelist_service, rbac_service):
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = WhitelistController(whitelist_model, whitelist_service, rbac_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        return app

    def test_list_domains_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/whitelist')
                assert resp.status_code == 200
                data = resp.get_json()
                assert "domains" in data or "success" in data

    def test_add_domain_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', json={
                    "value": f"ctrl-{uuid.uuid4().hex[:8]}.com", "type": "domain"
                })
                assert resp.status_code == 201

    def test_add_domain_no_value(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', json={"value": "", "type": "domain"})
                assert resp.status_code == 400

    def test_add_domain_not_json(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', data="not json")
                assert resp.status_code == 400

    def test_delete_domain_admin(self, app, whitelist_model):
        entry_id = whitelist_model.insert_entry({"value": "ctrl-del.com", "type": "domain"})
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.delete(f'/api/whitelist/{entry_id}')
                assert resp.status_code == 200

    def test_delete_domain_invalid_id(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.delete('/api/whitelist/short')
                assert resp.status_code == 400

    def test_get_statistics(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/whitelist/statistics')
                assert resp.status_code == 200

    def test_bulk_add_entries(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist/bulk', json={
                    "items": [
                        {"value": f"bctrl-{uuid.uuid4().hex[:6]}.com", "type": "domain"},
                        {"value": f"bctrl-{uuid.uuid4().hex[:6]}.com", "type": "domain"},
                    ]
                })
                assert resp.status_code == 200

    def test_bulk_add_no_items(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist/bulk', json={})
                assert resp.status_code == 400

    def test_bulk_delete_entries(self, app, whitelist_model):
        eid = whitelist_model.insert_entry({"value": "bkdel.com", "type": "domain"})
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.post('/api/whitelist/bulk-delete', json={"item_ids": [eid]})
                assert resp.status_code == 200


# ============================================================================
# 6. LOG CONTROLLER TESTS
# ============================================================================

class TestLogController:
    """Test LogController HTTP endpoints."""

    @pytest.fixture
    def app(self, log_model, log_service, rbac_service):
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = LogController(log_model, log_service, rbac_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        return app

    def test_web_routes_require_login(self, app):
        """Unauthenticated web-facing log routes must not expose data."""
        cases = [
            ("get", "/api/logs"),
            ("get", "/api/logs/stats"),
            ("delete", "/api/logs/clear"),
            ("delete", "/api/logs"),
            ("get", "/api/logs/export?format=json"),
        ]

        with app.test_client() as client:
            for method_name, path in cases:
                resp = getattr(client, method_name)(path)

                assert resp.status_code == 401, path
                assert resp.get_json()["error"] == "Authentication required"

    def test_receive_logs_via_jwt(self, agent_model, group_model):
        """Agent sends logs via POST with JWT - no RBAC check."""
        from flask import Flask
        import controllers.log_controller as lc_mod

        group = create_group(group_model, "Log Agent Group")
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="LogPC", agent_id="log-agent-1")

        # Patch require_jwt at the controller module level BEFORE constructing
        orig = lc_mod.require_jwt
        lc_mod.require_jwt = lambda f: f
        try:
            test_app = Flask(__name__)
            test_app.config['TESTING'] = True
            _log_model = LogModel(agent_model.db)
            _log_service = LogService(_log_model, agent_model=agent_model, socketio=None)
            rbac_svc = RBACService(group_model=group_model, agent_model=agent_model)
            ctrl = LogController(_log_model, _log_service, rbac_svc)
            test_app.register_blueprint(ctrl.blueprint, url_prefix='/api')

            with test_app.test_client() as client:
                resp = client.post('/api/logs', json={
                    "logs": [
                        {"action": "ALLOWED", "domain": "google.com", "port": "443"},
                        {"action": "BLOCKED", "domain": "malware.com", "port": "80"},
                    ]
                }, headers={"X-Agent-ID": "log-agent-1"})
                assert resp.status_code == 201
                data = resp.get_json()
                assert data["success"] is True
                assert data["processed_count"] == 2
        finally:
            lc_mod.require_jwt = orig

    def test_list_logs_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200

    def test_list_logs_with_filters(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs?action=BLOCKED&time_range=24h')
                assert resp.status_code == 200

    def test_get_statistics(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs/stats')
                assert resp.status_code == 200

    def test_clear_logs_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.delete('/api/logs/clear')
                assert resp.status_code == 200

    def test_export_logs_admin(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs/export?format=json')
                assert resp.status_code == 200


# ============================================================================
# 7. RBAC - TEACHER WHITELIST ISOLATION
# ============================================================================

class TestRBACWhitelistTeacher:
    """Teacher cannot add/delete global whitelist, can only access own groups."""

    @pytest.fixture
    def app(self, whitelist_model, whitelist_service, rbac_service, group_model):
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = WhitelistController(whitelist_model, whitelist_service, rbac_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        return app

    def test_teacher_cannot_add_global(self, app):
        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', json={
                    "value": "teacher-global.com", "type": "domain"
                })
                assert resp.status_code == 403

    def test_teacher_cannot_add_to_other_group(self, app, group_model):
        other_teacher = make_teacher()
        group = create_group(group_model, "Other Teacher Group", created_by=other_teacher["_id"])
        gid = str(group["_id"])

        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', json={
                    "value": "steal.com", "type": "domain",
                    "scope": "group", "group_id": gid,
                })
                assert resp.status_code == 403

    def test_teacher_can_add_to_own_group(self, app, group_model):
        teacher = make_teacher()
        group = create_group(group_model, "My Teacher Group", created_by=teacher["_id"])
        gid = str(group["_id"])

        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.post('/api/whitelist', json={
                    "value": f"own-{uuid.uuid4().hex[:6]}.com", "type": "domain",
                    "scope": "group", "group_id": gid,
                })
                # Should succeed (201) or at least not 403
                assert resp.status_code != 403

    def test_teacher_cannot_delete_global(self, app, whitelist_model):
        entry_id = whitelist_model.insert_entry({"value": "nodelete.com", "type": "domain", "scope": "global"})
        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.delete(f'/api/whitelist/{entry_id}')
                assert resp.status_code == 403

    def test_teacher_cannot_delete_other_group_entry(self, app, whitelist_model, group_model):
        other_teacher = make_teacher()
        group = create_group(group_model, "Other Del Group", created_by=other_teacher["_id"])
        gid = str(group["_id"])
        entry_id = whitelist_model.insert_entry({
            "value": "other-grp.com", "type": "domain",
            "scope": "group", "group_id": gid,
        })

        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.delete(f'/api/whitelist/{entry_id}')
                assert resp.status_code == 403

    def test_teacher_bulk_add_blocked_for_other_group(self, app, group_model):
        other_teacher = make_teacher()
        group = create_group(group_model, "Bulk Other Group", created_by=other_teacher["_id"])
        gid = str(group["_id"])

        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.post('/api/whitelist/bulk', json={
                    "items": [{"value": "bulk-steal.com", "type": "domain", "group_id": gid}]
                })
                assert resp.status_code == 403


# ============================================================================
# 8. RBAC - TEACHER LOG ISOLATION
# ============================================================================

class TestRBACLogTeacher:
    """Teacher cannot delete/export logs. Can only see logs from own agents."""

    @pytest.fixture
    def app(self, log_model, log_service, rbac_service):
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = LogController(log_model, log_service, rbac_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        return app

    def test_teacher_cannot_clear_logs(self, app):
        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.delete('/api/logs/clear')
                assert resp.status_code == 403
                data = resp.get_json()
                assert "Insufficient permissions to delete logs" in data.get("error", "")

    def test_teacher_cannot_export_logs(self, app):
        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs/export')
                assert resp.status_code == 403

    def test_teacher_can_list_logs(self, app):
        teacher = make_teacher()
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200

    def test_teacher_log_filter_applied(self, app, log_model, group_model, agent_model):
        """Teacher only sees logs from agents in their groups."""
        teacher = make_teacher()
        group = create_group(group_model, "Teacher Log Group", created_by=teacher["_id"])
        gid = str(group["_id"])
        agent = insert_agent(agent_model, gid, hostname="TeacherPC", agent_id="teacher-log-agent")

        # Insert logs for teacher's agent
        log_model.insert_logs([
            {"agent_id": "teacher-log-agent", "action": "ALLOWED", "domain": "teacher.com"},
        ])
        # Insert logs for OTHER agent
        log_model.insert_logs([
            {"agent_id": "other-agent", "action": "BLOCKED", "domain": "other.com"},
        ])

        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200
                data = resp.get_json()
                logs = data.get("logs", [])
                agent_ids = [l.get("agent_id") for l in logs]
                # Teacher should NOT see other-agent logs
                assert "other-agent" not in agent_ids

    def test_admin_sees_all_logs(self, app, log_model):
        admin = make_admin()
        log_model.insert_logs([
            {"agent_id": "admin-see-1", "action": "ALLOWED", "domain": "all1.com"},
            {"agent_id": "admin-see-2", "action": "BLOCKED", "domain": "all2.com"},
        ])
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "admin-see-1" in agent_ids
                assert "admin-see-2" in agent_ids

    def test_admin_can_clear_logs(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.delete('/api/logs/clear')
                assert resp.status_code == 200

    def test_admin_can_export_logs(self, app):
        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs/export')
                assert resp.status_code == 200


# ============================================================================
# 9. PENDING GROUP - Agent logs invisible to all teachers
# ============================================================================

class TestPendingGroupIsolation:
    """Agent in Pending group: logs invisible to teachers, visible to admin."""

    @pytest.fixture
    def app(self, log_model, log_service, rbac_service):
        from flask import Flask
        app = Flask(__name__)
        app.config['TESTING'] = True
        controller = LogController(log_model, log_service, rbac_service)
        app.register_blueprint(controller.blueprint, url_prefix='/api')
        return app

    def test_pending_agent_logs_invisible_to_teacher(self, app, log_model, group_model, agent_model):
        """Teacher cannot see logs from agent in Pending (system) group."""
        # Ensure pending group exists
        pending = group_model.ensure_pending_group()
        pending_gid = str(pending["_id"])

        # Agent registered into Pending group
        agent = insert_agent(agent_model, pending_gid, hostname="PendingPC", agent_id="pending-agent-1")

        # Logs from pending agent
        log_model.insert_logs([
            {"agent_id": "pending-agent-1", "action": "ALLOWED", "domain": "pending-test.com"},
        ])

        # Teacher with their own group (NOT pending)
        teacher = make_teacher()
        create_group(group_model, "Teacher Own Group", created_by=teacher["_id"])

        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "pending-agent-1" not in agent_ids

    def test_pending_agent_logs_invisible_to_any_teacher(self, app, log_model, group_model, agent_model):
        """Even a teacher with no groups cannot see pending agent logs."""
        pending = group_model.ensure_pending_group()
        pending_gid = str(pending["_id"])

        insert_agent(agent_model, pending_gid, hostname="PendPC2", agent_id="pending-agent-2")
        log_model.insert_logs([
            {"agent_id": "pending-agent-2", "action": "BLOCKED", "domain": "hidden.com"},
        ])

        # Teacher with ZERO groups
        lonely_teacher = make_teacher()

        with _mock_auth(lonely_teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "pending-agent-2" not in agent_ids

    def test_pending_agent_logs_visible_to_admin(self, app, log_model, group_model, agent_model):
        """Admin CAN see logs from agents in Pending group."""
        pending = group_model.ensure_pending_group()
        pending_gid = str(pending["_id"])

        insert_agent(agent_model, pending_gid, hostname="PendPC3", agent_id="pending-agent-3")
        log_model.insert_logs([
            {"agent_id": "pending-agent-3", "action": "ALLOWED", "domain": "admin-sees.com"},
        ])

        admin = make_admin()
        with _mock_auth(admin):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                assert resp.status_code == 200
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "pending-agent-3" in agent_ids

    def test_pending_agent_moves_to_teacher_group_logs_become_visible(
        self, app, log_model, group_model, agent_model
    ):
        """After moving agent from Pending to teacher's group, logs become visible."""
        pending = group_model.ensure_pending_group()
        pending_gid = str(pending["_id"])

        # Agent starts in Pending
        insert_agent(agent_model, pending_gid, hostname="MovePC", agent_id="move-agent-1")
        log_model.insert_logs([
            {"agent_id": "move-agent-1", "action": "ALLOWED", "domain": "moved.com"},
        ])

        teacher = make_teacher()
        teacher_group = create_group(group_model, "Teacher Adopt Group", created_by=teacher["_id"])
        teacher_gid = str(teacher_group["_id"])

        # Before move - teacher cannot see
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "move-agent-1" not in agent_ids

        # Move agent to teacher's group
        agent_model.update_agent("move-agent-1", {"group_id": teacher_gid})

        # After move - teacher CAN see
        with _mock_auth(teacher):
            with app.test_client() as client:
                resp = client.get('/api/logs')
                data = resp.get_json()
                agent_ids = [l.get("agent_id") for l in data.get("logs", [])]
                assert "move-agent-1" in agent_ids
