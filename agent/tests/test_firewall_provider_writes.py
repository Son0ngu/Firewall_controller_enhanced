import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from firewall.application_service import FirewallApplicationService
from firewall.manager import FirewallManager
from firewall.policy import PolicyManager
from firewall.provider import FirewallProvider
from firewall.rules import RulesManager


class FakeFirewallProvider(FirewallProvider):
    name = "fake"

    def __init__(self):
        self.created = []
        self.deleted = []
        self.deleted_prefixes = []
        self.policies = []
        self.rules = []

    @classmethod
    def available(cls):
        return True

    def list_rules(
        self,
        *,
        rule_prefix=None,
        direction=None,
        action=None,
        enabled_only=True,
    ):
        return [
            rule for rule in self.rules
            if (not rule_prefix or rule.get("rule_name", "").startswith(rule_prefix))
            and (not direction or rule.get("direction") == direction)
            and (not action or rule.get("action") == action)
            and (not enabled_only or rule.get("enabled", True))
        ]

    def get_policy_status(self):
        return {"outbound_default_block": False, "profile_name": "Private"}

    def create_or_replace_rule(
        self,
        rule_name,
        *,
        direction="out",
        action="allow",
        protocol="any",
        remote_addresses=None,
        remote_ports=None,
        program=None,
        profile="any",
        description=None,
    ):
        self.created.append({
            "rule_name": rule_name,
            "direction": direction,
            "action": action,
            "protocol": protocol,
            "remote_addresses": list(remote_addresses or []),
            "remote_ports": list(remote_ports or []),
            "program": program,
            "profile": profile,
            "description": description,
        })
        return True

    def update_rule_remote_addresses(self, rule_name, remote_addresses):
        return True

    def delete_rule(self, rule_name):
        self.deleted.append(rule_name)
        return True

    def delete_rules_by_prefix(self, rule_prefix):
        self.deleted_prefixes.append(rule_prefix)
        return 2

    def set_profile_outbound_policy(self, profile, action):
        self.policies.append((profile, action))
        return True


class FakeManager:
    def __init__(self):
        self.restored = []
        self.cleared = 0

    def restore_snapshot(self, path):
        self.restored.append(path)
        return True

    def clear_all_rules(self):
        self.cleared += 1
        return True


class RecordingRules:
    def __init__(self, events, *, self_allow_ok=True, batch_ok=True):
        self.events = events
        self.self_allow_ok = self_allow_ok
        self.batch_ok = batch_ok

    def create_self_allow_rules(self, program_path):
        self.events.append(("self_allow", bool(program_path)))
        return self.self_allow_ok

    def create_allow_rules_batch(self, ips):
        self.events.append(("allow_batch", frozenset(ips)))
        return self.batch_ok


class RecordingPolicy:
    def __init__(self, events):
        self.events = events
        self.default_deny_enabled = False

    def enable_default_deny(self):
        self.events.append(("default_deny", None))
        self.default_deny_enabled = True
        return True


class SyncRecordingRules:
    def __init__(self):
        self.allowed_ips = {"10.0.0.8", "127.0.0.1", "192.0.2.10"}
        self.added_ips = []
        self.removed_ips = []

    def create_allow_rule(self, ip):
        self.added_ips.append(ip)
        self.allowed_ips.add(ip)
        return True

    def remove_allow_rule(self, ip):
        self.removed_ips.append(ip)
        self.allowed_ips.discard(ip)
        return True


def make_firewall_manager_for_setup(events, *, self_allow_ok=True, batch_ok=True):
    manager = FirewallManager.__new__(FirewallManager)
    manager.rules_manager = RecordingRules(
        events,
        self_allow_ok=self_allow_ok,
        batch_ok=batch_ok,
    )
    manager.policy_manager = RecordingPolicy(events)
    manager.essential_ips = set()
    manager.server_ips = set()
    manager.whitelist_mode_active = False
    return manager


def test_rules_manager_delegates_writes_to_write_provider():
    read_provider = FakeFirewallProvider()
    write_provider = FakeFirewallProvider()
    manager = RulesManager(
        "SAINT",
        provider=read_provider,
        write_provider=write_provider,
    )

    assert manager.create_allow_rule("8.8.8.8") is True
    assert manager.allowed_ips == {"8.8.8.8"}
    assert write_provider.created[0]["rule_name"].startswith("SAINT_Allow_8_8_8_8_")
    assert write_provider.created[0]["remote_addresses"] == ["8.8.8.8"]

    read_provider.rules = [{
        "rule_name": write_provider.created[0]["rule_name"],
        "direction": "out",
        "action": "allow",
        "enabled": True,
        "remote_addresses": ["8.8.8.8"],
    }]
    assert manager.remove_allow_rule("8.8.8.8") is True
    assert write_provider.deleted == [write_provider.created[0]["rule_name"]]
    assert manager.allowed_ips == set()

    assert manager.clear_all_rules() is True
    assert write_provider.deleted_prefixes == ["SAINT"]


def test_rules_manager_batch_requires_every_rule_to_succeed():
    class FailingProvider(FakeFirewallProvider):
        def create_or_replace_rule(self, rule_name, **kwargs):
            super().create_or_replace_rule(rule_name, **kwargs)
            return kwargs.get("remote_addresses") != ["8.8.4.4"]

    provider = FailingProvider()
    manager = RulesManager("SAINT", provider=provider, write_provider=provider)

    assert manager.create_allow_rules_batch({"8.8.8.8", "8.8.4.4"}) is False
    assert manager.allowed_ips == {"8.8.8.8"}


def test_rules_manager_removes_recent_rule_when_read_provider_is_empty():
    read_provider = FakeFirewallProvider()
    write_provider = FakeFirewallProvider()
    manager = RulesManager(
        "SAINT",
        provider=read_provider,
        write_provider=write_provider,
    )

    assert manager.create_allow_rule("8.8.4.4") is True
    created_rule_name = write_provider.created[0]["rule_name"]
    read_provider.rules = []

    assert manager.remove_allow_rule("8.8.4.4") is True
    assert write_provider.deleted == [created_rule_name]
    assert manager.allowed_ips == set()
    assert manager.allowed_rule_names == {}


def test_policy_manager_delegates_profile_writes_to_provider():
    provider = FakeFirewallProvider()
    manager = PolicyManager(write_provider=provider)

    assert manager.restore_policies({"domain": "allow", "public": "block"}) is True

    assert provider.policies == [("domain", "allow"), ("public", "block")]


def test_policy_manager_parses_firewall_policy_line(monkeypatch):
    class Result:
        returncode = 0
        stderr = ""
        stdout = """
Domain Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,BlockOutbound

Public Profile Settings:
----------------------------------------------------------------------
Firewall Policy                       BlockInbound,AllowOutbound
"""

    monkeypatch.setattr(
        "firewall.policy.FirewallUtils.run_netsh_command",
        lambda args: Result(),
    )

    manager = PolicyManager(write_provider=FakeFirewallProvider())

    assert manager.get_current_policy() == {
        "domain": "allow",
        "private": "block",
        "public": "allow",
    }


def test_setup_whitelist_firewall_creates_allow_rules_before_default_deny():
    events = []
    manager = make_firewall_manager_for_setup(events)

    assert manager.setup_whitelist_firewall(
        {"10.0.0.8"},
        essential_ips={"127.0.0.1"},
    ) is True

    assert events == [
        ("self_allow", True),
        ("allow_batch", frozenset({"10.0.0.8", "127.0.0.1"})),
        ("default_deny", None),
    ]
    assert manager.whitelist_mode_active is True
    assert manager.essential_ips == {"127.0.0.1"}


def test_setup_whitelist_firewall_does_not_enable_default_deny_if_allow_batch_fails():
    events = []
    manager = make_firewall_manager_for_setup(events, batch_ok=False)

    assert manager.setup_whitelist_firewall(
        {"10.0.0.8"},
        essential_ips={"127.0.0.1"},
    ) is False

    assert events == [
        ("self_allow", True),
        ("allow_batch", frozenset({"10.0.0.8", "127.0.0.1"})),
    ]
    assert manager.whitelist_mode_active is False
    assert manager.policy_manager.default_deny_enabled is False


def test_setup_whitelist_firewall_does_not_enable_default_deny_if_self_allow_fails():
    events = []
    manager = make_firewall_manager_for_setup(events, self_allow_ok=False)

    assert manager.setup_whitelist_firewall(
        {"10.0.0.8"},
        essential_ips={"127.0.0.1"},
    ) is False

    assert events == [("self_allow", True)]
    assert manager.whitelist_mode_active is False
    assert manager.policy_manager.default_deny_enabled is False


def test_enable_whitelist_mode_creates_allow_rules_before_default_deny(monkeypatch):
    events = []
    manager = make_firewall_manager_for_setup(events)
    monkeypatch.setattr(
        "firewall.manager.FirewallUtils.get_essential_ips",
        lambda: {"127.0.0.1"},
    )

    assert manager.enable_whitelist_mode(
        whitelist_ips={"10.0.0.8"},
    ) is True

    assert events == [
        ("self_allow", True),
        ("allow_batch", frozenset({"10.0.0.8", "127.0.0.1"})),
        ("default_deny", None),
    ]


def test_enable_whitelist_mode_does_not_enable_default_deny_if_allow_batch_fails(monkeypatch):
    events = []
    manager = make_firewall_manager_for_setup(events, batch_ok=False)
    monkeypatch.setattr(
        "firewall.manager.FirewallUtils.get_essential_ips",
        lambda: {"127.0.0.1"},
    )

    assert manager.enable_whitelist_mode(
        whitelist_ips={"10.0.0.8"},
    ) is False

    assert events == [
        ("self_allow", True),
        ("allow_batch", frozenset({"10.0.0.8", "127.0.0.1"})),
    ]
    assert manager.policy_manager.default_deny_enabled is False


def test_sync_whitelist_changes_keeps_essential_and_server_ips():
    events = []
    manager = FirewallManager.__new__(FirewallManager)
    manager.rules_manager = SyncRecordingRules()
    manager.policy_manager = RecordingPolicy(events)
    manager.essential_ips = {"127.0.0.1"}
    manager.server_ips = {"192.0.2.10"}
    manager.whitelist_mode_active = True

    assert manager.sync_whitelist_changes(
        {"10.0.0.8", "127.0.0.1", "192.0.2.10"},
        {"10.0.0.9"},
    ) is True

    assert manager.rules_manager.added_ips == ["10.0.0.9"]
    assert manager.rules_manager.removed_ips == ["10.0.0.8"]


def test_firewall_application_service_uses_running_manager_when_supplied():
    manager = FakeManager()
    service = FirewallApplicationService(rule_prefix="SAINT", manager=manager)

    assert service.restore_firewall_snapshot("profiles/test.json") is True
    assert service.clear_saint_rules() is True

    assert manager.restored == ["profiles/test.json"]
    assert manager.cleared == 1
