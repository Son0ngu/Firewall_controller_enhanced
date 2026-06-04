import os
import sys
import types

import pytest


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.agent import make_runtime
from core.lifecycle import (
    AgentComponent,
    InitResult,
    LifecycleContext,
    STATUS_DEGRADED,
    STATUS_FAILED,
    STATUS_OK,
    STATUS_SKIPPED,
    _init_firewall,
    _init_packet_sniffer,
    start_components,
    stop_components,
)


class FakeComponent(AgentComponent):
    def __init__(self, name, events, *, fail_on_start=False, reported_status=STATUS_OK):
        self.name = name
        self.events = events
        self.fail_on_start = fail_on_start
        self.reported_status = reported_status

    def start(self, context):
        self.events.append(f"start:{self.name}")
        if self.fail_on_start:
            raise RuntimeError(f"{self.name} failed")
        context.result.record(self.name, self.reported_status)

    def stop(self, context):
        self.events.append(f"stop:{self.name}")

    def health(self, context):
        return {"name": self.name, "status": self.reported_status}


def make_context():
    return LifecycleContext(runtime=make_runtime(), config={}, result=InitResult())


def test_start_components_preserves_order_and_stop_reverses_order():
    events = []
    context = make_context()
    components = [
        FakeComponent("registration", events),
        FakeComponent("token", events),
        FakeComponent("whitelist", events),
    ]

    start_components(context, components)
    assert events == ["start:registration", "start:token", "start:whitelist"]
    assert context.runtime.components == components

    stop_components(context)
    assert events == [
        "start:registration",
        "start:token",
        "start:whitelist",
        "stop:whitelist",
        "stop:token",
        "stop:registration",
    ]
    assert context.runtime.components == []


def test_start_exception_cleans_up_started_and_starting_components():
    events = []
    context = make_context()
    components = [
        FakeComponent("registration", events),
        FakeComponent("token", events, fail_on_start=True),
        FakeComponent("whitelist", events),
    ]

    with pytest.raises(RuntimeError, match="token failed"):
        start_components(context, components)

    assert events == [
        "start:registration",
        "start:token",
        "stop:token",
        "stop:registration",
    ]
    assert context.runtime.components == []
    failed = [c for c in context.result.components if c.status == STATUS_FAILED]
    assert failed
    assert failed[-1].name == "token"


def test_reported_failed_status_cleans_up_including_reporting_component():
    events = []
    context = make_context()
    components = [
        FakeComponent("registration", events),
        FakeComponent("firewall", events, reported_status=STATUS_FAILED),
        FakeComponent("log_sender", events),
    ]

    with pytest.raises(RuntimeError, match="firewall"):
        start_components(context, components)

    assert events == [
        "start:registration",
        "start:firewall",
        "stop:firewall",
        "stop:registration",
    ]
    assert context.runtime.components == []


def test_firewall_skips_when_whitelist_sync_did_not_succeed(monkeypatch):
    context = make_context()
    context.config = {
        "firewall": {
            "enabled": True,
            "rule_prefix": "FirewallController",
        }
    }
    context.result.record("whitelist_sync", STATUS_DEGRADED, "sync failed")

    constructed = []

    class FakeFirewallManager:
        def __init__(self, *args, **kwargs):
            constructed.append((args, kwargs))

    monkeypatch.setitem(
        sys.modules,
        "firewall",
        types.SimpleNamespace(FirewallManager=FakeFirewallManager),
    )
    monkeypatch.setattr(
        "core.lifecycle.check_admin_privileges",
        lambda: True,
    )

    _init_firewall(context.runtime, context.config, context.result)

    assert constructed == []
    assert context.runtime.firewall is None
    firewall_status = context.result.components[-1]
    assert firewall_status.name == "firewall"
    assert firewall_status.status == STATUS_SKIPPED
    assert "waiting for successful whitelist sync" in firewall_status.detail


def test_packet_sniffer_skips_when_pcap_driver_missing(monkeypatch):
    context = make_context()
    context.config = {"capture": {"enabled": True}}

    monkeypatch.setattr("capture.scapy_config.ensure_pcap_driver", lambda: False)

    _init_packet_sniffer(context.runtime, context.config, context.result)

    packet_status = context.result.components[-1]
    assert packet_status.name == "packet_sniffer"
    assert packet_status.status == STATUS_SKIPPED
    assert "Npcap/WinPcap" in packet_status.detail
    assert context.runtime.sniffer is None
