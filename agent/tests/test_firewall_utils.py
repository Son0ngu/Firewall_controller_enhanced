import os
import sys


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from firewall.utils import FirewallUtils


def test_get_essential_ips_does_not_add_public_dns_fallback(monkeypatch):
    import dns.resolver

    class BrokenResolver:
        def __init__(self):
            raise RuntimeError("dns config unavailable")

    monkeypatch.setattr(dns.resolver, "Resolver", BrokenResolver)
    monkeypatch.setattr("firewall.utils.get_local_ip", lambda: None)

    essential = FirewallUtils.get_essential_ips()

    assert "127.0.0.1" in essential
    assert "8.8.8.8" not in essential
    assert "8.8.4.4" not in essential
    assert "1.1.1.1" not in essential


def test_get_essential_ips_uses_detected_system_dns_only(monkeypatch):
    import dns.resolver

    class FakeResolver:
        nameservers = ["192.168.1.1", "8.8.8.8", "not-an-ip", "2001:db8::1"]

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    monkeypatch.setattr("firewall.utils.get_local_ip", lambda: None)

    essential = FirewallUtils.get_essential_ips()

    assert "192.168.1.1" in essential
    assert "8.8.8.8" in essential
    assert "not-an-ip" not in essential
    assert "2001:db8::1" not in essential
