import os
import sys
from types import SimpleNamespace


AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from whitelist.manager import WhitelistManager
from whitelist.state import WhitelistState


def test_oauth_url_query_is_domain_not_question_mark_pattern():
    state = WhitelistState()

    state.update({
        "domains": [{
            "type": "domain",
            "value": (
                "https://login.microsoftonline.com/oauth2/v2.0/authorize"
                "?scope=openid&state=abc"
            ),
        }]
    })

    assert state.get_all_domains() == {"login.microsoftonline.com"}
    assert state.get_all_patterns() == set()
    assert state.is_domain_allowed("login.microsoftonline.com")


def test_url_without_query_matches_hostname():
    state = WhitelistState()

    state.update({
        "domains": [{
            "type": "domain",
            "value": "https://login.microsoftonline.com",
        }]
    })

    assert state.get_all_domains() == {"login.microsoftonline.com"}
    assert state.is_domain_allowed("login.microsoftonline.com")


def test_explicit_pattern_url_without_wildcard_becomes_exact_domain():
    state = WhitelistState()

    state.update({
        "domains": [{
            "type": "pattern",
            "value": "https://login.microsoftonline.com/oauth2/v2.0/authorize?x=1",
        }]
    })

    assert state.get_all_domains() == {"login.microsoftonline.com"}
    assert state.get_all_patterns() == set()
    assert state.is_domain_allowed("login.microsoftonline.com")


def test_wildcard_url_pattern_normalizes_to_hostname_pattern():
    state = WhitelistState()

    state.update({
        "domains": [{
            "type": "pattern",
            "value": "https://*.microsoftonline.com/oauth2/v2.0/authorize?x=1",
        }]
    })

    assert state.get_all_domains() == set()
    assert state.get_all_patterns() == {"*.microsoftonline.com"}
    assert state.is_domain_allowed("login.microsoftonline.com")


def test_dns_resolver_receives_only_exact_clean_hostnames():
    seen = {}

    class FakeResolver:
        def resolve_multiple_parallel(self, domains):
            seen["domains"] = list(domains)
            return {
                domain: SimpleNamespace(ipv4=("203.0.113.10",))
                for domain in domains
            }

        def shutdown(self):
            pass

    class FakeFirewall:
        def __init__(self):
            self.calls = []

        def update_whitelist(self, domains, ips):
            self.calls.append((set(domains), set(ips)))
            return True

    manager = WhitelistManager({
        "server": {"url": "https://controller.example/api-keys?"},
        "whitelist": {},
    })
    try:
        manager.resolver = FakeResolver()
        firewall = FakeFirewall()
        manager.set_firewall_manager(firewall)
        manager._state.update({
            "domains": [
                {
                    "type": "domain",
                    "value": (
                        "https://login.microsoftonline.com/oauth2/v2.0/"
                        "authorize?scope=openid&state=abc"
                    ),
                },
                {
                    "type": "pattern",
                    "value": "https://*.microsoftonline.com/oauth?x=1",
                },
                {
                    "type": "url",
                    "value": "https://example.com/path?x=1",
                },
            ],
        })

        manager._update_firewall_rules()

        assert seen["domains"]
        for domain in seen["domains"]:
            assert "://" not in domain
            assert "/" not in domain
            assert "?" not in domain
            assert "*" not in domain
        assert "login.microsoftonline.com" in seen["domains"]
        assert "example.com" in seen["domains"]
        assert "*.microsoftonline.com" not in seen["domains"]
        assert firewall.calls[-1][0] == set()
    finally:
        manager.cleanup()
