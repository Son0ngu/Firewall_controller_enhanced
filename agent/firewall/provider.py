"""Firewall provider abstraction.

Goal: replace ad-hoc parsing of ``netsh advfirewall ... show rule`` text output
(``Rule Name:``, ``Direction:``, ``Action:``, ``RemoteIP:``) with a structured
interface so callers don't depend on Windows-English text layout.

Two concrete implementations live alongside this module:

- :class:`NetshFirewallProvider` (``netsh_provider.py``) — wraps the existing
  text-parsing code path. Default for now because every existing call site
  already exercises it; new callers should still go through this interface so
  the parsing pain is isolated.
- :class:`NetSecurityFirewallProvider` (``netsecurity_provider.py``) — uses
  PowerShell ``Get-NetFirewallRule`` + ``Get-NetFirewallAddressFilter`` with
  ``ConvertTo-Json`` output. Robust to non-English Windows locales (which
  break ``Rule Name:`` parsing) and to format changes in ``netsh`` output.

Picking a provider:

- The factory :func:`get_default_provider` returns the NetSecurity provider
  when PowerShell + the ``NetSecurity`` module are available, otherwise falls
  back to netsh. Callers can override via the ``SAINT_FIREWALL_PROVIDER``
  env var (``netsh`` | ``netsecurity``) — useful for tests/staging.

Why GUI code goes through here too:

  ``agent/gui_qt/views/firewall.py`` and ``settings.py`` historically called
  netsh and parsed the same text directly. That meant a parser fix had to land
  in three places. With this interface they now ask a provider for structured
  ``FirewallRule`` dicts and let the provider worry about backends.
"""

from __future__ import annotations

import logging
import os
from abc import ABC, abstractmethod
from typing import Iterable, List, Optional, Set, TypedDict

logger = logging.getLogger("firewall.provider")


class FirewallRule(TypedDict, total=False):
    """Structured representation of a single firewall rule.

    Only fields we actually consume across SAINT are typed. Providers may
    populate additional keys; consumers should treat unknown keys as opaque.
    """

    rule_name: str          # e.g. "FirewallController_Allow_203.0.113.10"
    direction: str          # "in" | "out"
    action: str             # "allow" | "block"
    enabled: bool
    protocol: str           # "tcp" | "udp" | "any"
    profile: str            # "Domain,Private,Public" | "Any"
    program: Optional[str]  # path to exe, if scoped
    remote_addresses: List[str]  # parsed RemoteIP list (IPv4 only at SAINT)
    remote_ports: List[str]      # e.g. ["443", "53"]


class FirewallPolicyStatus(TypedDict, total=False):
    """Outbound default-policy summary used by the dashboard."""

    outbound_default_block: bool
    profile_name: str  # "Domain", "Private", "Public"


class FirewallProvider(ABC):
    """Backend-agnostic facade for firewall read/write operations.

    Reads isolate the old English-only ``netsh`` text parsing. Writes preserve
    the existing netsh behavior by default, while allowing an opt-in
    NetSecurity backend for Windows-admin smoke testing.
    """

    name: str = "abstract"

    # ------------------------------------------------------------------
    # Capability negotiation
    # ------------------------------------------------------------------

    @classmethod
    @abstractmethod
    def available(cls) -> bool:
        """Return True if this provider can run on the current host.

        ``NetSecurityFirewallProvider`` returns False on Windows without
        PowerShell or the NetSecurity module. The default factory uses this
        for graceful fallback.
        """

    # ------------------------------------------------------------------
    # Read APIs
    # ------------------------------------------------------------------

    @abstractmethod
    def list_rules(
        self,
        *,
        rule_prefix: Optional[str] = None,
        direction: Optional[str] = None,
        action: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[FirewallRule]:
        """Return rules matching the filters.

        ``rule_prefix`` is the SAINT convention (``FirewallController_*``);
        providers should treat it as a name prefix, not a regex. ``direction``
        / ``action`` accept ``"in"`` / ``"out"`` / ``"allow"`` / ``"block"``.
        """

    def count_rules(self, *, rule_prefix: Optional[str] = None) -> int:
        """Default impl: count via list_rules; providers can override for speed."""
        return len(self.list_rules(rule_prefix=rule_prefix, enabled_only=False))

    def list_outbound_allow_ips(self, *, rule_prefix: str) -> Set[str]:
        """Return the union of RemoteIP values across enabled OUT/allow rules.

        This is the primary use case that drove the original netsh text
        parsing in ``RulesManager._load_existing_rules``: when the agent
        boots, re-hydrate its in-memory ``allowed_ips`` set from the OS so
        we don't drop rules created during the previous session.
        """
        ips: Set[str] = set()
        for rule in self.list_rules(
            rule_prefix=rule_prefix, direction="out", action="allow",
            enabled_only=True,
        ):
            for raw in rule.get("remote_addresses") or []:
                raw = (raw or "").strip()
                if not raw or raw.lower() == "any":
                    continue
                ips.add(raw)
        return ips

    @abstractmethod
    def get_policy_status(self) -> FirewallPolicyStatus:
        """Return the outbound default policy for the active profile.

        Used by the dashboard to show "Default Deny (Active)" vs
        "Default Allow". Implementations should pick the *active* profile
        (Domain / Private / Public) rather than aggregating across all three.
        """

    # ------------------------------------------------------------------
    # Write APIs
    # ------------------------------------------------------------------

    @abstractmethod
    def create_or_replace_rule(
        self,
        rule_name: str,
        *,
        direction: str = "out",
        action: str = "allow",
        protocol: str = "any",
        remote_addresses: Optional[Iterable[str]] = None,
        remote_ports: Optional[Iterable[str]] = None,
        program: Optional[str] = None,
        profile: str = "any",
        description: Optional[str] = None,
    ) -> bool:
        """Create a managed firewall rule, replacing an exact-name match."""

    @abstractmethod
    def update_rule_remote_addresses(
        self,
        rule_name: str,
        remote_addresses: Iterable[str],
    ) -> bool:
        """Update RemoteAddress on an existing rule."""

    @abstractmethod
    def delete_rule(self, rule_name: str) -> bool:
        """Delete rules matching an exact display name."""

    @abstractmethod
    def delete_rules_by_prefix(self, rule_prefix: str) -> int:
        """Delete all rules whose display name starts with ``rule_prefix``."""

    @abstractmethod
    def set_profile_outbound_policy(self, profile: str, action: str) -> bool:
        """Set profile outbound policy to ``allow`` or ``block``."""


# ----------------------------------------------------------------------
# Factory
# ----------------------------------------------------------------------

_PROVIDER_ENV = "SAINT_FIREWALL_PROVIDER"
_WRITE_PROVIDER_ENV = "FIREWALL_WRITE_BACKEND"


def get_default_provider() -> FirewallProvider:
    """Return the preferred provider for the current host.

    Resolution order:
      1. ``SAINT_FIREWALL_PROVIDER`` env var (``netsh`` or ``netsecurity``).
      2. NetSecurity if available (PowerShell + ``Get-NetFirewallRule``).
      3. Netsh fallback.

    Imports are local because both concrete modules import this one.
    """
    forced = (os.environ.get(_PROVIDER_ENV) or "").strip().lower()

    # Local imports avoid a circular dependency: the concrete providers import
    # FirewallProvider from this module.
    from .netsh_provider import NetshFirewallProvider
    from .netsecurity_provider import NetSecurityFirewallProvider

    if forced == "netsh":
        return NetshFirewallProvider()
    if forced == "netsecurity":
        return NetSecurityFirewallProvider()

    if NetSecurityFirewallProvider.available():
        return NetSecurityFirewallProvider()
    return NetshFirewallProvider()


def get_write_provider() -> FirewallProvider:
    """Return the firewall write backend.

    Default is netsh for behavior compatibility. Operators can opt in to the
    PowerShell NetSecurity write path with ``FIREWALL_WRITE_BACKEND=powershell``
    after Windows-admin smoke testing.
    """
    forced = (os.environ.get(_WRITE_PROVIDER_ENV) or "netsh").strip().lower()

    from .netsh_provider import NetshFirewallProvider
    from .netsecurity_provider import NetSecurityFirewallProvider

    if forced in ("powershell", "netsecurity"):
        if NetSecurityFirewallProvider.available():
            return NetSecurityFirewallProvider()
        logger.warning(
            "%s=%s requested but NetSecurity is unavailable; falling back to netsh",
            _WRITE_PROVIDER_ENV, forced,
        )
        return NetshFirewallProvider()
    if forced != "netsh":
        logger.warning(
            "Unsupported %s=%s; falling back to netsh",
            _WRITE_PROVIDER_ENV, forced,
        )
    return NetshFirewallProvider()


def _normalize_direction(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("in", "inbound"):
        return "in"
    if v in ("out", "outbound"):
        return "out"
    return v or None


def _normalize_action(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    v = value.strip().lower()
    if v in ("allow", "permit"):
        return "allow"
    if v in ("block", "deny"):
        return "block"
    return v or None


def _split_csv(value: Optional[str]) -> List[str]:
    """Split a comma-separated firewall field, preserving order, dropping blanks."""
    if not value:
        return []
    out: List[str] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if chunk:
            out.append(chunk)
    return out


__all__ = [
    "FirewallProvider",
    "FirewallRule",
    "FirewallPolicyStatus",
    "get_default_provider",
    "get_write_provider",
    "_normalize_direction",
    "_normalize_action",
    "_split_csv",
]
