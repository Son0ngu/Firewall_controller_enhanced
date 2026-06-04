"""
Agent Policy Service - Business logic for per-agent policy overrides.
Handles isolate mode, custom whitelist, and policy merging into agent-sync.
"""

import logging
from typing import Dict, List, Optional
from datetime import timedelta

from models.agent_policy_model import AgentPolicyModel
from models.agent_model import AgentModel
from time_utils import now_vietnam


class AgentPolicyService:

    def __init__(self, policy_model: AgentPolicyModel, agent_model: AgentModel,
                 socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.policy_model = policy_model
        self.agent_model = agent_model
        self.socketio = socketio

    # ── Policy CRUD ───────────────────────────────────────────

    def get_policy(self, agent_id: str) -> Dict:
        """Get current effective policy for an agent."""
        policy = self.policy_model.get_policy(agent_id)
        if not policy:
            return {
                "agent_id": agent_id,
                "override_mode": "none",
                "custom_whitelist": [],
                "reason": "",
                "expires_at": None,
                "override_version": 0,
            }

        # Check expiry
        expires = policy.get("expires_at")
        if expires and expires < now_vietnam():
            policy["override_mode"] = "none"
            policy["custom_whitelist"] = []

        return policy

    def set_policy(self, agent_id: str, mode: str, applied_by_user: Dict,
                   reason: str = "", custom_whitelist: List[Dict] = None,
                   duration_minutes: int = None) -> Dict:
        """
        Set policy for agent.

        Args:
            agent_id: target agent
            mode: "none" | "isolate" | "custom_whitelist"
            applied_by_user: g.current_user dict
            reason: reason for applying
            custom_whitelist: list of domains (only when mode=custom_whitelist)
            duration_minutes: auto-expire after N minutes (None = permanent)
        """
        # Validate agent exists
        agent = self.agent_model.find_by_agent_id(agent_id)
        if not agent:
            raise ValueError(f"Agent {agent_id} not found")

        # Calculate expires_at
        expires_at = None
        if duration_minutes and duration_minutes > 0:
            expires_at = now_vietnam() + timedelta(minutes=duration_minutes)

        policy = self.policy_model.set_policy(
            agent_id=agent_id,
            mode=mode,
            applied_by_user=applied_by_user,
            reason=reason,
            custom_whitelist=custom_whitelist,
            expires_at=expires_at,
        )

        # Broadcast via SocketIO for real-time frontend updates
        if self.socketio:
            self.socketio.emit("agent_policy_changed", {
                "agent_id": agent_id,
                "override_mode": mode,
                "reason": reason,
                "applied_by": applied_by_user.get("username", "unknown"),
                "expires_at": expires_at.isoformat() if expires_at else None,
            })

        self.logger.info(
            f"Policy set: agent={agent_id} mode={mode} "
            f"by={applied_by_user.get('username')} reason='{reason}' "
            f"expires={expires_at}"
        )

        return policy

    def isolate_agent(self, agent_id: str, applied_by_user: Dict,
                      reason: str = "Isolated by teacher",
                      duration_minutes: int = None) -> Dict:
        """Shortcut: completely cut network for an agent."""
        return self.set_policy(
            agent_id=agent_id,
            mode="isolate",
            applied_by_user=applied_by_user,
            reason=reason,
            duration_minutes=duration_minutes,
        )

    def reset_agent(self, agent_id: str, applied_by_user: Dict) -> Dict:
        """Shortcut: remove isolate/custom, return to normal group whitelist."""
        return self.set_policy(
            agent_id=agent_id,
            mode="none",
            applied_by_user=applied_by_user,
            reason="Reset to group default",
        )

    # ── Merge policy into sync response ────────────────────────

    def _build_system_entries(self, server_host: str = None, source: str = "policy_system") -> List[Dict]:
        """
        Build list of system domains/IPs that MUST be present in all policy overrides.
        Includes:
          - Server host (so agent maintains API connection)

        DNS is intentionally not injected here. The Windows agent adds its
        configured system DNS servers locally when it applies firewall rules,
        so policy sync does not force Google/Cloudflare public resolvers.
        """
        entries = []
        if server_host:
            entries.append({
                "domain": server_host,
                "category": "system",
                "is_active": True,
                "source": source,
            })
        return entries

    def apply_policy_to_sync(self, agent_id: str,
                             group_domains: List[Dict],
                             server_host: str = None) -> Dict:
        """
        Core function: Merge agent policy into whitelist sync response.
        Called from whitelist_service.get_agent_sync_data().

        Returns:
            {
                "domains": [...],       # Whitelist after merge
                "policy_mode": "none",  # Current mode
                "policy_active": False, # Whether override is active
            }
        """
        effective_mode = self.policy_model.get_effective_mode(agent_id)

        if effective_mode == "none":
            # No override → return original group whitelist
            return {
                "domains": group_domains,
                "policy_mode": "none",
                "policy_active": False,
            }

        if effective_mode == "isolate":
            # Block all - only keep server host so agent doesn't lose connection
            minimal_domains = self._build_system_entries(server_host, "policy_isolate")
            return {
                "domains": minimal_domains,
                "policy_mode": "isolate",
                "policy_active": True,
            }

        if effective_mode == "custom_whitelist":
            # Replace group whitelist with custom list
            custom_entries = self.policy_model.get_custom_whitelist(agent_id)
            # Server host is always included in list
            domains = self._build_system_entries(server_host, "policy_custom")
            for entry in custom_entries:
                domains.append({
                    "domain": entry.get("domain"),
                    "category": entry.get("category", "custom"),
                    "is_active": True,
                    "source": "policy_custom",
                })
            return {
                "domains": domains,
                "policy_mode": "custom_whitelist",
                "policy_active": True,
            }

        # Fallback
        return {
            "domains": group_domains,
            "policy_mode": "none",
            "policy_active": False,
        }

    # ── Dashboard helpers ─────────────────────────────────────

    def get_policies_for_agents(self, agent_ids: List[str]) -> Dict[str, Dict]:
        """Batch load policies (for list_agents dashboard)."""
        return self.policy_model.list_policies_by_agent_ids(agent_ids)

    def get_stats(self) -> Dict:
        """Policy statistics (for dashboard)."""
        return self.policy_model.count_by_mode()
