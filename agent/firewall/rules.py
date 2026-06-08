import logging
import threading
from typing import Dict, Optional, Set

from shared.time_utils import now, now_iso, sleep
from .provider import FirewallProvider, get_default_provider, get_write_provider
from .utils import FirewallUtils

logger = logging.getLogger("firewall.rules")

class RulesManager:

    def __init__(
        self,
        rule_prefix: str = "FirewallController",
        provider: Optional[FirewallProvider] = None,
        write_provider: Optional[FirewallProvider] = None,
    ):
        self.rule_prefix = rule_prefix
        self.allowed_ips: Set[str] = set()
        self.allowed_rule_names: Dict[str, str] = {}
        self._rule_lock = threading.Lock()
        # Read and write sides are injectable for tests and backend rollout.
        # Writes default to netsh through the provider, with PowerShell
        # NetSecurity available behind FIREWALL_WRITE_BACKEND=powershell.
        self._provider: FirewallProvider = provider or get_default_provider()
        self._write_provider: FirewallProvider = write_provider or get_write_provider()
        logger.info("RulesManager using firewall provider: %s", self._provider.name)
        logger.info("RulesManager using firewall write provider: %s", self._write_provider.name)
    
    def create_self_allow_rules(self, program_path: str) -> bool:
        """Create allow rules for the agent's own exe.

        Rationale: when Default Deny is enabled, the agent must still reach the
        control server (HTTPS / TCP 443) and resolve domains via its own
        dnspython/aiodns stack (DNS / UDP 53 + TCP 53 fallback). Whitelisting
        by program path is bulletproof against server IP rotation (Render.com
        load balancer, CDN), unlike `remoteip=` rules.

        Rules are created with deterministic names and re-created idempotently
        (delete-then-add) so agent restarts don't accumulate duplicates.
        """
        if not program_path:
            logger.error("Self-allow rules skipped: no program path provided")
            return False

        rules = [
            ("HTTPS", "tcp", "443"),
            ("DNS_UDP", "udp", "53"),
            ("DNS_TCP", "tcp", "53"),
        ]

        success = True
        for tag, protocol, remoteport in rules:
            rule_name = f"{self.rule_prefix}_SelfAllow_{tag}"

            if self._write_provider.create_or_replace_rule(
                rule_name,
                direction="out",
                action="allow",
                program=program_path,
                protocol=protocol,
                remote_ports=[remoteport],
                profile="any",
                description=f"Allow SAINT agent outbound {tag} ({now_iso()})",
            ):
                logger.info(f"Self-allow rule created: {rule_name} ({protocol}/{remoteport})")
            else:
                logger.error(f"Failed to create self-allow rule {rule_name}")
                success = False

        return success

    def create_allow_rule(self, ip: str) -> bool:
        try:
            if not FirewallUtils.is_valid_ip(ip):
                logger.warning(f"Invalid IP: {ip}")
                return False

            if ip in self.allowed_ips:
                logger.debug(f"Allow rule already exists for {ip}")
                return True

            timestamp = int(now())
            sanitized_ip = ip.replace('.', '_')
            rule_name = f"{self.rule_prefix}_Allow_{sanitized_ip}_{timestamp}"
            
            if self._write_provider.create_or_replace_rule(
                rule_name,
                direction="out",
                action="allow",
                remote_addresses=[ip],
                protocol="any",
                profile="any",
                description=f"ALLOW rule for whitelisted IP {ip} (Created: {now_iso()})",
            ):
                self.allowed_ips.add(ip)
                self.allowed_rule_names[ip] = rule_name
                logger.debug(f"Created allow rule for {ip}")
                return True
            else:
                logger.error(f"Failed to create allow rule for {ip}")
                return False
                
        except Exception as e:
            logger.error(f"Exception creating allow rule for {ip}: {e}")
            return False
    
    def remove_allow_rule(self, ip: str) -> bool:
        try:
            if ip not in self.allowed_ips:
                logger.debug(f"No allow rule exists for {ip}")
                return True
            
            sanitized_ip = ip.replace('.', '_')
            rule_pattern = f"_{sanitized_ip}_"

            rule_names_to_delete = []
            mapped_rule_name = self.allowed_rule_names.get(ip)
            if mapped_rule_name:
                rule_names_to_delete.append(mapped_rule_name)
            for rule in self._provider.list_rules(
                rule_prefix=self.rule_prefix,
                direction="out",
                action="allow",
                enabled_only=False,
            ):
                rule_name = rule.get("rule_name", "")
                remote_addresses = set(rule.get("remote_addresses") or [])
                if (
                    ip in remote_addresses
                    or (
                        rule_name.startswith(self.rule_prefix)
                        and "_Allow_" in rule_name
                        and (
                            rule_pattern in rule_name
                            or rule_name.endswith(f"_Allow_{sanitized_ip}")
                        )
                    )
                ):
                    rule_names_to_delete.append(rule_name)
            
            success = True
            for rule_name in dict.fromkeys(rule_names_to_delete):
                if self._write_provider.delete_rule(rule_name):
                    logger.debug(f"Removed allow rule: {rule_name}")
                else:
                    logger.warning(f"Failed to remove rule {rule_name}")
                    success = False
            
            if success:
                self.allowed_ips.discard(ip)
                self.allowed_rule_names.pop(ip, None)
            
            return success
                
        except Exception as e:
            logger.error(f"Error removing allow rule for {ip}: {e}")
            return False
    
    def create_allow_rules_batch(self, ips: Set[str]) -> bool:
        try:
            logger.info(f"Creating ALLOW rules for {len(ips)} IPs...")
            
            success_count = 0
            error_count = 0
            
            with self._rule_lock:
                for ip in sorted(ips):
                    try:
                        if self.create_allow_rule(ip):
                            success_count += 1
                        else:
                            error_count += 1
                        
                        # Small delay for stability
                        sleep(0.02)
                        
                    except Exception as e:
                        error_count += 1
                        logger.error(f"Exception creating allow rule for {ip}: {e}")
            
            logger.info(f"Allow rules creation completed: {success_count} success, {error_count} errors")
            return error_count == 0 and success_count == len(ips)
            
        except Exception as e:
            logger.error(f"Error creating allow rules batch: {e}")
            return False
    
    def clear_all_rules(self) -> bool:
        try:
            removed = self._write_provider.delete_rules_by_prefix(self.rule_prefix)
            self.allowed_ips.clear()
            self.allowed_rule_names.clear()
            if removed:
                logger.info(f"Cleared {removed} rules successfully")
            else:
                logger.info(f"No rules with prefix '{self.rule_prefix}' to clear")
            return True
            
        except Exception as e:
            logger.error(f"Error clearing firewall rules: {e}")
            return False
    
    def load_existing_rules(self):
        """Re-hydrate ``allowed_ips`` from rules already present on the OS.

        Backend-agnostic now: delegates to the firewall provider's
        ``list_outbound_allow_ips`` rather than parsing ``netsh`` text inline.
        Behaviour is unchanged for English-locale Windows; non-English locales
        now also work (the netsh text parser was English-only).
        """
        try:
            logger.debug("Loading existing firewall rules via provider %s",
                         self._provider.name)
            ips = self._provider.list_outbound_allow_ips(rule_prefix=self.rule_prefix)
            self.allowed_ips.update(ips)
            logger.info("Loaded %d existing allow rules", len(self.allowed_ips))
        except Exception as e:
            logger.warning("Could not load existing firewall rules: %s", e)

    def get_rule_count(self) -> int:
        try:
            return self._provider.count_rules(rule_prefix=self.rule_prefix)
        except Exception:
            return 0
