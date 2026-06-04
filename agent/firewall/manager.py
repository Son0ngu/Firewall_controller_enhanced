import logging
import json
import os
import sys
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set

from config.paths import get_user_data_dir
from shared.time_utils import now_iso
from shared.whitelist_values import canonicalize_whitelist_entry
from .policy import PolicyManager
from .provider import FirewallProvider, get_default_provider, get_write_provider
from .rules import RulesManager
from .utils import FirewallUtils

logger = logging.getLogger("firewall.manager")


# Default snapshot filename. Relative paths resolve to SAINT's per-user data
# directory, not next to the executable, so onefile builds do not need write
# permission in `dist` or Program Files.
DEFAULT_SNAPSHOT_FILENAME = "profiles/backup.saint-snapshot.json"


def _resolve_legacy_snapshot_path(path: str) -> Path:
    """Resolve a legacy relative snapshot path beside the source/exe install."""
    p = Path(path)
    if p.is_absolute():
        return p

    try:
        install_root = Path(__file__).resolve().parents[2]
    except Exception:
        install_root = Path.cwd()

    if getattr(sys, "frozen", False):
        install_root = Path(sys.executable).resolve().parent

    return install_root / p


def _resolve_snapshot_path(path: str) -> Path:
    """Resolve a snapshot file path to an absolute, cwd-independent location.

    Rules:
      - Absolute path: use as-is.
      - Relative path: resolve under SAINT's per-user data directory.
    """
    p = Path(path)
    if p.is_absolute():
        return p

    return get_user_data_dir() / p


def _resolve_snapshot_read_path(path: str) -> Path:
    """Return the snapshot path to read, falling back to the legacy location."""
    primary = _resolve_snapshot_path(path)
    if primary.exists():
        return primary

    legacy = _resolve_legacy_snapshot_path(path)
    if legacy != primary and legacy.exists():
        return legacy

    return primary


class FirewallManager:
    def __init__(
        self,
        rule_prefix: str = "FirewallController",
        provider: Optional[FirewallProvider] = None,
        write_provider: Optional[FirewallProvider] = None,
    ):
        self.rule_prefix = rule_prefix
        self._provider = provider or get_default_provider()
        self._write_provider = write_provider or get_write_provider()
        
        # Initialize sub-managers
        self.policy_manager = PolicyManager(write_provider=self._write_provider)
        self.rules_manager = RulesManager(
            rule_prefix,
            provider=self._provider,
            write_provider=self._write_provider,
        )
        
        # State tracking
        self.essential_ips: Set[str] = set()
        self.whitelist_mode_active = False
        
        # Check admin privileges
        if not FirewallUtils.has_admin_privileges():
            logger.warning("Firewall operations require administrator privileges")
        
        # Load existing rules and backup policy
        try:
            self.rules_manager.load_existing_rules()
            self.policy_manager.backup_current_policy()
            
            # Check if Default Deny is already active
            if self.policy_manager.verify_default_deny():
                self.policy_manager.default_deny_enabled = True
                if self.rules_manager.allowed_ips:
                    self.whitelist_mode_active = True
                    logger.info("Detected existing whitelist-only firewall mode")
            
            logger.info(f"FirewallManager initialized with prefix: {self.rule_prefix}")
            
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    # MAIN WHITELIST SETUP
    def setup_whitelist_firewall(self, whitelisted_ips: Set[str], essential_ips: Set[str] = None) -> bool:
        """Setup whitelist-based firewall using Windows Default Deny policy."""
        try:
            logger.info("Setting up whitelist firewall with DEFAULT DENY policy...")
            
            if not whitelisted_ips:
                logger.error("No whitelisted IPs provided")
                return False
            
            # Get essential IPs if not provided
            if essential_ips is None:
                essential_ips = FirewallUtils.get_essential_ips()
            
            # Validate IPs
            whitelisted_ips_valid = {ip for ip in whitelisted_ips if FirewallUtils.is_valid_ip(ip)}
            essential_ips_valid = {ip for ip in essential_ips if FirewallUtils.is_valid_ip(ip)}
            
            all_allowed_ips = whitelisted_ips_valid.union(essential_ips_valid)

            logger.info(f"Total IPs to allow: {len(all_allowed_ips)}")

            # Step 0: Whitelist the agent's own exe (see enable_whitelist_mode
            # for rationale - survives server IP rotation).
            self.rules_manager.create_self_allow_rules(sys.executable)

            # Step 1: Enable Default Deny policy
            if not self.policy_manager.enable_default_deny():
                logger.error("Failed to enable Default Deny policy")
                return False
            
            # Step 2: Create allow rules
            success = self.rules_manager.create_allow_rules_batch(all_allowed_ips)
            
            if success:
                self.whitelist_mode_active = True
                self.essential_ips = essential_ips_valid
                
                logger.info("Whitelist firewall with Default Deny setup completed!")
                logger.info("Windows Firewall Policy: DENY all outbound by default")
                logger.info(f"Created {len(all_allowed_ips)} ALLOW rules for whitelisted traffic")
                
                return True
            else:
                logger.error("Failed to create allow rules")
                return False
                
        except Exception as e:
            logger.error(f"Error setting up whitelist firewall: {e}")
            return False
    
   
    # DYNAMIC IP MANAGEMENT
    def add_ip_to_whitelist(self, ip: str, reason: str = "dynamic_addition") -> bool:
        """Add IP to whitelist dynamically."""
        try:
            if not FirewallUtils.is_valid_ip(ip):
                logger.warning(f"Invalid IP: {ip}")
                return False
            
            if ip in self.allowed_ips:
                logger.debug(f"IP {ip} already in whitelist")
                return True
            
            success = self.rules_manager.create_allow_rule(ip)
            
            if success:
                logger.info(f"Added {ip} to whitelist ({reason})")
            else:
                logger.error(f"Failed to add {ip} to whitelist")
            
            return success
                
        except Exception as e:
            logger.error(f"Error adding IP to whitelist: {e}")
            return False
    
    def remove_ip_from_whitelist(self, ip: str) -> bool:
        try:
            if ip not in self.allowed_ips:
                logger.debug(f"IP {ip} not in whitelist")
                return True
            
            success = self.rules_manager.remove_allow_rule(ip)
            
            if success:
                logger.info(f"Removed {ip} from whitelist")
            else:
                logger.error(f"Failed to remove {ip} from whitelist")
            
            return success
                
        except Exception as e:
            logger.error(f"Error removing IP from whitelist: {e}")
            return False
    
    def sync_whitelist_changes(self, old_ips: Set[str], new_ips: Set[str]) -> bool:
        try:
            added_ips = new_ips - old_ips
            removed_ips = old_ips - new_ips
            
            if not added_ips and not removed_ips:
                logger.debug("No IP changes to sync")
                return True
            
            logger.info(f"Syncing: +{len(added_ips)} IPs, -{len(removed_ips)} IPs")
            
            success_count = 0
            error_count = 0
            
            for ip in added_ips:
                if self.add_ip_to_whitelist(ip, "sync_update"):
                    success_count += 1
                else:
                    error_count += 1
            
            for ip in removed_ips:
                if self.remove_ip_from_whitelist(ip):
                    success_count += 1
                else:
                    error_count += 1
            
            logger.info(f"Sync completed: {success_count} changes, {error_count} errors")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Error syncing whitelist: {e}")
            return False
    
    def cleanup_whitelist_firewall(self) -> bool:
        
        try:
            logger.info("Cleaning up whitelist firewall...")
            
            # Step 1: Remove all our allow rules
            rules_success = self.rules_manager.clear_all_rules()
            
            # Step 2: Restore original Windows Firewall policy
            if self.policy_manager.restore_original_policy():
                logger.info("Windows Firewall policy restored to original state")
            else:
                logger.warning("Failed to restore original policy, using defaults")
                self.policy_manager.restore_default_policy()
            
            # Step 3: Clear state
            self.essential_ips.clear()
            self.whitelist_mode_active = False
            
            logger.info("Whitelist firewall cleanup completed")
            return rules_success
            
        except Exception as e:
            logger.error(f"Error cleaning up whitelist firewall: {e}")
            return False
    
    def clear_all_rules(self) -> bool:
        """Remove all firewall rules created by this manager."""
        return self.rules_manager.clear_all_rules()
    
    def cleanup_all_rules(self) -> bool:
        """Complete cleanup for whitelist-only mode (legacy compatibility)."""
        try:
            logger.info("Performing complete firewall cleanup...")
            
            # Step 1: Remove all our allow rules
            rules_success = self.rules_manager.clear_all_rules()
            
            # Step 2: Restore original firewall policy
            policy_success = self.policy_manager.restore_original_policy()
            
            # Step 3: Clear all state
            self.essential_ips.clear()
            self.whitelist_mode_active = False
            
            success = rules_success and policy_success
            
            if success:
                logger.info("Complete firewall cleanup successful")
            else:
                logger.warning("Some cleanup operations failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Error in complete cleanup: {e}")
            return False
    
    @property
    def allowed_ips(self) -> Set[str]:
        """Get allowed IPs from rules manager."""
        return self.rules_manager.allowed_ips
    
    @property
    def default_deny_enabled(self) -> bool:
        """Check if default deny is enabled."""
        return self.policy_manager.default_deny_enabled
    
    # STATUS & MONITORING
    def get_whitelist_status(self) -> Dict:
        """Get current status of whitelist-only firewall mode."""
        return {
            "whitelist_mode_active": self.whitelist_mode_active,
            "default_deny_enabled": self.default_deny_enabled,
            "allowed_ips_count": len(self.allowed_ips),
            "essential_ips_count": len(self.essential_ips),
            "total_allowed": len(self.allowed_ips) + len(self.essential_ips),
            "rule_prefix": self.rule_prefix,
            "approach": "default_deny_with_allow_rules",
            "status_timestamp": now_iso()
        }
    
    def get_firewall_policy_status(self) -> Dict:
        """Get current Windows Firewall policy status."""
        try:
            policies = self.policy_manager.get_current_policy()
            
            return {
                "default_deny_active": self.default_deny_enabled,
                "profiles": policies,
                "whitelist_mode_active": self.whitelist_mode_active,
                "allowed_ips_count": len(self.allowed_ips),
                "checked_at": now_iso()
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "checked_at": now_iso()
            }
    
    def validate_firewall_state(self) -> Dict:
        try:
            logger.info("Validating firewall state...")
            
            validation_result = {
                "whitelist_mode_active": self.whitelist_mode_active,
                "default_deny_enabled": self.default_deny_enabled,
                "total_allowed_ips": len(self.allowed_ips),
                "policy_verified": False,
                "issues": [],
                "validated_at": now_iso()
            }
            
            # Check policy state
            if self.whitelist_mode_active:
                policy_verified = self.policy_manager.verify_default_deny()
                validation_result["policy_verified"] = policy_verified
                
                if not policy_verified:
                    validation_result["issues"].append("Default Deny policy may not be active")
            
            # Check for missing essential IPs
            if not self.essential_ips:
                validation_result["issues"].append("No essential IPs configured")
            
            logger.info(f"Validation complete: {len(validation_result['issues'])} issues found")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating firewall state: {e}")
            return {"error": str(e), "validated_at": now_iso()}
    
    def test_whitelist_connectivity(self, sample_ips: List[str]) -> Dict[str, bool]:
        """Test connectivity to sample whitelisted IPs."""
        try:
            logger.info(f"Testing connectivity to {len(sample_ips)} sample IPs...")
            
            results = {}
            for ip in sample_ips[:5]:  # Test max 5 IPs
                results[ip] = FirewallUtils.test_ip_connectivity(ip)
            
            success_count = sum(1 for success in results.values() if success)
            logger.info(f"Connectivity test: {success_count}/{len(results)} IPs accessible")
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing connectivity: {e}")
            return {}
    
    # LEGACY COMPATIBILITY
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked (not in whitelist when Default Deny is active)."""
        if self.whitelist_mode_active and self.default_deny_enabled:
            return ip not in self.allowed_ips and ip not in self.essential_ips
        return False
    
    def get_blocked_ips(self) -> List[str]:
        """Get blocked IPs (in Default Deny mode, all non-whitelisted IPs are blocked)."""
        if self.whitelist_mode_active and self.default_deny_enabled:
            return ["ALL_NON_WHITELISTED_IPS"]
        return []
    
    def block_ip(self, ip: str, domain: Optional[str] = None) -> bool:
        """Legacy: In Default Deny mode, blocking means removing from whitelist."""
        if self.whitelist_mode_active:
            return self.remove_ip_from_whitelist(ip)
        logger.info(f"Default Deny not active - cannot block {ip}")
        return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Legacy: In Default Deny mode, unblocking means adding to whitelist."""
        if self.whitelist_mode_active:
            return self.add_ip_to_whitelist(ip, "unblock_request")
        logger.info(f"Default Deny not active - cannot unblock {ip}")
        return False
    
    # Internal policy methods for compatibility
    def _restore_original_policy(self) -> bool:
        """Wrapper for policy manager."""
        return self.policy_manager.restore_original_policy()
    
    def _restore_default_policy(self) -> bool:
        """Wrapper for policy manager."""
        return self.policy_manager.restore_default_policy()
    
    # WHITELIST UPDATE (CALLED BY WhitelistManager)
    def update_whitelist(self, domains: set, ips: set) -> bool:
        """
        Update firewall rules based on whitelist data.
        Called by WhitelistManager after sync.
        
        Args:
            domains: Set of whitelisted domains (need DNS resolution)
            ips: Set of whitelisted IPs
            
        Returns:
            True if update successful
        """
        try:
            logger.info(f"Updating firewall whitelist: {len(domains)} domains, {len(ips)} IPs")
            
            # Get current allowed IPs
            old_ips = self.allowed_ips.copy()
            
            # Collect all IPs to whitelist
            new_ips: Set[str] = set()
            
            # Add direct IPs from whitelist
            for ip in ips:
                if FirewallUtils.is_valid_ip(ip):
                    new_ips.add(ip)
            
            # Resolve domains to IPs
            resolved_ips = self._resolve_domains_to_ips(domains)
            new_ips.update(resolved_ips)
            
            logger.info(f"Total IPs after resolution: {len(new_ips)} ({len(resolved_ips)} from DNS)")
            
            # If no IPs, don't update (safety)
            if not new_ips:
                logger.warning("No valid IPs to whitelist, keeping current rules")
                return False
            
            # Setup whitelist firewall if not already active
            if not self.whitelist_mode_active:
                return self.setup_whitelist_firewall(new_ips)
            
            # Sync changes
            return self.sync_whitelist_changes(old_ips, new_ips)
            
        except Exception as e:
            logger.error(f"Error updating whitelist: {e}")
            return False
    
    def _resolve_domains_to_ips(self, domains: Set[str]) -> Set[str]:
        """Resolve domain names to IP addresses."""
        import socket

        resolved_ips: Set[str] = set()

        if not domains:
            return resolved_ips

        # Normalize domains: drop protocol, path, port, query and skip
        # wildcard patterns. DNS can resolve exact hostnames only.
        cleaned_domains: List[str] = []
        for domain in domains:
            try:
                entry_type, normalized = canonicalize_whitelist_entry(
                    "domain",
                    domain,
                )
                if entry_type == "domain" and normalized:
                    cleaned_domains.append(normalized)
            except Exception:
                continue

        if not cleaned_domains:
            return resolved_ips

        try:
            try:
                from agent.network import OptimizedDNSResolver

                resolver = OptimizedDNSResolver(max_workers=10, timeout=5.0)
                try:
                    results = resolver.resolve_multiple_parallel(cleaned_domains)

                    for domain, record in results.items():
                        for ip in (record.ipv4 or []):
                            if FirewallUtils.is_valid_ip(ip):
                                resolved_ips.add(ip)

                    logger.info(f"Resolved {len(cleaned_domains)} domains -> {len(resolved_ips)} IPs (optimized)")
                finally:
                    # Ephemeral resolver: shut down its thread pool now so
                    # worker threads don't linger until process exit.
                    try:
                        resolver.shutdown()
                    except Exception as e:
                        logger.debug(f"Ephemeral DNS resolver shutdown failed: {e}")

            except ImportError:
                for domain in cleaned_domains:
                    try:
                        results = socket.getaddrinfo(domain, None, socket.AF_INET)
                        for result in results:
                            ip = result[4][0]
                            if FirewallUtils.is_valid_ip(ip):
                                resolved_ips.add(ip)
                    except socket.gaierror:
                        logger.debug(f"Could not resolve domain: {domain}")
                    except Exception as e:
                        logger.debug(f"Error resolving {domain}: {e}")

                logger.info(f"Resolved {len(cleaned_domains)} domains -> {len(resolved_ips)} IPs (socket)")

        except Exception as e:
            logger.error(f"Error in DNS resolution: {e}")

        return resolved_ips
    
    def enable_whitelist_mode(self, server_urls: List[str] = None, whitelist_ips: Set[str] = None, whitelist_domains: Set[str] = None) -> bool:
        """
        Enable whitelist-only mode with Default Deny policy.
        Should be called during agent startup if firewall.mode == "whitelist_only".
        
        IMPORTANT: This adds allow rules for server URLs and essential IPs
        BEFORE enabling Default Deny to prevent blocking server connections.
        
        Args:
            server_urls: List of server URLs to allow (will resolve to IPs)
            whitelist_ips: Set of whitelisted IPs from server sync
            whitelist_domains: Set of domains to resolve to IPs
        
        Returns:
            True if enabled successfully
        """
        try:
            if self.whitelist_mode_active and self.default_deny_enabled:
                logger.info("Whitelist mode already active")
                return True
            
            logger.info("Enabling whitelist-only mode...")

            # Step 0: Whitelist the agent's own exe by program path. This is
            # immune to server-side IP rotation (Render.com load balancer)
            # whereas remoteip-based rules break the moment DNS resolves to a
            # different IP than what was whitelisted at startup.
            self.rules_manager.create_self_allow_rules(sys.executable)

            # Step 1: Collect all IPs to allow BEFORE enabling Default Deny
            all_allowed_ips = set()

            # 1a. Add essential IPs (DNS, localhost, gateway)
            essential_ips = FirewallUtils.get_essential_ips()
            all_allowed_ips.update(essential_ips)
            self.essential_ips = essential_ips
            logger.info(f"Essential IPs: {len(essential_ips)}")
            
            # 1b. Resolve server URLs to IPs
            if server_urls:
                server_ips = self._resolve_server_urls(server_urls)
                all_allowed_ips.update(server_ips)
                logger.info(f"Server IPs resolved: {len(server_ips)} - {server_ips}")
            
            # 1c. Add direct whitelist IPs from server sync
            if whitelist_ips:
                whitelist_valid = {ip for ip in whitelist_ips if FirewallUtils.is_valid_ip(ip)}
                all_allowed_ips.update(whitelist_valid)
                logger.info(f"Whitelist direct IPs: {len(whitelist_valid)}")
            
            # 1d. Resolve whitelist domains to IPs
            if whitelist_domains:
                logger.info(f"Resolving {len(whitelist_domains)} whitelist domains...")
                domain_ips = self._resolve_domains_to_ips(whitelist_domains)
                all_allowed_ips.update(domain_ips)
                logger.info(f"Whitelist domains resolved to: {len(domain_ips)} IPs")
            
            logger.info(f"Total IPs to allow: {len(all_allowed_ips)}")
            
            # Step 2: Create allow rules FIRST (before Default Deny)
            logger.info("Step 2: Creating ALLOW rules before enabling Default Deny...")
            for ip in all_allowed_ips:
                self.rules_manager.create_allow_rule(ip)
            
            # Step 3: NOW enable Default Deny policy (after rules are created)
            logger.info("Step 3: Enabling Default Deny policy...")
            if not self.policy_manager.enable_default_deny():
                logger.error("Failed to enable Default Deny policy")
                return False
            
            self.whitelist_mode_active = True
            
            logger.info("Whitelist-only mode enabled successfully")
            logger.info(f"Total ALLOW rules created: {len(all_allowed_ips)}")
            logger.info("Default Deny policy is now active")
            
            return True
            
        except Exception as e:
            logger.error(f"Error enabling whitelist mode: {e}")
            return False
    
    def _resolve_server_urls(self, urls: List[str]) -> Set[str]:
        """Resolve server URLs to IP addresses."""
        import socket
        from urllib.parse import urlparse
        
        ips = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    # Resolve hostname to IP
                    try:
                        ip = socket.gethostbyname(hostname)
                        ips.add(ip)
                        logger.debug(f"Resolved {hostname} -> {ip}")
                    except socket.gaierror:
                        # Try to get all IPs. Narrow exception type so a
                        # genuine bug (e.g. socket lib broken) isn't masked
                        # as "could not resolve" — only DNS failures land
                        # here.
                        try:
                            _, _, ip_list = socket.gethostbyname_ex(hostname)
                            for ip in ip_list:
                                ips.add(ip)
                        except (socket.gaierror, socket.herror) as e:
                            logger.warning(
                                f"Could not resolve {hostname}: {e.__class__.__name__}: {e}"
                            )
            except Exception as e:
                logger.warning(f"Error resolving {url}: {e}")
        
        return ips

    # BACKUP / RESTORE HELPERS
    def save_snapshot(
        self,
        path: str = DEFAULT_SNAPSHOT_FILENAME,
        *,
        force: bool = False,
    ) -> bool:
        """Save current firewall state to a snapshot file.

        Args:
            path: snapshot file path. Relative paths are resolved against the
                SAINT per-user data directory (cwd-independent).
            force: when False (default) and a snapshot file already exists,
                refuse to overwrite. This prevents losing the pre-SAINT
                baseline if the agent restarts after a crash where current
                policies have already been mutated by a previous run.

        Returns:
            True on success or when an existing snapshot was deliberately
            preserved; False on actual failure.
        """
        try:
            file_path = (
                _resolve_snapshot_path(path)
                if force
                else _resolve_snapshot_read_path(path)
            )
            file_path.parent.mkdir(parents=True, exist_ok=True)

            if file_path.exists() and not force:
                logger.info(
                    "Pre-SAINT snapshot already exists at %s - preserving "
                    "original baseline (use force=True to overwrite).",
                    file_path,
                )
                return True

            # Capture current state
            current_policies = self.policy_manager.get_current_policy()
            allowed_ips = (
                list(self.rules_manager.allowed_ips)
                if hasattr(self.rules_manager, "allowed_ips")
                else []
            )

            snapshot = {
                "version": 1,
                "timestamp": datetime.now().isoformat(),
                "policies": current_policies,
                "whitelist_mode": self.whitelist_mode_active,
                "essential_ips": list(self.essential_ips),
                "allowed_ips": allowed_ips,
            }

            # Atomic write: write to temp file in same dir, then os.replace().
            # Avoids corrupted snapshot if the process crashes mid-write.
            fd, tmp_name = tempfile.mkstemp(
                prefix=".saint-snapshot-",
                suffix=".tmp",
                dir=str(file_path.parent),
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, indent=4)
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass  # fsync not supported on some FS
                os.replace(tmp_name, file_path)
            except Exception:
                # Clean up temp file on failure
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise

            logger.info("Firewall snapshot saved to %s", file_path)
            return True

        except Exception as e:
            logger.error(f"Failed to save firewall snapshot: {e}")
            return False

    def restore_snapshot(self, path: str = DEFAULT_SNAPSHOT_FILENAME) -> bool:
        """Restore firewall to the state captured in the snapshot file.

        Intent: revert the machine to its **pre-SAINT** state. We restore the
        recorded profile policies and clear SAINT-managed rules. If the
        snapshot itself was captured while another SAINT run was already in
        whitelist mode, we do NOT re-enable Default Deny (that would be the
        opposite of "restore" from the user's point of view).
        """
        try:
            file_path = _resolve_snapshot_read_path(path)
            if not file_path.exists():
                logger.error(f"Snapshot file not found: {file_path}")
                return False

            # Admin guard - without elevation, netsh calls silently fail and we
            # would otherwise report a false-positive success.
            if not FirewallUtils.has_admin_privileges():
                logger.error(
                    "Restore requires administrator privileges. "
                    "Relaunch the agent as administrator."
                )
                return False

            with open(file_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)

            logger.info(
                "Restoring firewall snapshot from %s", snapshot.get("timestamp")
            )

            # 1. Restore Windows Firewall profile policies.
            policies = snapshot.get("policies", {})
            if policies:
                if not self.policy_manager.restore_policies(policies):
                    logger.warning("No firewall profile policy was restored from snapshot")
            else:
                logger.warning(
                    "Firewall snapshot contains no profile policies. "
                    "Restoring default allow-outbound policy to avoid lockout."
                )
                self.policy_manager.restore_default_policy()

            # Safety net: if every profile is block, force the Windows default
            # allow-outbound policy so the device doesn't lose connectivity.
            restored_actions = {
                a for a in policies.values() if a in {"allow", "block"}
            }
            if restored_actions == {"block"}:
                logger.warning(
                    "Snapshot keeps every profile in block-outbound. "
                    "Forcing default allow-outbound policy to avoid lockout."
                )
                self.policy_manager.restore_default_policy()

            # 2. Always clear SAINT-managed rules so restore truly reverts to
            #    pre-SAINT. Re-enabling Default Deny (the previous behaviour
            #    when snapshot.whitelist_mode was True) contradicts the user's
            #    intent - they clicked "Restore" precisely to step out of
            #    SAINT control.
            try:
                self.rules_manager.clear_all_rules()
            except Exception as clear_exc:
                logger.warning("clear_all_rules failed: %s", clear_exc)
            self.whitelist_mode_active = False

            was_whitelist_mode = snapshot.get("whitelist_mode", False)
            if was_whitelist_mode:
                logger.info(
                    "Snapshot recorded whitelist mode; not re-enabling it on "
                    "restore (intent: revert pre-SAINT state)."
                )

            return True

        except Exception as e:
            logger.error(f"Failed to restore firewall snapshot: {e}")
            return False
