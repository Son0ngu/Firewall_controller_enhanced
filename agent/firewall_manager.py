# Import các thư viện cần thiết
import logging
import subprocess
import re
import time
from typing import Dict, List, Optional, Set
import socket

# Cấu hình logger cho module này
logger = logging.getLogger("firewall_manager")

class FirewallManager:
    """
    Enhanced Manages Windows Firewall rules for whitelist-only mode.
    Supports both reactive blocking and proactive allow/default-block setup.
    """
    
    def __init__(self, rule_prefix: str = "FirewallController"):
        """
        Initialize the firewall manager with enhanced whitelist-only support.
        
        Args:
            rule_prefix: Prefix to use for all firewall rules created by this instance
        """
        self.rule_prefix = rule_prefix
        
        # ✅ ENHANCED: Separate tracking for different rule types
        self.blocked_ips: Set[str] = set()  # Individual block rules (reactive)
        self.allowed_ips: Set[str] = set()  # Individual allow rules (proactive)
        self.essential_ips: Set[str] = set()  # Essential IPs (always allowed)
        
        # ✅ ADD: Whitelist-only mode state tracking
        self.whitelist_mode_active = False
        self.default_block_created = False
        
        # ✅ ADD: Rule priority management for proper ordering
        self.allow_rule_priority = 1000    # High priority for allow rules
        self.block_rule_priority = 2000    # Lower priority for individual blocks
        self.default_block_priority = 9999 # Lowest priority for default block
        
        # Check admin privileges
        if not self._has_admin_privileges():
            logger.warning("Firewall operations require administrator privileges")
        
        # Load existing rules to sync state
        self._load_existing_rules()
        logger.info(f"FirewallManager initialized with prefix: {self.rule_prefix}")
    
    # ✅ NEW: Whitelist-only mode setup (STARTUP PHASE)
    def setup_whitelist_firewall(self, whitelisted_ips: Set[str], essential_ips: Set[str] = None) -> bool:
        """
        Setup complete whitelist-based firewall (STARTUP PHASE).
        Creates allow rules for whitelisted IPs and default block rule.
        
        Args:
            whitelisted_ips: Set of IP addresses that should be allowed
            essential_ips: Set of essential IPs (localhost, DNS, etc.)
            
        Returns:
            bool: True if setup successful, False otherwise
        """
        try:
            logger.info("🔧 Setting up whitelist-based firewall...")
            
            # 1. Get essential IPs if not provided
            if essential_ips is None:
                essential_ips = self._get_essential_ips()
            
            # 2. Store essential IPs for tracking
            self.essential_ips = essential_ips.copy()
            
            # 3. Combine whitelisted + essential IPs
            all_allowed_ips = whitelisted_ips.union(essential_ips)
            logger.info(f"Total IPs to allow: {len(all_allowed_ips)} ({len(whitelisted_ips)} whitelist + {len(essential_ips)} essential)")
            
            # 4. Create allow rules for all allowed IPs (HIGH PRIORITY)
            success_count = 0
            error_count = 0
            
            for ip in all_allowed_ips:
                if self._create_allow_rule(ip, "Whitelist startup"):
                    success_count += 1
                else:
                    error_count += 1
            
            logger.info(f"Created {success_count}/{len(all_allowed_ips)} allow rules")
            
            # 5. Create default block rule (LOWEST PRIORITY)
            if self._create_default_block_rule():
                self.whitelist_mode_active = True
                logger.info("🔒 Whitelist-only firewall setup completed")
                logger.info("   - All non-whitelisted outbound traffic will be blocked")
                logger.info(f"   - {len(all_allowed_ips)} IPs are explicitly allowed")
                return True
            else:
                logger.error("❌ Failed to create default block rule")
                return False
                
        except Exception as e:
            logger.error(f"Error setting up whitelist firewall: {e}")
            return False
    
    def _create_allow_rule(self, ip: str, reason: str = None) -> bool:
        """
        Create high-priority allow rule for an IP address.
        
        Args:
            ip: IP address to allow
            reason: Reason for the rule (for description)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if already exists
            if ip in self.allowed_ips:
                logger.debug(f"Allow rule already exists for {ip}")
                return True
            
            # Validate IP format
            if not self._is_valid_ip(ip):
                logger.warning(f"Invalid IP address format: {ip}")
                return False
            
            # Generate rule name
            rule_name = f"{self.rule_prefix}_Allow_{ip.replace('.', '_').replace(':', '_')}"
            
            # Create high priority allow rule
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",                    # Outbound traffic
                "action=allow",               # Allow action
                f"remoteip={ip}",            # Target IP
                "protocol=any",               # All protocols
                "enable=yes",                 # Enable immediately
                f"description=Allow: {reason or 'Whitelist'}"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.allowed_ips.add(ip)
                logger.debug(f"✅ Allow rule created for {ip}")
                return True
            else:
                logger.error(f"❌ Failed to create allow rule for {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating allow rule for {ip}: {e}")
            return False
    
    def _create_default_block_rule(self) -> bool:
        """
        Create default block rule with lowest priority.
        This blocks all outbound traffic not explicitly allowed.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if self.default_block_created:
            logger.debug("Default block rule already exists")
            return True
        
        try:
            rule_name = f"{self.rule_prefix}_DefaultBlock"
            
            # Create lowest priority default block rule
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",                                    # Outbound traffic
                "action=block",                               # Block action
                "remoteip=any",                              # All remote IPs
                "enable=yes",                                # Enable immediately
                "description=Default block rule - blocks all non-whitelisted traffic"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.default_block_created = True
                logger.info("🔒 Default block rule created")
                return True
            else:
                logger.error(f"❌ Failed to create default block rule: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error creating default block rule: {e}")
            return False
    
    def _get_essential_ips(self) -> Set[str]:
        """
        Get essential IPs that should always be allowed.
        Includes localhost, common DNS servers, and local gateway.
        
        Returns:
            Set[str]: Set of essential IP addresses
        """
        essential = set()
        
        # Localhost addresses
        essential.update(["127.0.0.1", "::1"])
        
        # Common public DNS servers
        essential.update([
            "8.8.8.8", "8.8.4.4",              # Google DNS
            "1.1.1.1", "1.0.0.1",              # Cloudflare DNS
            "208.67.222.222", "208.67.220.220", # OpenDNS
            "9.9.9.9", "149.112.112.112"       # Quad9 DNS
        ])
        
        # Try to detect local network gateway
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                # Add likely gateway (usually .1 of local subnet)
                gateway_ip = '.'.join(local_ip.split('.')[:-1]) + '.1'
                essential.add(gateway_ip)
                logger.debug(f"Detected local gateway: {gateway_ip}")
        except Exception as e:
            logger.debug(f"Could not detect local gateway: {e}")
        
        logger.debug(f"Essential IPs: {essential}")
        return essential
    
    # ✅ NEW: Runtime sync methods (RUNTIME PHASE)
    def sync_whitelist_changes(self, old_ips: Set[str], new_ips: Set[str]) -> bool:
        """
        Sync firewall rules with whitelist changes (RUNTIME PHASE).
        Updates allow rules when whitelist changes.
        
        Args:
            old_ips: Previous set of whitelisted IPs
            new_ips: New set of whitelisted IPs
            
        Returns:
            bool: True if sync successful, False otherwise
        """
        try:
            # Calculate changes
            added_ips = new_ips - old_ips
            removed_ips = old_ips - new_ips
            
            if not added_ips and not removed_ips:
                logger.debug("No IP changes to sync")
                return True
            
            logger.info(f"🔄 Syncing firewall rules: +{len(added_ips)} IPs, -{len(removed_ips)} IPs")
            
            success_count = 0
            error_count = 0
            
            # Add new allow rules
            for ip in added_ips:
                # Skip essential IPs (already handled)
                if ip not in self.essential_ips:
                    if self._create_allow_rule(ip, "Whitelist update"):
                        success_count += 1
                    else:
                        error_count += 1
            
            # Remove old allow rules
            for ip in removed_ips:
                # Skip essential IPs (never remove)
                if ip not in self.essential_ips:
                    if self._remove_allow_rule(ip, "Whitelist update"):
                        success_count += 1
                    else:
                        error_count += 1
            
            logger.info(f"✅ Firewall sync completed: {success_count} changes, {error_count} errors")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Error syncing whitelist changes: {e}")
            return False
    
    def _remove_allow_rule(self, ip: str, reason: str = None) -> bool:
        """
        Remove allow rule for an IP address.
        
        Args:
            ip: IP address to remove allow rule for
            reason: Reason for removal (for logging)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if ip not in self.allowed_ips:
                logger.debug(f"No allow rule exists for {ip}")
                return True
            
            rule_name = f"{self.rule_prefix}_Allow_{ip.replace('.', '_').replace(':', '_')}"
            
            command = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.allowed_ips.discard(ip)
                logger.debug(f"🗑️ Allow rule removed for {ip}")
                return True
            else:
                logger.warning(f"Failed to remove allow rule for {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error removing allow rule for {ip}: {e}")
            return False
    
    # ✅ NEW: Enhanced cleanup methods (MAINTENANCE PHASE)
    def cleanup_all_rules(self) -> bool:
        """
        Clean up all rules including default block (MAINTENANCE PHASE).
        Used when shutting down whitelist-only mode.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("🧹 Cleaning up all firewall rules...")
            
            # Remove default block rule first
            if self.default_block_created:
                self._remove_default_block_rule()
            
            # Remove all other rules with our prefix
            success = self.clear_all_rules()
            
            # Clear tracking sets
            self.allowed_ips.clear()
            self.essential_ips.clear()
            self.blocked_ips.clear()
            
            # Reset state
            self.whitelist_mode_active = False
            
            logger.info("🗑️ All firewall rules cleaned up")
            return success
            
        except Exception as e:
            logger.error(f"Error cleaning up all rules: {e}")
            return False
    
    def _remove_default_block_rule(self) -> bool:
        """
        Remove the default block rule.
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.default_block_created:
            return True
        
        try:
            rule_name = f"{self.rule_prefix}_DefaultBlock"
            
            command = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.default_block_created = False
                logger.info("🗑️ Default block rule removed")
                return True
            else:
                logger.warning(f"Failed to remove default block rule: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error removing default block rule: {e}")
            return False
    
    # ✅ NEW: Status and monitoring methods
    def get_whitelist_status(self) -> Dict:
        """
        Get current status of whitelist-only firewall mode.
        
        Returns:
            Dict: Status information
        """
        return {
            "whitelist_mode_active": self.whitelist_mode_active,
            "default_block_created": self.default_block_created,
            "allowed_ips_count": len(self.allowed_ips),
            "essential_ips_count": len(self.essential_ips),
            "blocked_ips_count": len(self.blocked_ips),
            "total_allowed": len(self.allowed_ips) + len(self.essential_ips),
            "rule_prefix": self.rule_prefix
        }
    
    def refresh_essential_ips(self) -> bool:
        """
        Refresh essential IPs and update allow rules if needed.
        Useful for handling network changes.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.debug("🔄 Refreshing essential IPs...")
            
            # Get current essential IPs
            new_essential_ips = self._get_essential_ips()
            
            # Find changes
            added_essential = new_essential_ips - self.essential_ips
            removed_essential = self.essential_ips - new_essential_ips
            
            if added_essential or removed_essential:
                logger.info(f"Essential IP changes: +{len(added_essential)}, -{len(removed_essential)}")
                
                # Add new essential IPs
                for ip in added_essential:
                    self._create_allow_rule(ip, "Essential IP refresh")
                
                # Note: We don't remove old essential IPs automatically
                # as they might still be needed
                
                # Update tracking
                self.essential_ips = new_essential_ips
                
                return True
            else:
                logger.debug("No essential IP changes detected")
                return True
                
        except Exception as e:
            logger.error(f"Error refreshing essential IPs: {e}")
            return False
    
    # ✅ ENHANCED: Improved existing methods
    def _load_existing_rules(self):
        """
        Enhanced loading of existing firewall rules.
        Now tracks both allow and block rules separately.
        """
        try:
            logger.debug("Loading existing firewall rules...")
            
            # Get all firewall rules
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return
                
            # Parse output
            current_rule = None
            current_action = None
            current_ip = None
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Start of a new rule
                if line.startswith("Rule Name:"):
                    current_rule = line[10:].strip()
                    current_action = None
                    current_ip = None
                    
                    # Check if it's our rule
                    if not current_rule.startswith(self.rule_prefix):
                        current_rule = None
                        continue
                    
                    # Check for default block rule
                    if current_rule.endswith("_DefaultBlock"):
                        self.default_block_created = True
                        logger.debug("Found existing default block rule")
                
                # Only process lines if we're in a rule with our prefix
                elif current_rule:
                    if line.startswith("Action:"):
                        current_action = line[7:].strip().lower()
                    
                    elif line.startswith("RemoteIP:"):
                        ip_part = line[9:].strip()
                        
                        if ip_part and ip_part != "Any":
                            ip_parts = ip_part.split(',')
                            for part in ip_parts:
                                part = part.strip()
                                if self._is_valid_ip(part):
                                    current_ip = part
                                    
                                    # Categorize based on action
                                    if current_action == "allow":
                                        self.allowed_ips.add(part)
                                        logger.debug(f"Found existing allow rule for: {part}")
                                    elif current_action == "block":
                                        self.blocked_ips.add(part)
                                        logger.debug(f"Found existing block rule for: {part}")
            
            # Check if we're in whitelist mode
            if self.default_block_created and self.allowed_ips:
                self.whitelist_mode_active = True
                logger.info("Detected existing whitelist-only firewall mode")
            
            logger.info(f"Loaded existing rules: {len(self.allowed_ips)} allow, {len(self.blocked_ips)} block")
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while loading existing firewall rules")
        except Exception as e:
            logger.error(f"Error loading existing firewall rules: {e}")
    
    # ✅ LEGACY: Keep existing methods for backward compatibility
    def block_ip(self, ip: str, domain: Optional[str] = None) -> bool:
        """
        Legacy method: Block an IP address by creating a firewall rule.
        Note: In whitelist-only mode, this is less relevant as default block handles most blocking.
        """
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} is already blocked")
            return True
        
        # In whitelist mode, check if IP is already handled by default block
        if self.whitelist_mode_active:
            if ip not in self.allowed_ips:
                logger.debug(f"IP {ip} already blocked by default rule in whitelist mode")
                return True
            
        timestamp = int(time.time())
        rule_name = f"{self.rule_prefix}_Block_{ip.replace('.', '_')}_{timestamp}"
        
        if domain:
            description = f"Blocked connection to {domain} ({ip})"
        else:
            description = f"Blocked connection to {ip}"
            
        try:
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                f"description={description}"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.info(f"Successfully blocked IP: {ip}")
                return True
            else:
                logger.error(f"Failed to block IP {ip}. Error: {result.stderr.strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {str(e)}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Legacy method: Unblock an IP address by removing associated firewall rules."""
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        if ip not in self.blocked_ips:
            logger.debug(f"IP {ip} is not in our blocked list")
            return False
            
        try:
            rules = self._find_rules_for_ip(ip)
            
            if not rules:
                logger.warning(f"No firewall rules found for IP {ip}")
                return False
                
            success = False
            
            for rule_name in rules:
                command = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    logger.info(f"Successfully removed rule: {rule_name}")
                    success = True
                else:
                    logger.error(f"Failed to remove rule {rule_name}. Error: {result.stderr.strip()}")
            
            if success:
                self.blocked_ips.remove(ip)
                return True
            else:
                return False
                
        except Exception as e:
            logger.error(f"Error unblocking IP {ip}: {str(e)}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP address is blocked."""
        # In whitelist mode, check if IP is allowed
        if self.whitelist_mode_active:
            return ip not in self.allowed_ips and ip not in self.essential_ips
        # In legacy mode, check blocked list
        return ip in self.blocked_ips
    
    def get_blocked_ips(self) -> List[str]:
        """Get a list of all IPs blocked by this firewall manager."""
        return list(self.blocked_ips)
    
    def clear_all_rules(self) -> bool:
        """Remove all firewall rules created by this firewall manager."""
        try:
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return False
                
            rule_names = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if line.strip().startswith("Rule Name:"):
                    rule_name = line.strip()[10:].strip()
                    if rule_name.startswith(self.rule_prefix):
                        rule_names.append(rule_name)
            
            if not rule_names:
                logger.info("No rules to clear")
                return True
                
            success = True
            for rule_name in rule_names:
                command = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    logger.debug(f"Successfully removed rule: {rule_name}")
                else:
                    logger.error(f"Failed to remove rule {rule_name}. Error: {result.stderr.strip()}")
                    success = False
            
            if success:
                self.blocked_ips.clear()
                
            return success
                
        except Exception as e:
            logger.error(f"Error clearing firewall rules: {str(e)}")
            return False
    
    def _find_rules_for_ip(self, ip: str) -> List[str]:
        """Find all firewall rules that target the given IP."""
        rule_names = []
        
        try:
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return rule_names
                
            ip_pattern = ip.replace('.', '_')
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    rule_name = line[10:].strip()
                    if rule_name.startswith(self.rule_prefix) and ip_pattern in rule_name:
                        rule_names.append(rule_name)
            
            return rule_names
            
        except Exception as e:
            logger.error(f"Error finding rules for IP {ip}: {str(e)}")
            return rule_names
    
    def _has_admin_privileges(self) -> bool:
        """Check if the application is running with administrator privileges."""
        try:
            command = ["netsh", "advfirewall", "show", "currentprofile"]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error checking admin privileges: {str(e)}")
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate if a string is a valid IPv4 address."""
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        
        if not match:
            return False
            
        for i in range(1, 5):
            octet = int(match.group(i))
            if octet < 0 or octet > 255:
                return False
                
        return True


# ✅ NEW: Example usage and testing
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test whitelist-only mode
    firewall = FirewallManager()
    
    # Test IPs
    whitelisted_ips = {"93.184.216.34", "172.217.164.142"}  # example.com, google.com
    
    print("\n=== Testing Whitelist-Only Firewall Mode ===")
    
    # Setup whitelist firewall
    print(f"\nSetting up whitelist firewall for IPs: {whitelisted_ips}")
    success = firewall.setup_whitelist_firewall(whitelisted_ips)
    print(f"Setup result: {'Success' if success else 'Failed'}")
    
    # Check status
    status = firewall.get_whitelist_status()
    print(f"\nFirewall status: {status}")
    
    # Test sync with changes
    print(f"\nTesting sync with new IPs...")
    new_ips = whitelisted_ips.union({"8.8.8.8"})  # Add Google DNS
    sync_result = firewall.sync_whitelist_changes(whitelisted_ips, new_ips)
    print(f"Sync result: {'Success' if sync_result else 'Failed'}")
    
    # Final status
    final_status = firewall.get_whitelist_status()
    print(f"\nFinal status: {final_status}")
    
    # Cleanup
    print(f"\nCleaning up...")
    cleanup_result = firewall.cleanup_all_rules()
    print(f"Cleanup result: {'Success' if cleanup_result else 'Failed'}")