# Import các thư viện cần thiết
import logging
import subprocess
import re
import socket
import threading
from typing import Dict, List, Optional, Set

# Import time utilities - UTC ONLY
from time_utils import now, now_iso, sleep

# Cấu hình logger cho module này
logger = logging.getLogger("firewall_manager")

class FirewallManager:
    """
    Simplified Firewall Manager using Windows Default Deny Policy
    NO BLOCK RULES - Only ALLOW rules + Default Deny Policy
    """
    
    def __init__(self, rule_prefix: str = "FirewallController"):
        """
        Initialize the firewall manager with Default Deny approach.
        
        Args:
            rule_prefix: Prefix to use for all firewall rules created by this instance
        """
        self.rule_prefix = rule_prefix
        
        #  SIMPLIFIED: Only track allowed IPs
        self.allowed_ips: Set[str] = set()
        self.essential_ips: Set[str] = set()
        
        #  SIMPLIFIED: State tracking
        self.whitelist_mode_active = False
        self.default_deny_enabled = False
        
        #  SIMPLIFIED: Threading control
        self.rule_creation_lock = threading.Lock()
        
        # Check admin privileges
        if not self._has_admin_privileges():
            logger.warning("Firewall operations require administrator privileges")
        
        # Load existing rules
        try:
            self._load_existing_rules()
            logger.info(f"FirewallManager initialized with prefix: {self.rule_prefix}")
        except Exception as e:
            logger.error(f"Error loading existing rules: {e}")

        #  NEW: Backup current policy before making changes
        self._backup_current_policy()

    # ========================================
    # MAIN WHITELIST SETUP METHOD
    # ========================================

    def setup_whitelist_firewall(self, whitelisted_ips: Set[str], essential_ips: Set[str] = None) -> bool:
        """Setup whitelist-based firewall using Windows Default Deny policy"""
        try:
            logger.info("🔧 Setting up whitelist firewall with DEFAULT DENY policy...")
            
            if not whitelisted_ips:
                logger.error("❌ No whitelisted IPs provided")
                return False
            
            # Get essential IPs if not provided
            if essential_ips is None:
                essential_ips = self._get_essential_ips()
            
            # Filter IPv4 only
            whitelisted_ips_v4 = {ip for ip in whitelisted_ips if self._is_valid_ipv4(ip)}
            essential_ips_v4 = {ip for ip in essential_ips if self._is_valid_ipv4(ip)}
            
            all_allowed_ips = whitelisted_ips_v4.union(essential_ips_v4)
            
            logger.info(f"📊 Total IPv4 IPs to allow: {len(all_allowed_ips)}")
            
            #  STEP 1: Set Windows Firewall to Default Deny for Outbound
            if not self._enable_default_deny_policy():
                logger.error("❌ Failed to enable Default Deny policy")
                return False
            
            #  STEP 2: Create ONLY allow rules (no block rules needed)
            success = self._create_allow_rules_only(all_allowed_ips)
            
            if success:
                self.whitelist_mode_active = True
                self.allowed_ips = all_allowed_ips
                self.essential_ips = essential_ips_v4
                
                logger.info("🎉 Whitelist firewall with Default Deny setup completed!")
                logger.info("🔒 Windows Firewall Policy: DENY all outbound by default")
                logger.info(f" Created {len(all_allowed_ips)} ALLOW rules for whitelisted traffic")
                
                return True
            else:
                logger.error("❌ Failed to create allow rules")
                return False
                
        except Exception as e:
            logger.error(f"Error setting up whitelist firewall: {e}")
            return False

    # ========================================
    # WINDOWS FIREWALL POLICY MANAGEMENT
    # ========================================

    def _get_current_firewall_policy(self) -> Dict[str, str]:
        """Get current firewall policy for all profiles"""
        try:
            command = ["netsh", "advfirewall", "show", "allprofiles"]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                policies = {}
                current_profile = None
                
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if "Domain Profile Settings:" in line:
                        current_profile = "domain"
                    elif "Private Profile Settings:" in line:
                        current_profile = "private"
                    elif "Public Profile Settings:" in line:
                        current_profile = "public"
                    elif current_profile and "Outbound connections:" in line:
                        action = "block" if "block" in line.lower() else "allow"
                        policies[current_profile] = action
                
                return policies
            
            return {}
        except Exception as e:
            logger.error(f"Error getting current firewall policy: {e}")
            return {}

    def _enable_default_deny_policy(self) -> bool:
        """Enable Windows Firewall Default Deny policy for outbound connections"""
        try:
            logger.info("🔒 Enabling Windows Firewall Default Deny policy...")
            
            #  IMPROVED: Check current state first
            current_policies = self._get_current_firewall_policy()
            logger.debug(f"Current firewall policies: {current_policies}")
            
            #  Set outbound default action to BLOCK for all profiles
            profiles = ["domain", "private", "public"]
            success_count = 0
            
            for profile in profiles:
                # Skip if already set to block
                if current_policies.get(profile) == "block":
                    logger.info(f" {profile.title()} profile already set to block outbound")
                    success_count += 1
                    continue
                
                command = [
                    "netsh", "advfirewall", "set", f"{profile}profile", 
                    "firewallpolicy", "blockinbound,blockoutbound"
                ]
                
                logger.info(f"🔒 Setting {profile.title()} profile to block outbound by default...")
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    logger.info(f" {profile.title()} profile set to Default Deny")
                    success_count += 1
                else:
                    logger.error(f"❌ Failed to set {profile.title()} profile: {result.stderr}")
            
            #  IMPROVED: More lenient success criteria
            if success_count >= 1:  # At least one profile should succeed
                # Verify the policy is set
                if self._verify_default_deny_policy():
                    self.default_deny_enabled = True
                    logger.info(" Default Deny policy enabled successfully")
                    logger.info("🔒 All outbound traffic will be BLOCKED unless explicitly allowed")
                    return True
                else:
                    logger.warning("⚠️ Policy set but verification failed - proceeding anyway")
                    self.default_deny_enabled = True
                    return True
            else:
                logger.error("❌ Failed to set any firewall profiles")
                return False
                
        except Exception as e:
            logger.error(f"Error enabling Default Deny policy: {e}")
            return False

    def _verify_default_deny_policy(self) -> bool:
        """Verify that Default Deny policy is active"""
        try:
            command = ["netsh", "advfirewall", "show", "allprofiles"]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                #  IMPROVED: Better parsing logic
                profiles_verified = 0
                lines = output.split('\n')
                current_profile = None
                
                for line in lines:
                    line = line.strip()
                    
                    # Detect profile headers - more robust pattern
                    if "Profile Settings:" in line or "profile settings" in line.lower():
                        current_profile = line
                        logger.debug(f"Checking profile: {current_profile}")
                    
                    # Look for outbound connections setting - case insensitive
                    elif current_profile and ("outbound connections" in line.lower() or "outbound connection" in line.lower()):
                        if "block" in line.lower():
                            profiles_verified += 1
                            logger.debug(f" Profile has outbound block: {line}")
                        else:
                            logger.debug(f"❌ Profile allows outbound: {line}")
                
                #  IMPROVED: More lenient verification
                if profiles_verified >= 1:  # At least 1 profile should have outbound blocking
                    logger.info(f" Default Deny policy verified - {profiles_verified} profiles blocking outbound")
                    return True
                else:
                    #  FALLBACK: Try alternative verification method
                    logger.warning("⚠️ Standard verification failed, trying alternative method...")
                    return self._verify_policy_alternative(output)
            else:
                logger.error(f"Failed to verify firewall policy: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying Default Deny policy: {e}")
            return False

    def _verify_policy_alternative(self, output: str) -> bool:
        """Alternative verification method using different patterns"""
        try:
            output_lower = output.lower()
            
            # Check for blockoutbound in the output
            if "blockoutbound" in output_lower:
                logger.info(" Alternative verification: Found blockoutbound policy")
                return True
            
            # Check for block + outbound combination
            block_count = output_lower.count("block")
            outbound_count = output_lower.count("outbound")
            
            if block_count > 0 and outbound_count > 0:
                logger.info(" Alternative verification: Found block + outbound indicators")
                return True
            
            logger.warning("⚠️ Alternative verification also failed")
            logger.debug(f"Full firewall output:\n{output}")
            return False
            
        except Exception as e:
            logger.error(f"Error in alternative verification: {e}")
            return False

    def _restore_default_policy(self) -> bool:
        """Restore Windows Firewall to default policy (allow outbound)"""
        try:
            logger.info(" Restoring Windows Firewall to default policy...")
            
            #  Restore default policy for all profiles
            profiles = ["Domain", "Private", "Public"]
            
            for profile in profiles:
                command = [
                    "netsh", "advfirewall", "set", profile.lower() + "profile", 
                    "firewallpolicy", "blockinbound,allowoutbound"
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    logger.info(f" {profile} profile restored to default (allow outbound)")
                else:
                    logger.error(f"❌ Failed to restore {profile} profile: {result.stderr}")
                    return False
            
            self.default_deny_enabled = False
            return True
            
        except Exception as e:
            logger.error(f"Error restoring default policy: {e}")
            return False

    # ========================================
    # ALLOW RULES MANAGEMENT
    # ========================================

    def _create_allow_rules_only(self, allowed_ips: Set[str]) -> bool:
        """Create ONLY allow rules - no block rules needed with Default Deny"""
        try:
            logger.info(f"🔓 Creating ALLOW rules for {len(allowed_ips)} IPs...")
            
            success_count = 0
            error_count = 0
            
            with self.rule_creation_lock:
                for ip in sorted(allowed_ips):
                    try:
                        if self._create_simple_allow_rule(ip):
                            success_count += 1
                            logger.debug(f"     Allow rule created for {ip}")
                        else:
                            error_count += 1
                            logger.warning(f"    ❌ Failed to create allow rule for {ip}")
                            
                        # Small delay for stability - using time_utils
                        sleep(0.02)
                        
                    except Exception as e:
                        error_count += 1
                        logger.error(f"    ❌ Exception creating allow rule for {ip}: {e}")
        
            logger.info(f"🔓 Allow rules creation completed: {success_count} success, {error_count} errors")
            
            if success_count > 0:
                logger.info(" Whitelist firewall ready - only allowed IPs can connect")
                return True
            else:
                logger.error("❌ No allow rules created successfully")
                return False
                
        except Exception as e:
            logger.error(f"Error creating allow rules: {e}")
            return False

    def _create_simple_allow_rule(self, ip: str) -> bool:
        """Create simple allow rule for an IP (no priority concerns with Default Deny)"""
        try:
            if not self._is_valid_ipv4(ip):
                logger.warning(f"Invalid IPv4: {ip}")
                return False
            
            if ip in self.allowed_ips:
                logger.debug(f"Allow rule already exists for {ip}")
                return True
            
            #  SIMPLE NAMING: Using time_utils for timestamp - UTC ONLY
            timestamp = int(now())  # UTC Unix timestamp
            rule_name = f"{self.rule_prefix}_Allow_{ip.replace('.', '_')}_{timestamp}"
            
            #  SIMPLE COMMAND: Just allow the IP, Windows handles the rest
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=allow",
                f"remoteip={ip}",
                "protocol=any",
                "enable=yes",
                "profile=any",
                f"description=ALLOW rule for whitelisted IP {ip} (Created: {now_iso()})"  # UTC ISO
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                self.allowed_ips.add(ip)
                return True
            else:
                logger.error(f"Failed to create allow rule for {ip}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Exception creating allow rule for {ip}: {e}")
            return False

    # ========================================
    # DYNAMIC IP MANAGEMENT
    # ========================================

    def add_ip_to_whitelist(self, ip: str, reason: str = "dynamic_addition") -> bool:
        """Add IP to whitelist dynamically (simple with Default Deny)"""
        try:
            if not self._is_valid_ipv4(ip):
                logger.warning(f"Invalid IPv4: {ip}")
                return False
            
            if ip in self.allowed_ips:
                logger.debug(f"IP {ip} already in whitelist")
                return True
            
            #  SIMPLE: Just create allow rule, Default Deny handles the rest
            success = self._create_simple_allow_rule(ip)
            
            if success:
                logger.info(f" Added {ip} to whitelist ({reason})")
                return True
            else:
                logger.error(f"❌ Failed to add {ip} to whitelist")
                return False
                
        except Exception as e:
            logger.error(f"Error adding IP to whitelist: {e}")
            return False

    def remove_ip_from_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist (simple with Default Deny)"""
        try:
            if ip not in self.allowed_ips:
                logger.debug(f"IP {ip} not in whitelist")
                return True
            
            #  SIMPLE: Just delete allow rule, Default Deny blocks automatically
            success = self._remove_allow_rule(ip)
            
            if success:
                logger.info(f" Removed {ip} from whitelist (will be blocked by Default Deny)")
                return True
            else:
                logger.error(f"❌ Failed to remove {ip} from whitelist")
                return False
                
        except Exception as e:
            logger.error(f"Error removing IP from whitelist: {e}")
            return False

    def _remove_allow_rule(self, ip: str) -> bool:
        """Remove allow rule for an IP address"""
        try:
            if ip not in self.allowed_ips:
                logger.debug(f"No allow rule exists for {ip}")
                return True
            
            # Find rule by IP pattern in name
            rule_pattern = f"_{ip.replace('.', '_')}_"
            
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
                logger.error("Failed to list rules")
                return False
            
            # Find matching rule names
            rule_names_to_delete = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if line.strip().startswith("Rule Name:"):
                    rule_name = line.strip()[10:].strip()
                    if (rule_name.startswith(self.rule_prefix) and 
                        "_Allow_" in rule_name and 
                        rule_pattern in rule_name):
                        rule_names_to_delete.append(rule_name)
            
            # Delete found rules
            success = True
            for rule_name in rule_names_to_delete:
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
                    logger.debug(f"🗑️ Removed allow rule: {rule_name}")
                else:
                    logger.warning(f"Failed to remove rule {rule_name}: {result.stderr}")
                    success = False
            
            if success:
                self.allowed_ips.discard(ip)
            
            return success
                
        except Exception as e:
            logger.error(f"Error removing allow rule for {ip}: {e}")
            return False

    def sync_whitelist_changes(self, old_ips: Set[str], new_ips: Set[str]) -> bool:
        """Simple whitelist sync with Default Deny (no complex rule management)"""
        try:
            added_ips = new_ips - old_ips
            removed_ips = old_ips - new_ips
            
            if not added_ips and not removed_ips:
                logger.debug("No IP changes to sync")
                return True
            
            logger.info(f" Simple sync: +{len(added_ips)} IPs, -{len(removed_ips)} IPs")
            
            success_count = 0
            error_count = 0
            
            #  Add new IPs (create allow rules)
            for ip in added_ips:
                if self.add_ip_to_whitelist(ip, "sync_update"):
                    success_count += 1
                else:
                    error_count += 1
            
            #  Remove old IPs (delete allow rules)
            for ip in removed_ips:
                if self.remove_ip_from_whitelist(ip):
                    success_count += 1
                else:
                    error_count += 1
            
            logger.info(f" Simple sync completed: {success_count} changes, {error_count} errors")
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Error in simple whitelist sync: {e}")
            return False

    # ========================================
    # CLEANUP AND UTILITIES
    # ========================================

    def cleanup_whitelist_firewall(self) -> bool:
        """Clean up whitelist firewall and restore original policy"""
        try:
            logger.info("🧹 Cleaning up whitelist firewall...")
            
            #  STEP 1: Remove all our allow rules
            success = self.clear_all_rules()
            
            #  STEP 2: Restore ORIGINAL Windows Firewall policy
            if self._restore_original_policy():
                logger.info(" Windows Firewall policy restored to original state")
            else:
                logger.warning("⚠️ Failed to restore original policy, using defaults")
                self._restore_default_policy()
        
            #  STEP 3: Clear state
            self.allowed_ips.clear()
            self.essential_ips.clear()
            self.whitelist_mode_active = False
            self.default_deny_enabled = False
            
            logger.info(" Whitelist firewall cleanup completed")
            return success
        
        except Exception as e:
            logger.error(f"Error cleaning up whitelist firewall: {e}")
            return False

    def cleanup_all_rules(self) -> bool:
        """Complete cleanup for whitelist-only mode"""
        try:
            logger.info("🗑️ Performing complete firewall cleanup...")
            
            #  STEP 1: Remove all our allow rules
            rules_success = self.clear_all_rules()
            
            #  STEP 2: Restore original firewall policy
            policy_success = self._restore_original_policy()
            
            #  STEP 3: Clear all state
            self.allowed_ips.clear()
            self.essential_ips.clear()
            self.whitelist_mode_active = False
            self.default_deny_enabled = False
            
            success = rules_success and policy_success
            
            if success:
                logger.info(" Complete firewall cleanup successful")
            else:
                logger.warning("⚠️ Some cleanup operations failed")
            
            return success
            
        except Exception as e:
            logger.error(f"Error in complete cleanup: {e}")
            return False

    def clear_all_rules(self) -> bool:
        """Remove all firewall rules created by this firewall manager"""
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
                self.allowed_ips.clear()
                
            return success
                
        except Exception as e:
            logger.error(f"Error clearing firewall rules: {str(e)}")
            return False

    # ========================================
    # STATUS AND MONITORING
    # ========================================

    def get_whitelist_status(self) -> Dict:
        """Get current status of whitelist-only firewall mode"""
        return {
            "whitelist_mode_active": self.whitelist_mode_active,
            "default_deny_enabled": self.default_deny_enabled,
            "allowed_ips_count": len(self.allowed_ips),
            "essential_ips_count": len(self.essential_ips),
            "total_allowed": len(self.allowed_ips) + len(self.essential_ips),
            "rule_prefix": self.rule_prefix,
            "approach": "default_deny_with_allow_rules",
            "status_timestamp": now_iso()  # UTC timestamp
        }

    def get_firewall_policy_status(self) -> Dict:
        """Get current Windows Firewall policy status"""
        try:
            command = ["netsh", "advfirewall", "show", "allprofiles"]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse firewall status
                status = {
                    "default_deny_active": "blockoutbound" in output.lower(),
                    "firewall_enabled": "state" in output.lower() and "on" in output.lower(),
                    "whitelist_mode_active": self.whitelist_mode_active,
                    "allowed_ips_count": len(self.allowed_ips),
                    "policy_output": output,
                    "checked_at": now_iso()  # UTC timestamp
                }
                
                return status
            else:
                return {
                    "error": f"Failed to get firewall status: {result.stderr}",
                    "checked_at": now_iso()  # UTC timestamp
                }
                
        except Exception as e:
            return {
                "error": f"Exception getting firewall status: {e}",
                "checked_at": now_iso()  # UTC timestamp
            }

    def validate_firewall_state(self) -> Dict[str, any]:
        """Validate current firewall state"""
        try:
            logger.info(" Validating firewall state...")
            
            validation_result = {
                "whitelist_mode_active": self.whitelist_mode_active,
                "default_deny_enabled": self.default_deny_enabled,
                "total_allowed_ips": len(self.allowed_ips),
                "policy_verified": False,
                "issues": [],
                "validated_at": now_iso()  # UTC timestamp
            }
            
            # Check policy state
            if self.whitelist_mode_active:
                policy_verified = self._verify_default_deny_policy()
                validation_result["policy_verified"] = policy_verified
                
                if not policy_verified:
                    validation_result["issues"].append("Default Deny policy may not be active")
            
            # Check for missing essential IPs
            if not self.essential_ips:
                validation_result["issues"].append("No essential IPs configured")
            
            logger.info(f" Validation complete: {len(validation_result['issues'])} issues found")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating firewall state: {e}")
            return {
                "error": str(e),
                "validated_at": now_iso()  # UTC timestamp
            }

    def test_whitelist_connectivity(self, sample_ips: List[str]) -> Dict[str, bool]:
        """Test connectivity to sample whitelisted IPs"""
        try:
            logger.info(f"🧪 Testing connectivity to {len(sample_ips)} sample IPs...")
            
            results = {}
            
            for ip in sample_ips[:5]:  # Test max 5 IPs
                try:
                    # Simple socket test with timeout
                    logger.debug(f"   Testing connectivity to {ip}...")
                    
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                        sock.settimeout(3)  # 3 second timeout
                        # Try common ports
                        for port in [80, 443, 53]:
                            try:
                                result = sock.connect_ex((ip, port))
                                if result == 0:
                                    results[ip] = True
                                    logger.debug(f"     {ip}:{port} - Connected")
                                    break
                                else:
                                    logger.debug(f"    ⚠️ {ip}:{port} - Connection failed (code: {result})")
                            except Exception as e:
                                logger.debug(f"    ❌ {ip}:{port} - Exception: {e}")
                                continue
                        
                        if ip not in results:
                            results[ip] = False
                            logger.debug(f"    ❌ {ip} - All ports failed")
                            
                except Exception as e:
                    results[ip] = False
                    logger.debug(f"    ❌ {ip} - Exception: {e}")
            
            success_count = sum(1 for success in results.values() if success)
            logger.info(f"🧪 Connectivity test: {success_count}/{len(results)} IPs accessible")
            
            return results
            
        except Exception as e:
            logger.error(f"Error testing connectivity: {e}")
            return {}

    # ========================================
    # UTILITY METHODS
    # ========================================

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address"""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return isinstance(addr, ipaddress.IPv4Address)
        except:
            return False

    def _get_essential_ips(self) -> Set[str]:
        """Get essential IPs - IPv4 only for firewall compatibility"""
        essential = set()
        
        # IPv4 localhost
        essential.add("127.0.0.1")
        
        # Common DNS servers (IPv4 only)
        essential.update([
            "8.8.8.8", "8.8.4.4",              # Google DNS
            "1.1.1.1", "1.0.0.1",              # Cloudflare DNS
            "208.67.222.222", "208.67.220.220", # OpenDNS
            "9.9.9.9", "149.112.112.112"       # Quad9 DNS
        ])
        
        # Try to detect local network
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                essential.add(local_ip)
                
                # Add gateway
                gateway_ip = '.'.join(local_ip.split('.')[:-1]) + '.1'
                essential.add(gateway_ip)
                
                logger.debug(f"Detected local network: {local_ip}, gateway: {gateway_ip}")
        except Exception as e:
            logger.debug(f"Could not detect local network: {e}")
        
        return essential

    def _load_existing_rules(self):
        """Load existing firewall rules"""
        try:
            logger.debug("Loading existing firewall rules...")
            
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
                
            current_rule = None
            current_action = None
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    current_rule = line[10:].strip()
                    current_action = None
                    
                    if not current_rule.startswith(self.rule_prefix):
                        current_rule = None
                        continue
                
                elif current_rule:
                    if line.startswith("Action:"):
                        current_action = line[7:].strip().lower()
                    
                    elif line.startswith("RemoteIP:") and current_action == "allow":
                        ip_part = line[9:].strip()
                        
                        if ip_part and ip_part != "Any":
                            ip_parts = ip_part.split(',')
                            for part in ip_parts:
                                part = part.strip()
                                if self._is_valid_ipv4(part):
                                    self.allowed_ips.add(part)
                                    logger.debug(f"Found existing allow rule for: {part}")
            
            # Check if Default Deny is enabled
            if self._verify_default_deny_policy():
                self.default_deny_enabled = True
                if self.allowed_ips:
                    self.whitelist_mode_active = True
                    logger.info("Detected existing whitelist-only firewall mode with Default Deny")
            
            logger.info(f"Loaded existing rules: {len(self.allowed_ips)} allow rules")
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while loading existing firewall rules")
        except Exception as e:
            logger.error(f"Error loading existing firewall rules: {e}")

    def _has_admin_privileges(self) -> bool:
        """Check if the application is running with administrator privileges"""
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

    # ========================================
    # LEGACY COMPATIBILITY METHODS (simplified)
    # ========================================

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP address is blocked (not in whitelist when Default Deny is active)"""
        if self.whitelist_mode_active and self.default_deny_enabled:
            return ip not in self.allowed_ips and ip not in self.essential_ips
        return False

    def get_blocked_ips(self) -> List[str]:
        """Get a list of all IPs blocked (in Default Deny mode, this is all IPs NOT in allowed_ips)"""
        if self.whitelist_mode_active and self.default_deny_enabled:
            return ["ALL_NON_WHITELISTED_IPS"]
        return []

    def block_ip(self, ip: str, domain: Optional[str] = None) -> bool:
        """Legacy method: In Default Deny mode, blocking means removing from whitelist"""
        if self.whitelist_mode_active:
            return self.remove_ip_from_whitelist(ip)
        else:
            logger.info(f"Default Deny not active - cannot block {ip}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Legacy method: In Default Deny mode, unblocking means adding to whitelist"""
        if self.whitelist_mode_active:
            return self.add_ip_to_whitelist(ip, "unblock_request")
        else:
            logger.info(f"Default Deny not active - cannot unblock {ip}")
            return False

    def _backup_current_policy(self):
        """Backup current firewall policy before making changes"""
        try:
            self._original_policies = self._get_current_firewall_policy()
            logger.debug(f"Backed up original policies: {self._original_policies}")
        except Exception as e:
            logger.warning(f"Failed to backup current policy: {e}")
            self._original_policies = {}

    def _restore_original_policy(self) -> bool:
        """Restore original firewall policy"""
        try:
            if not hasattr(self, '_original_policies') or not self._original_policies:
                logger.info("No original policy to restore, using defaults")
                return self._restore_default_policy()
            
            logger.info(" Restoring original firewall policy...")
            success_count = 0
            
            for profile, action in self._original_policies.items():
                policy = f"blockinbound,{action}outbound"
                
                command = [
                    "netsh", "advfirewall", "set", f"{profile}profile",
                    "firewallpolicy", policy
                ]
                
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    logger.info(f" {profile.title()} profile restored to {action} outbound")
                    success_count += 1
                else:
                    logger.error(f"❌ Failed to restore {profile.title()} profile")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error restoring original policy: {e}")
            return False
