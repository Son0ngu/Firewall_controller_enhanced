import logging
import subprocess
from typing import Dict, Optional

from .provider import FirewallProvider, get_write_provider
from .utils import FirewallUtils

logger = logging.getLogger("firewall.policy")

class PolicyManager:
    
    def __init__(self, write_provider: Optional[FirewallProvider] = None):
        self._original_policies: Dict[str, str] = {}
        self.default_deny_enabled = False
        self._write_provider = write_provider or get_write_provider()
    
    def get_current_policy(self) -> Dict[str, str]:
        # Get current firewall policy for all profiles.
        try:
            result = FirewallUtils.run_netsh_command(
                ["advfirewall", "show", "allprofiles"]
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to get firewall policy: {result.stderr}")
                return {}
            
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
                elif current_profile:
                    lower = line.lower()
                    # Windows versions/local netsh formats differ here. Some
                    # print "Outbound connections: Block", while others print
                    # "Firewall Policy BlockInbound,BlockOutbound".
                    if "blockoutbound" in lower:
                        policies[current_profile] = "block"
                    elif "allowoutbound" in lower:
                        policies[current_profile] = "allow"
                    elif "outbound" in lower and "block" in lower:
                        policies[current_profile] = "block"
                    elif "outbound" in lower and "allow" in lower:
                        policies[current_profile] = "allow"
            
            return policies
            
        except Exception as e:
            logger.error(f"Error getting current firewall policy: {e}")
            return {}
    
    def backup_current_policy(self):
        try:
            self._original_policies = self.get_current_policy()
            logger.debug(f"Backed up original policies: {self._original_policies}")
        except Exception as e:
            logger.warning(f"Failed to backup current policy: {e}")
            self._original_policies = {}
    
    def enable_default_deny(self) -> bool:
        try:
            logger.info("Enabling Windows Firewall Default Deny policy...")
            
            current_policies = self.get_current_policy()
            logger.debug(f"Current firewall policies: {current_policies}")
            
            profiles = ["domain", "private", "public"]
            success_count = 0
            
            for profile in profiles:
                if current_policies.get(profile) == "block":
                    logger.info(f"{profile.title()} profile already set to block outbound")
                    success_count += 1
                    continue
                
                if self._write_provider.set_profile_outbound_policy(profile, "block"):
                    logger.info(f"{profile.title()} profile set to Default Deny")
                    success_count += 1
                else:
                    logger.error(f"Failed to set {profile.title()} profile")
            
            # Require ALL profiles to be set. A partial result can leave the
            # active network profile allowing outbound, so treating it as
            # success would be fail-open.
            if success_count == len(profiles):
                if self.verify_default_deny():
                    self.default_deny_enabled = True
                    logger.info("Default Deny policy enabled successfully")
                    return True
                # Verification failed → do NOT claim deny is active.
                logger.error("Default Deny verification failed - not all profiles block outbound")
                self.default_deny_enabled = False
                return False
            else:
                logger.error(f"Failed to set all firewall profiles ({success_count}/{len(profiles)})")
                self.default_deny_enabled = False
                return False
                
        except Exception as e:
            logger.error(f"Error enabling Default Deny policy: {e}")
            return False
    
    def verify_default_deny(self) -> bool:
        # Verify per-profile via get_current_policy() (parses outbound action
        # for every profile) instead of counting the word 'block' in raw netsh
        # output. Default Deny is only "verified" when ALL profiles block
        # outbound.
        try:
            policies = self.get_current_policy()
            profiles = ["domain", "private", "public"]
            return all(policies.get(profile) == "block" for profile in profiles)
        except Exception as e:
            logger.warning(f"Error verifying Default Deny policy: {e}")
            return False
    
    def restore_original_policy(self) -> bool:
        try:
            if not self._original_policies:
                logger.info("No original policy to restore, using defaults")
                return self.restore_default_policy()
            
            logger.info("Restoring original firewall policy...")
            success_count = 0
            
            for profile, action in self._original_policies.items():
                if self._write_provider.set_profile_outbound_policy(profile, action):
                    logger.info(f"{profile.title()} profile restored to {action} outbound")
                    success_count += 1
                else:
                    logger.error(f"Failed to restore {profile.title()} profile")
            
            if success_count > 0:
                self.default_deny_enabled = False

            # Require ALL profiles restored (consistent with
            # restore_default_policy). A partial restore returns False so the
            # caller falls back to restore_default_policy() rather than leaving
            # a profile stuck in block-outbound.
            return success_count == len(self._original_policies)

        except Exception as e:
            logger.error(f"Error restoring original policy: {e}")
            return False
    
    def restore_default_policy(self) -> bool:
        try:
            logger.info("Restoring Windows Firewall to default policy...")
            
            profiles = ["domain", "private", "public"]
            success_count = 0
            
            for profile in profiles:
                if self._write_provider.set_profile_outbound_policy(profile, "allow"):
                    logger.info(f"{profile.title()} profile restored to default")
                    success_count += 1
                else:
                    logger.error(f"Failed to restore {profile.title()} profile")
            
            if success_count > 0:
                self.default_deny_enabled = False
            
            return success_count == len(profiles)
            
        except Exception as e:
            logger.error(f"Error restoring default policy: {e}")
            return False

    def restore_policies(self, policies: Dict[str, str]) -> bool:
        """Restore explicit profile outbound policies from a snapshot."""
        try:
            success_count = 0
            for profile, action in (policies or {}).items():
                if action not in ("allow", "block"):
                    continue
                if self._write_provider.set_profile_outbound_policy(profile, action):
                    logger.debug("Restored %s profile to %s", profile, action)
                    success_count += 1
                else:
                    logger.warning("Failed to restore %s profile", profile)
            if success_count > 0:
                self.default_deny_enabled = False
            return success_count > 0
        except Exception as e:
            logger.error(f"Error restoring explicit policies: {e}")
            return False
