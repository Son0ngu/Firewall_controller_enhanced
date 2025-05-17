import logging
import subprocess
import re
import time
from typing import Dict, List, Optional, Set

# Configure logging
logger = logging.getLogger("firewall_manager")

class FirewallManager:
    """
    Manages Windows Firewall rules to block unauthorized connections.
    Uses netsh advfirewall commands through subprocess to interact with Windows Firewall.
    """
    
    def __init__(self, rule_prefix: str = "FWController_Block_"):
        """
        Initialize the firewall manager.
        
        Args:
            rule_prefix: Prefix to use for all firewall rules created by this instance
        """
        self.rule_prefix = rule_prefix
        self.blocked_ips: Set[str] = set()
        
        # Check if we have admin privileges (required for firewall operations)
        if not self._has_admin_privileges():
            logger.warning("Firewall operations require administrator privileges")
        
        # Initialize by loading existing rules with our prefix
        self._load_existing_rules()
    
    def block_ip(self, ip: str, domain: Optional[str] = None) -> bool:
        """
        Block an IP address by creating a firewall rule.
        
        Args:
            ip: The IP address to block
            domain: Associated domain name (used in rule description)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        # If already blocked, consider it a success
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} is already blocked")
            return True
            
        # Create rule name with timestamp to ensure uniqueness
        timestamp = int(time.time())
        rule_name = f"{self.rule_prefix}{ip.replace('.', '_')}_{timestamp}"
        
        # Build description
        if domain:
            description = f"Blocked connection to {domain} ({ip})"
        else:
            description = f"Blocked connection to {ip}"
            
        try:
            # Create the firewall rule using netsh
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
                "enable=yes",
                f"description={description}"
            ]
            
            # Execute the command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode == 0:
                # Success
                self.blocked_ips.add(ip)
                logger.info(f"Successfully blocked IP: {ip} with rule: {rule_name}")
                return True
            else:
                # Command failed
                logger.error(f"Failed to block IP {ip}. Error: {result.stderr.strip()}")
                return False
                
        except Exception as e:
            logger.error(f"Error blocking IP {ip}: {str(e)}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address by removing associated firewall rules.
        
        Args:
            ip: The IP address to unblock
            
        Returns:
            bool: True if at least one rule was removed, False otherwise
        """
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        # If not in our blocked list, nothing to do
        if ip not in self.blocked_ips:
            logger.debug(f"IP {ip} is not in our blocked list")
            return False
            
        try:
            # Find all rules related to this IP
            rules = self._find_rules_for_ip(ip)
            
            if not rules:
                logger.warning(f"No firewall rules found for IP {ip}")
                return False
                
            success = False
            
            # Delete each rule
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
        """
        Check if an IP address is blocked.
        
        Args:
            ip: The IP address to check
            
        Returns:
            bool: True if the IP is blocked, False otherwise
        """
        return ip in self.blocked_ips
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get a list of all IPs blocked by this firewall manager.
        
        Returns:
            List[str]: List of blocked IP addresses
        """
        return list(self.blocked_ips)
    
    def clear_all_rules(self) -> bool:
        """
        Remove all firewall rules created by this firewall manager.
        Useful for cleanup on application exit.
        
        Returns:
            bool: True if successful, False if errors occurred
        """
        try:
            # Get all rules with our prefix
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                f"name={self.rule_prefix}*", "verbose"
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
                
            # Parse the output to extract rule names
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
                
            # Delete each rule
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
                    logger.info(f"Successfully removed rule: {rule_name}")
                else:
                    logger.error(f"Failed to remove rule {rule_name}. Error: {result.stderr.strip()}")
                    success = False
            
            # Clear the blocked IPs set
            if success:
                self.blocked_ips.clear()
                
            return success
                
        except Exception as e:
            logger.error(f"Error clearing firewall rules: {str(e)}")
            return False
    
    def _load_existing_rules(self):
        """
        Load existing firewall rules that match our prefix.
        Used during initialization to sync our state with the firewall.
        """
        try:
            # Get all rules with our prefix
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                f"name={self.rule_prefix}*", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return
                
            # Parse the output to extract IPs
            current_rule = None
            current_ip = None
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    current_rule = line[10:].strip()
                    current_ip = None
                    
                elif line.startswith("RemoteIP:"):
                    ip_part = line[9:].strip()
                    
                    # Extract IP from the RemoteIP field
                    if ip_part and ip_part != "Any":
                        # Handle multiple IPs or ranges
                        ip_parts = ip_part.split(',')
                        for part in ip_parts:
                            part = part.strip()
                            if self._is_valid_ip(part):
                                current_ip = part
                                self.blocked_ips.add(part)
                                logger.debug(f"Found existing block for IP: {part} in rule: {current_rule}")
            
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from existing firewall rules")
            
        except Exception as e:
            logger.error(f"Error loading existing firewall rules: {str(e)}")
    
    def _find_rules_for_ip(self, ip: str) -> List[str]:
        """
        Find all firewall rules that block the given IP.
        
        Args:
            ip: The IP address to find rules for
            
        Returns:
            List[str]: List of rule names
        """
        rule_names = []
        
        try:
            # Get all rules with our prefix
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                f"name={self.rule_prefix}*", "verbose"
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
                
            # Parse the output to find rules matching this IP
            current_rule = None
            current_ip = None
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    current_rule = line[10:].strip()
                    current_ip = None
                    
                elif line.startswith("RemoteIP:"):
                    ip_part = line[9:].strip()
                    
                    # Check if this rule blocks our IP
                    if ip_part and ip_part != "Any":
                        ip_parts = ip_part.split(',')
                        for part in ip_parts:
                            part = part.strip()
                            if part == ip:
                                rule_names.append(current_rule)
                                break
            
            return rule_names
            
        except Exception as e:
            logger.error(f"Error finding rules for IP {ip}: {str(e)}")
            return rule_names
    
    def _has_admin_privileges(self) -> bool:
        """
        Check if the application is running with administrator privileges.
        
        Returns:
            bool: True if running as admin, False otherwise
        """
        try:
            # Try to run a simple firewall command that requires admin rights
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
        """
        Validate if a string is a valid IPv4 address.
        
        Args:
            ip: The string to check
            
        Returns:
            bool: True if the string is a valid IPv4 address
        """
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        
        if not match:
            return False
            
        # Validate each octet
        for i in range(1, 5):
            octet = int(match.group(i))
            if octet < 0 or octet > 255:
                return False
                
        return True


# Example usage (for testing)
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create firewall manager
    firewall = FirewallManager()
    
    # Test blocking and unblocking
    test_ip = "93.184.216.34"  # example.com IP
    test_domain = "example.com"
    
    print(f"\nBlocking IP {test_ip} ({test_domain})...")
    if firewall.block_ip(test_ip, test_domain):
        print(f"Successfully blocked {test_ip}")
    else:
        print(f"Failed to block {test_ip}")
    
    # Check if blocked
    print(f"\nChecking if {test_ip} is blocked...")
    if firewall.is_blocked(test_ip):
        print(f"{test_ip} is blocked")
    else:
        print(f"{test_ip} is not blocked")
    
    # List all blocked IPs
    print("\nAll blocked IPs:")
    for ip in firewall.get_blocked_ips():
        print(f"- {ip}")
    
    # Unblock the IP
    print(f"\nUnblocking IP {test_ip}...")
    if firewall.unblock_ip(test_ip):
        print(f"Successfully unblocked {test_ip}")
    else:
        print(f"Failed to unblock {test_ip}")
    
    # Clear all rules
    print("\nClearing all firewall rules...")
    if firewall.clear_all_rules():
        print("Successfully cleared all rules")
    else:
        print("Failed to clear all rules")