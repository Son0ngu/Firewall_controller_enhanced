import subprocess
import json
import os
import logging
from typing import Dict, List, Optional, Union, Any
import sys

# Import utility functions from utils module
from core.utils import formatCommand, checkPrivileges

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('firewall_rules')

class FirewallRule:
    """Class representing a Windows Firewall rule with its properties."""
    
    def __init__(self, name: str, direction: str = "in", action: str = "allow", 
                 protocol: str = "TCP", local_port: Optional[str] = None, 
                 remote_port: Optional[str] = None, program: Optional[str] = None,
                 enabled: bool = True, profile: str = "any", description: str = ""):
        self.name = name
        self.direction = direction.lower()
        self.action = action.lower()
        self.protocol = protocol.upper()
        self.local_port = local_port
        self.remote_port = remote_port
        self.program = program
        self.enabled = enabled
        self.profile = profile.lower()
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation."""
        return {
            'name': self.name,
            'direction': self.direction,
            'action': self.action,
            'protocol': self.protocol,
            'local_port': self.local_port,
            'remote_port': self.remote_port,
            'program': self.program,
            'enabled': self.enabled,
            'profile': self.profile,
            'description': self.description
        }


def add_rule(params: Dict[str, Any]) -> bool:
    """
    Add a new firewall rule to Windows Firewall.
    
    Args:
        params: Dictionary containing rule parameters
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not checkPrivileges():
        logger.error("Administrator privileges required to add firewall rules")
        return False
    
    try:
        # Create rule object from parameters
        rule = FirewallRule(
            name=params.get('name', ''),
            direction=params.get('direction', 'in'),
            action=params.get('action', 'allow'),
            protocol=params.get('protocol', 'TCP'),
            local_port=params.get('local_port'),
            remote_port=params.get('remote_port'),
            program=params.get('program'),
            enabled=params.get('enabled', True),
            profile=params.get('profile', 'any'),
            description=params.get('description', '')
        )
        
        # Construct PowerShell command
        cmd_parts = [
            "New-NetFirewallRule",
            f"-Name '{rule.name}'",
            f"-DisplayName '{rule.name}'",
            f"-Direction {rule.direction.capitalize()}",
            f"-Action {rule.action.capitalize()}",
            f"-Protocol {rule.protocol}"
        ]
        
        if rule.local_port:
            cmd_parts.append(f"-LocalPort {rule.local_port}")
        
        if rule.remote_port:
            cmd_parts.append(f"-RemotePort {rule.remote_port}")
            
        if rule.program:
            cmd_parts.append(f"-Program '{rule.program}'")
            
        if rule.profile != "any":
            cmd_parts.append(f"-Profile {rule.profile.capitalize()}")
            
        if rule.description:
            cmd_parts.append(f"-Description '{rule.description}'")
            
        cmd_parts.append(f"-Enabled {'True' if rule.enabled else 'False'}")
        
        ps_command = " ".join(cmd_parts)
        
        # Execute PowerShell command
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to add rule: {result.stderr}")
            return False
        
        logger.info(f"Successfully added firewall rule '{rule.name}'")
        return True
        
    except Exception as e:
        logger.error(f"Error adding firewall rule: {str(e)}")
        return False


def remove_rule(name: str) -> bool:
    """
    Remove a firewall rule by name.
    
    Args:
        name: Name of the rule to remove
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not checkPrivileges():
        logger.error("Administrator privileges required to remove firewall rules")
        return False
    
    try:
        ps_command = f"Remove-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue"
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to remove rule '{name}': {result.stderr}")
            return False
        
        logger.info(f"Successfully removed firewall rule '{name}'")
        return True
        
    except Exception as e:
        logger.error(f"Error removing firewall rule: {str(e)}")
        return False


def list_rules():
    """List all firewall rules."""
    try:
        # Better PowerShell command with proper formatting
        cmd = 'Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Direction,Action | ConvertTo-Json'
        result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True)

        if result.returncode != 0:
            logging.error(f"Error executing PowerShell: {result.stderr}")
            return []

        # Handle empty output
        if not result.stdout.strip():
            logging.warning("PowerShell returned empty output")
            return []

        # Debug output to see what we're getting
        logging.debug(f"PowerShell output: {result.stdout[:100]}...")

        rules = json.loads(result.stdout)

        # Handle case when a single rule is returned (not in an array)
        if isinstance(rules, dict):
            rules = [rules]

        return rules

    except json.JSONDecodeError as e:
        logging.error(f"Error parsing firewall rules: {e}")
        logging.debug(f"Raw output: {result.stdout[:200]}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error in list_rules: {e}")
        return []

def enable_rule(name: str, enable: bool = True) -> bool:
    """
    Enable or disable a firewall rule.
    
    Args:
        name: Name of the rule to enable/disable
        enable: True to enable, False to disable
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not checkPrivileges():
        logger.error("Administrator privileges required to modify firewall rules")
        return False
    
    try:
        action = "Enable" if enable else "Disable"
        ps_command = f"{action}-NetFirewallRule -Name '{name}'"
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            status = "enable" if enable else "disable"
            logger.error(f"Failed to {status} rule '{name}': {result.stderr}")
            return False
        
        status = "enabled" if enable else "disabled"
        logger.info(f"Successfully {status} firewall rule '{name}'")
        return True
        
    except Exception as e:
        logger.error(f"Error modifying firewall rule: {str(e)}")
        return False


def rule_exists(name: str) -> bool:
    """
    Check if a firewall rule exists.
    
    Args:
        name: Name of the rule to check
        
    Returns:
        bool: True if rule exists, False otherwise
    """
    try:
        ps_command = f"Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue"
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        # If the command succeeds and returns output, the rule exists
        return result.returncode == 0 and result.stdout.strip() != ""
        
    except Exception as e:
        logger.error(f"Error checking if rule exists: {str(e)}")
        return False