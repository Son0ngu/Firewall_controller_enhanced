import os
import sys
import logging
import subprocess
import ctypes
from typing import List, Dict, Any, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('utils')

def checkPrivileges() -> bool:
    """
    Check if the application is running with administrator privileges.
    
    Returns:
        bool: True if running with admin privileges, False otherwise
    """
    try:
        # Windows-specific check for admin rights
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # For non-Windows systems, check if running as root (uid 0)
            return os.geteuid() == 0
    except Exception as e:
        logger.error(f"Error checking privileges: {str(e)}")
        return False

def formatCommand(command_parts: List[str]) -> Union[List[str], str]:
    """
    Format command arguments for subprocess execution.
    
    Args:
        command_parts: List of command parts to format
        
    Returns:
        Properly formatted command suitable for subprocess execution
    """
    try:
        # Check if running on Windows
        if os.name == 'nt':
            # For Windows, join commands for shell=True usage
            # This handles spaces and special characters in paths
            if len(command_parts) > 0 and command_parts[0].lower() == "powershell":
                # Special handling for PowerShell commands
                if len(command_parts) > 2:
                    # Ensure PowerShell command is properly quoted
                    return command_parts
                else:
                    return " ".join(command_parts)
            else:
                return " ".join(command_parts)
        else:
            # For non-Windows systems, return list for subprocess
            return command_parts
    except Exception as e:
        logger.error(f"Error formatting command: {str(e)}")
        return command_parts

def loadConfig(config_file: str = "config.json") -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Dictionary containing configuration settings
    """
    import json
    
    try:
        config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', config_file)
        
        if not os.path.exists(config_path):
            logger.warning(f"Configuration file {config_path} not found. Using default settings.")
            return {}
            
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        logger.info(f"Configuration loaded from {config_path}")
        return config
        
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

def saveConfig(config: Dict[str, Any], config_file: str = "config.json") -> bool:
    """
    Save configuration to a JSON file.
    
    Args:
        config: Dictionary containing configuration settings
        config_file: Path to the configuration file
        
    Returns:
        bool: True if successful, False otherwise
    """
    import json
    
    try:
        # Ensure data directory exists
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
            
        config_path = os.path.join(data_dir, config_file)
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
            
        logger.info(f"Configuration saved to {config_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        return False