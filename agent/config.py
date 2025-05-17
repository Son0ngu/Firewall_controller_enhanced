"""
Configuration module for the Firewall Controller Agent.

This module loads and provides access to all configuration parameters needed by the agent.
Configuration can be sourced from environment variables, a configuration file, or defaults.

Sections:
- Server Connection: URLs and connection parameters
- Authentication: API keys and authentication settings
- Whitelist: Sources and update intervals
- Packet Capture: PyDivert and packet filtering settings
- Logging: Log levels, formats, and destinations
- Firewall: Blocking behavior and rule management
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Configure logging for the config module itself
logger = logging.getLogger("config")

# Constants for configuration file paths
DEFAULT_CONFIG_FILE = "agent_config.json"
CONFIG_PATHS = [
    # Current directory
    Path(DEFAULT_CONFIG_FILE),
    # User's home directory
    Path.home() / ".firewall-controller" / DEFAULT_CONFIG_FILE,
    # System-wide config (Windows)
    Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "FirewallController" / DEFAULT_CONFIG_FILE,
]

# Default configuration
DEFAULT_CONFIG = {
    # Server connection
    "server": {
        "url": "http://localhost:5000/api",
        "connect_timeout": 10,
        "read_timeout": 30,
        "retry_interval": 60,
        "max_retries": 5,
    },
    
    # Authentication
    "auth": {
        "api_key": "",
        "auth_method": "api_key",  # api_key, jwt, or none
        "jwt_refresh_interval": 3600,  # 1 hour
    },
    
    # Whitelist settings
    "whitelist": {
        "source": "both",  # file, server, or both
        "file": "whitelist.json",
        "update_interval": 3600,  # 1 hour
        "max_size": 100000,  # Maximum number of domains in whitelist
    },
    
    # Packet capture settings
    "packet_capture": {
        "engine": "pydivert",  # pydivert or scapy
        "filter": "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)",
        "buffer_size": 4096,
        "packet_limit": 0,  # 0 means no limit
        "interfaces": [],  # Empty list means all interfaces
        "snaplen": 1500,  # Maximum bytes to capture per packet
    },
    
    # Logging settings
    "logging": {
        "level": "INFO",
        "file": "agent.log",
        "max_size": 10485760,  # 10 MB
        "backup_count": 5,
        "log_to_console": True,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        
        # Log sender settings
        "sender": {
            "enabled": True,
            "batch_size": 100,
            "max_queue_size": 1000,
            "send_interval": 30,  # Seconds
            "failures_before_warn": 3,
        }
    },
    
    # Firewall settings
    "firewall": {
        "enabled": True,
        "mode": "block",  # block, warn, or monitor
        "rule_prefix": "FWController_Block_",
        "include_domain_in_rule": True,
        "cleanup_on_exit": True,
        "block_timeout": 0,  # 0 means indefinite, otherwise seconds until unblock
    },
    
    # General settings
    "general": {
        "agent_name": "",  # Auto-generated if empty
        "startup_delay": 0,  # Seconds to wait before starting
        "check_admin": True,  # Check for admin rights on startup
    }
}


def load_config() -> Dict[str, Any]:
    """
    Load configuration from multiple sources, with the following precedence:
    1. Environment variables
    2. Configuration file
    3. Default values
    
    Returns:
        Dict: Complete configuration dictionary
    """
    # Start with default config
    config = DEFAULT_CONFIG.copy()
    
    # Load from config file if available
    file_config = _load_from_file()
    if file_config:
        _deep_update(config, file_config)
    
    # Override with environment variables
    env_config = _load_from_env()
    if env_config:
        _deep_update(config, env_config)
    
    # Validate the configuration
    _validate_config(config)
    
    return config


def _load_from_file() -> Optional[Dict[str, Any]]:
    """
    Load configuration from the first available config file.
    
    Returns:
        Optional[Dict]: Configuration from file, or None if no file found
    """
    # Check config file path from environment variable first
    env_path = os.environ.get("FIREWALL_CONTROLLER_CONFIG")
    if env_path:
        config_paths = [Path(env_path)]
    else:
        config_paths = CONFIG_PATHS
    
    # Try each path
    for path in config_paths:
        try:
            if path.exists():
                logger.info(f"Loading configuration from {path}")
                with open(path, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"Error reading config file {path}: {str(e)}")
    
    return None


def _load_from_env() -> Dict[str, Any]:
    """
    Load configuration from environment variables.
    Environment variables should be prefixed with FC_ and use double underscore
    as separator for nested keys, e.g., FC_SERVER__URL for server.url.
    
    Returns:
        Dict: Configuration from environment variables
    """
    config = {}
    prefix = "FC_"
    
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Remove prefix and split by double underscore
            key_parts = key[len(prefix):].lower().split("__")
            
            # Build nested dictionary
            current = config
            for part in key_parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            # Set the value with appropriate type conversion
            current[key_parts[-1]] = _convert_value(value)
    
    return config


def _convert_value(value: str) -> Any:
    """
    Convert string values from environment variables to appropriate types.
    
    Args:
        value: String value to convert
        
    Returns:
        Converted value of appropriate type
    """
    # Try to convert to appropriate type
    if value.lower() in ["true", "yes", "1"]:
        return True
    elif value.lower() in ["false", "no", "0"]:
        return False
    elif value.lower() in ["none", "null"]:
        return None
    elif value.isdigit():
        return int(value)
    elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
        return float(value)
    else:
        # Try to parse as JSON (for lists, dicts)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value


def _deep_update(base_dict: Dict, update_dict: Dict) -> None:
    """
    Recursively update a dictionary with another dictionary.
    
    Args:
        base_dict: Dictionary to update
        update_dict: Dictionary with updates
    """
    for key, value in update_dict.items():
        if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
            _deep_update(base_dict[key], value)
        else:
            base_dict[key] = value


def _validate_config(config: Dict) -> None:
    """
    Validate the configuration.
    
    Args:
        config: Configuration dictionary to validate
    """
    # Required fields
    if not config["server"]["url"]:
        logger.warning("Server URL is not configured")
    
    # Authentication
    if config["auth"]["auth_method"] == "api_key" and not config["auth"]["api_key"]:
        logger.warning("API key authentication is enabled but no API key is provided")
    
    # Whitelist
    if config["whitelist"]["source"] in ["server", "both"] and not config["server"]["url"]:
        logger.warning("Whitelist source includes 'server' but server URL is not configured")
    
    # Packet capture
    if config["packet_capture"]["engine"] not in ["pydivert", "scapy"]:
        logger.warning(f"Unknown packet capture engine: {config['packet_capture']['engine']}")
    
    # Firewall
    if config["firewall"]["enabled"] and config["firewall"]["mode"] not in ["block", "warn", "monitor"]:
        logger.warning(f"Unknown firewall mode: {config['firewall']['mode']}")


def get_config() -> Dict[str, Any]:
    """
    Get the loaded configuration.
    
    Returns:
        Dict: Complete configuration dictionary
    """
    global _config
    if _config is None:
        _config = load_config()
    return _config


def save_config(config: Dict[str, Any], path: Optional[str] = None) -> bool:
    """
    Save configuration to a file.
    
    Args:
        config: Configuration dictionary to save
        path: Path to save to, defaults to the first path in CONFIG_PATHS
        
    Returns:
        bool: True if successful, False otherwise
    """
    if path is None:
        # Use the first config path
        path = os.environ.get("FIREWALL_CONTROLLER_CONFIG", str(CONFIG_PATHS[0]))
    
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Write config file
        with open(path, "w") as f:
            json.dump(config, f, indent=2)
        
        logger.info(f"Configuration saved to {path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration to {path}: {str(e)}")
        return False


# Initialize global configuration
_config = None


# Example usage
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load configuration
    config = get_config()
    
    # Print configuration
    print("Current configuration:")
    print(json.dumps(config, indent=2))
    
    # Example: Update and save configuration
    if len(sys.argv) > 1 and sys.argv[1] == "--save-example":
        config["server"]["url"] = "https://example.com/api"
        config["auth"]["api_key"] = "example_key"
        save_config(config, "example_config.json")
        print("Example configuration saved to example_config.json")