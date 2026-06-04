import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from shared.time_utils import now, now_iso
from .defaults import DEFAULT_CONFIG
from .paths import DEFAULT_CONFIG_FILE, get_config_read_paths
from .validator import validate_config
from shared.server_urls import normalize_server_url

logger = logging.getLogger("config.loader")

# Global config cache
_config: Optional[Dict[str, Any]] = None


def load_config() -> Dict[str, Any]:
    """
    Load configuration from multiple sources.
    
    Priority:
        1. Environment variables
        2. Configuration file
        3. Default values
    
    Returns:
        Complete configuration dictionary
    """
    load_start_time = now()
    
    logger.info(f"Loading configuration at {now_iso()}")
    
    # Start with defaults
    config = _deep_copy(DEFAULT_CONFIG)
    
    # Load from file
    file_config = _load_from_file()
    if file_config:
        _deep_update(config, file_config)
    
    # Override with environment variables
    env_config = _load_from_env()
    if env_config:
        _deep_update(config, env_config)
    
    # Add metadata
    config["_metadata"] = {
        "loaded_at": now_iso(),
        "loaded_timestamp": now(),
        "load_duration": now() - load_start_time,
        "config_source": _get_config_source(file_config, env_config)
    }

    # Ensure server URLs honor the explicitly configured primary URL
    # If a single server url is provided but the defaults injected a urls list,
    # align the list so runtime components (LogSender, API clients) use the user choice.
    server_cfg = config.get("server", {})
    primary_url = server_cfg.get("url")
    if primary_url:
        primary_url = normalize_server_url(primary_url)
        server_cfg["url"] = primary_url
        server_cfg["urls"] = [primary_url]
    elif server_cfg.get("urls"):
        normalized_urls = []
        for url in server_cfg.get("urls", []):
            normalized_url = normalize_server_url(url)
            if normalized_url:
                normalized_urls.append(normalized_url)
        server_cfg["urls"] = normalized_urls
    config["server"] = server_cfg
    
    # Validate configuration
    is_valid, errors, warnings = validate_config(config)
    
    config["_metadata"]["validation"] = {
        "is_valid": is_valid,
        "errors": errors,
        "warnings": warnings,
        "validated_at": now_iso()
    }
    
    # Log validation results
    for error in errors:
        logger.error(f"Config error: {error}")
    for warning in warnings:
        logger.warning(f"Config warning: {warning}")
    
    load_duration = now() - load_start_time
    logger.info(f"Configuration loaded in {load_duration:.3f}s")
    
    return config


def get_config() -> Dict[str, Any]:
    """
    Get cached configuration or load if not cached.
    
    Returns:
        Complete configuration dictionary
    """
    global _config
    
    if _config is None:
        _config = load_config()
    else:
        _config["_metadata"]["last_accessed"] = now_iso()
    
    return _config


def reload_config() -> Dict[str, Any]:
    """
    Force reload configuration from sources.
    
    Returns:
        Newly loaded configuration dictionary
    """
    global _config
    _config = None
    return get_config()


def _load_from_file() -> Optional[Dict[str, Any]]:
    """Load configuration from file (encrypted preferred, plaintext fallback)."""
    from .crypto import decrypt_config, migrate_plaintext_to_encrypted, ENCRYPTED_EXT

    for path in get_config_read_paths():
        try:
            enc_path = path.with_suffix(path.suffix + ENCRYPTED_EXT)

            # Try encrypted file first
            if enc_path.exists():
                logger.info(f"Loading encrypted config from {enc_path}")
                config = decrypt_config(path)
                if config is not None:
                    return config
                logger.warning(f"Failed to decrypt {enc_path}, trying plaintext")

            # Fallback to plaintext and auto-migrate
            if path.exists():
                logger.info(f"Loading plaintext config from {path}")
                with open(path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                # Auto-migrate to encrypted
                migrate_plaintext_to_encrypted(path)
                return config

        except Exception as e:
            logger.warning(f"Error reading config file {path}: {e}")

    logger.info("No configuration file found, using defaults")
    return None


def _load_from_env() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    config: Dict[str, Any] = {}
    prefix = "FC_"
    env_count = 0
    
    for key, value in os.environ.items():
        if key.startswith(prefix):
            env_count += 1
            
            # Remove prefix and split by double underscore
            key_parts = key[len(prefix):].lower().split("__")
            
            # Build nested dict structure
            current = config
            for part in key_parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            # Set value
            current[key_parts[-1]] = _convert_value(value)
    
    if env_count > 0:
        logger.info(f"Loaded {env_count} environment variables")
    
    return config


def _convert_value(value: str) -> Any:
    """Convert string value to appropriate type."""
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
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value

def _deep_copy(d: Dict) -> Dict:
    """Create a deep copy of a dictionary."""
    return json.loads(json.dumps(d))

def _deep_update(base_dict: Dict, update_dict: Dict) -> None:
    """Recursively update a dictionary with another dictionary."""
    for key, value in update_dict.items():
        if (key in base_dict and 
            isinstance(base_dict[key], dict) and 
            isinstance(value, dict)):
            _deep_update(base_dict[key], value)
        else:
            base_dict[key] = value


def _get_config_source(
    file_config: Optional[Dict], 
    env_config: Dict
) -> str:
    """Determine configuration source for metadata."""
    sources = []
    
    if file_config:
        sources.append("file")
    if env_config:
        sources.append("environment")
    
    sources.append("defaults")
    
    return " + ".join(sources)
