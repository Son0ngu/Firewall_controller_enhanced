"""
Configuration module for the Firewall Controller Agent.

✅ UPDATED: Sử dụng time_utils cho consistent time management

This module loads and provides access to all configuration parameters needed by the agent.
Configuration can be sourced from environment variables, a configuration file, or defaults.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# ✅ Import time_utils thay vì các time modules khác
from time_utils import now, now_iso, now_server_compatible

# Cấu hình logging cho chính module cấu hình
logger = logging.getLogger("config")

# Các hằng số định nghĩa đường dẫn file cấu hình
DEFAULT_CONFIG_FILE = "agent_config.json"
CONFIG_PATHS = [
    Path(DEFAULT_CONFIG_FILE),
    Path.home() / ".firewall-controller" / DEFAULT_CONFIG_FILE,
    Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "FirewallController" / DEFAULT_CONFIG_FILE,
]

# Cấu hình mặc định cho toàn bộ ứng dụng
DEFAULT_CONFIG = {
    # Cấu hình kết nối đến server
    "server": {
        "urls": [
            "https://firewall-controller.onrender.com",
            "http://localhost:5000"
        ],
        "url": "https://firewall-controller.onrender.com",
        "connect_timeout": 15,
        "read_timeout": 45,
        "retry_interval": 60,
        "max_retries": 5,
    },
    
    # Cấu hình xác thực
    "auth": {
        "api_key": "",
        "auth_method": "none",
        "jwt_refresh_interval": 3600,
    },
    
    # Cấu hình whitelist
    "whitelist": {
        "auto_sync": True,
        "sync_on_startup": True,
        "update_interval": 60,
        "retry_interval": 30,
        "max_retries": 5,
        "timeout": 30,
        "auto_sync_firewall": True,
        "resolve_ips_on_startup": True,
        "ip_cache_ttl": 300,
        "ip_refresh_interval": 300,
    },
    
    # Cấu hình bắt gói tin mạng
    "packet_capture": {
        "engine": "scapy",
        "filter": "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)",
        "buffer_size": 4096,
        "packet_limit": 0,
        "interfaces": [],
        "snaplen": 1500,
    },
    
    # Cấu hình ghi log
    "logging": {
        "level": "INFO",
        "file": "agent.log",
        "max_size": 10485760,
        "backup_count": 5,
        "log_to_console": True,
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        
        "sender": {
            "enabled": True,
            "batch_size": 100,
            "max_queue_size": 1000,
            "send_interval": 30,
            "failures_before_warn": 3,
        }
    },
    
    # Cấu hình tường lửa
    "firewall": {
        "enabled": True,
        "mode": "whitelist_only",
        "rule_prefix": "FirewallController",
        "cleanup_on_exit": True,
        "create_allow_rules": True,
        "create_default_block": True,
        "allow_essential_ips": True,
        "allow_private_networks": False,
        "rule_priority_offset": 100,
    },
    
    # Cấu hình heartbeat
    "heartbeat": {
        "enabled": True,
        "interval": 20,
        "timeout": 10,
        "retry_interval": 5,
        "max_failures": 3
    },
    
    # Cấu hình chung
    "general": {
        "agent_name": "",
        "startup_delay": 0,
        "check_admin": True,
        "debug": False,  # ✅ ADD: Debug flag
    }
}


def load_config() -> Dict[str, Any]:
    """
    ✅ UPDATED: Load configuration với time_utils logging
    
    Load configuration from multiple sources, with the following precedence:
    1. Environment variables
    2. Configuration file
    3. Default values
    
    Returns:
        Dict: Complete configuration dictionary
    """
    load_start_time = now()  # ✅ Use time_utils
    
    logger.info(f"🔧 Loading configuration at {now_server_compatible()}")  # ✅ Use time_utils
    
    # Khởi đầu với cấu hình mặc định
    config = DEFAULT_CONFIG.copy()
    
    # Tải cấu hình từ file nếu có
    file_config = _load_from_file()
    if file_config:
        _deep_update(config, file_config)
    
    # Ghi đè bằng các biến môi trường
    env_config = _load_from_env()
    if env_config:
        _deep_update(config, env_config)
    
    # ✅ Add configuration metadata với time_utils
    config["_metadata"] = {
        "loaded_at": now_iso(),           # ✅ Use time_utils
        "loaded_timestamp": now(),        # ✅ Use time_utils  
        "load_duration": now() - load_start_time,  # ✅ Calculate load time
        "config_source": _get_config_source(file_config, env_config)
    }
    
    # Xác thực cấu hình cuối cùng
    _validate_config(config)
    
    load_duration = now() - load_start_time  # ✅ Use time_utils
    logger.info(f"✅ Configuration loaded successfully in {load_duration:.3f}s")
    
    return config


def _load_from_file() -> Optional[Dict[str, Any]]:
    """
    ✅ UPDATED: Load from file với time_utils logging
    
    Returns:
        Optional[Dict]: Configuration from file, or None if no file found
    """
    # Kiểm tra đường dẫn cấu hình từ biến môi trường trước tiên
    env_path = os.environ.get("FIREWALL_CONTROLLER_CONFIG")
    if env_path:
        config_paths = [Path(env_path)]
    else:
        config_paths = CONFIG_PATHS
    
    # Thử từng đường dẫn
    for path in config_paths:
        try:
            if path.exists():
                file_load_start = now()  # ✅ Use time_utils
                logger.info(f"📄 Loading configuration from {path}")
                
                with open(path, "r") as f:
                    config = json.load(f)
                
                load_time = now() - file_load_start  # ✅ Use time_utils
                logger.info(f"✅ Config file loaded in {load_time:.3f}s")
                return config
                
        except Exception as e:
            logger.warning(f"❌ Error reading config file {path}: {str(e)}")
    
    logger.info("📄 No configuration file found, using defaults")
    return None


def _load_from_env() -> Dict[str, Any]:
    """
    ✅ UPDATED: Load from environment với basic logging
    
    Returns:
        Dict: Configuration from environment variables
    """
    config = {}
    prefix = "FC_"
    env_count = 0
    
    # Duyệt qua tất cả biến môi trường
    for key, value in os.environ.items():
        if key.startswith(prefix):
            env_count += 1
            # Bỏ tiền tố và phân tách theo dấu gạch dưới kép
            key_parts = key[len(prefix):].lower().split("__")
            
            # Xây dựng cấu trúc dict lồng nhau
            current = config
            for part in key_parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            # Gán giá trị cho key cuối cùng
            current[key_parts[-1]] = _convert_value(value)
    
    if env_count > 0:
        logger.info(f"🌍 Loaded {env_count} environment variables")
    
    return config


def _convert_value(value: str) -> Any:
    """Convert string values from environment variables to appropriate types"""
    # Boolean
    if value.lower() in ["true", "yes", "1"]:
        return True
    elif value.lower() in ["false", "no", "0"]:
        return False
    # None/null
    elif value.lower() in ["none", "null"]:
        return None
    # Số nguyên
    elif value.isdigit():
        return int(value)
    # Số thực
    elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
        return float(value)
    else:
        # Thử phân tích chuỗi như JSON
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value


def _deep_update(base_dict: Dict, update_dict: Dict) -> None:
    """Recursively update a dictionary with another dictionary"""
    for key, value in update_dict.items():
        if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
            _deep_update(base_dict[key], value)
        else:
            base_dict[key] = value


def _validate_config(config: Dict) -> None:
    """
    ✅ UPDATED: Enhanced validation với time_utils logging
    """
    validation_start = now()  # ✅ Use time_utils
    validation_issues = []
    
    # Validate server URL
    if not config["server"]["url"]:
        validation_issues.append("Server URL not configured")
    
    # Validate firewall mode
    valid_modes = ["block", "warn", "monitor", "whitelist_only"]
    if config["firewall"]["mode"] not in valid_modes:
        validation_issues.append(f"Invalid firewall mode: {config['firewall']['mode']}")
        config["firewall"]["mode"] = "monitor"
    
    # Validate whitelist_only mode requirements
    if config["firewall"]["mode"] == "whitelist_only":
        if not config["firewall"]["enabled"]:
            validation_issues.append("Whitelist-only mode requires firewall enabled")
            config["firewall"]["enabled"] = True
        
        if not _has_admin_privileges():
            validation_issues.append("Whitelist-only mode requires admin privileges")
            config["firewall"]["mode"] = "monitor"
            config["firewall"]["enabled"] = False
    
    # ✅ Add validation metadata
    config["_metadata"]["validation"] = {
        "validated_at": now_iso(),        # ✅ Use time_utils
        "validation_duration": now() - validation_start,  # ✅ Use time_utils
        "issues_found": len(validation_issues),
        "issues": validation_issues
    }
    
    # Log validation results
    if validation_issues:
        for issue in validation_issues:
            logger.warning(f"⚠️ Config validation: {issue}")
    else:
        logger.info("✅ Configuration validation passed")


def get_config() -> Dict[str, Any]:
    """
    ✅ UPDATED: Get config với caching info
    
    Returns:
        Dict: Complete configuration dictionary
    """
    global _config
    if _config is None:
        _config = load_config()
    else:
        # ✅ Update last accessed time
        _config["_metadata"]["last_accessed"] = now_iso()  # ✅ Use time_utils
    
    return _config


def save_config(config: Dict[str, Any], path: Optional[str] = None) -> bool:
    """
    ✅ UPDATED: Save config với time_utils timestamps
    
    Args:
        config: Configuration dictionary to save
        path: Path to save to, defaults to the first path in CONFIG_PATHS
        
    Returns:
        bool: True if successful, False otherwise
    """
    save_start_time = now()  # ✅ Use time_utils
    
    if path is None:
        path = os.environ.get("FIREWALL_CONTROLLER_CONFIG", str(CONFIG_PATHS[0]))
    
    try:
        # Đảm bảo thư mục tồn tại
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # ✅ Add save metadata
        config_to_save = config.copy()
        config_to_save["_metadata"]["saved_at"] = now_iso()      # ✅ Use time_utils
        config_to_save["_metadata"]["saved_timestamp"] = now()   # ✅ Use time_utils
        
        # Ghi file cấu hình
        with open(path, "w") as f:
            json.dump(config_to_save, f, indent=2)
        
        save_duration = now() - save_start_time  # ✅ Use time_utils
        logger.info(f"✅ Configuration saved to {path} in {save_duration:.3f}s")
        return True
        
    except Exception as e:
        save_duration = now() - save_start_time  # ✅ Use time_utils
        logger.error(f"❌ Error saving configuration to {path} after {save_duration:.3f}s: {str(e)}")
        return False


def get_default_config() -> Dict[str, Any]:
    """
    ✅ UPDATED: Default configuration với time_utils metadata
    """
    # Auto-detect firewall mode based on admin privileges
    firewall_mode = _detect_optimal_firewall_mode()
    firewall_enabled = _has_admin_privileges()
    
    config = {
        # Server configuration
        "server": {
            "urls": [
                "https://firewall-controller.onrender.com",
                "http://localhost:5000"
            ],
            "url": "https://firewall-controller.onrender.com",
            "connect_timeout": 15,
            "read_timeout": 45,
            "retry_interval": 60,
            "max_retries": 5,
        },
        
        # Auth configuration
        "auth": {
            "api_key": "",
            "auth_method": "none",
            "jwt_refresh_interval": 3600,
        },
        
        # Whitelist configuration
        "whitelist": {
            "auto_sync": True,
            "sync_on_startup": True,
            "update_interval": 300,
            "retry_interval": 60,
            "max_retries": 3,
            "timeout": 30,
            "auto_sync_firewall": firewall_enabled,
            "resolve_ips_on_startup": firewall_enabled,
            "ip_cache_ttl": 300,
            "ip_refresh_interval": 600,
            "require_server_domains": True,
            "allow_empty_whitelist": False
        },
        
        # Packet capture configuration  
        "packet_capture": {
            "engine": "scapy",
            "filter": "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)",
            "buffer_size": 4096,
            "packet_limit": 0,
            "interfaces": [],
            "snaplen": 1500,
        },
        
        # Logging configuration
        "logging": {
            "level": "INFO",
            "file": "agent.log", 
            "max_size": 10485760,
            "backup_count": 5,
            "log_to_console": True,
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            
            "sender": {
                "enabled": True,
                "batch_size": 100,
                "max_queue_size": 1000,
                "send_interval": 30,
                "failures_before_warn": 3,
            }
        },
        
        # Auto-detected firewall configuration
        "firewall": {
            "enabled": firewall_enabled,
            "mode": firewall_mode,
            "rule_prefix": "FirewallController",
            "cleanup_on_exit": firewall_enabled,
            "create_allow_rules": firewall_enabled,
            "create_default_block": firewall_enabled,
            "allow_essential_ips": True,
            "allow_private_networks": False,
            "rule_priority_offset": 100,
        },
        
        # Heartbeat configuration
        "heartbeat": {
            "enabled": True,
            "interval": 20,
            "timeout": 10,
            "retry_interval": 5,
            "max_failures": 3
        },
        
        # General configuration
        "general": {
            "agent_name": "",
            "startup_delay": 0,
            "check_admin": False,
            "debug": False,
        }
    }
    
    # ✅ Add creation metadata
    config["_metadata"] = {
        "created_at": now_iso(),          # ✅ Use time_utils
        "created_timestamp": now(),       # ✅ Use time_utils
        "config_type": "default",
        "admin_privileges": firewall_enabled,
        "detected_mode": firewall_mode
    }
    
    return config


def _detect_optimal_firewall_mode() -> str:
    """Tự động phát hiện firewall mode tối ưu dựa trên quyền admin"""
    if _has_admin_privileges():
        return "whitelist_only"
    else:
        return "monitor"


def _has_admin_privileges() -> bool:
    """Kiểm tra quyền administrator trên Windows"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        try:
            import subprocess
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.returncode == 0
        except Exception:
            return False


def _get_config_source(file_config: Optional[Dict], env_config: Dict) -> str:
    """
    ✅ NEW: Determine configuration source for metadata
    
    Args:
        file_config: Config loaded from file
        env_config: Config loaded from environment
        
    Returns:
        str: Configuration source description
    """
    sources = []
    
    if file_config:
        sources.append("file")
    if env_config:
        sources.append("environment")
    
    sources.append("defaults")
    
    return " + ".join(sources)


def get_config_info() -> Dict:
    """
    ✅ NEW: Get configuration metadata and info
    
    Returns:
        Dict: Configuration metadata
    """
    config = get_config()
    
    return {
        "current_time": now_server_compatible(),   # ✅ Use time_utils
        "config_metadata": config.get("_metadata", {}),
        "admin_privileges": _has_admin_privileges(),
        "optimal_mode": _detect_optimal_firewall_mode(),
        "config_file_paths": [str(p) for p in CONFIG_PATHS],
        "env_config_prefix": "FC_"
    }


# Khởi tạo biến cấu hình toàn cục
_config = None
