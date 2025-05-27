"""
Simplified Configuration for Firewall Controller Server.
No authentication, JWT, or complex features - perfect for small projects.
"""

import os
import secrets
from typing import Any

def get_env(key: str, default: Any = None) -> Any:
    """Get value from environment variable with proper type conversion."""
    value = os.environ.get(key, default)
    if isinstance(default, bool):
        return value.lower() in ('true', 'yes', '1', 't') if isinstance(value, str) else value
    elif isinstance(default, int):
        return int(value) if isinstance(value, str) and value.isdigit() else default
    elif isinstance(default, float):
        try:
            return float(value) if isinstance(value, str) else default
        except ValueError:
            return default
    return value

class Config:
    """Simplified configuration class."""
    
    # Flask core settings
    SECRET_KEY = get_env('SECRET_KEY', secrets.token_hex(32))
    DEBUG = get_env('DEBUG', True)
    TESTING = get_env('TESTING', False)
    
    # MongoDB Settings
    MONGO_URI = get_env('MONGO_URI', 'mongodb://localhost:27017/firewall_controller')
    MONGO_DBNAME = get_env('MONGO_DBNAME', 'Monitoring')
    
    # Logging settings
    LOG_LEVEL = get_env('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = get_env('LOG_FILE', 'server.log')
    
    # Socket.IO settings
    SOCKETIO_CORS_ALLOWED_ORIGINS = ["*"]
    SOCKETIO_ASYNC_MODE = get_env('SOCKETIO_ASYNC_MODE', 'eventlet')
    
    # Agent settings
    AGENT_WHITELIST_UPDATE_INTERVAL = int(get_env('AGENT_WHITELIST_UPDATE_INTERVAL', 300))

def get_config():
    """Get configuration instance."""
    return Config()