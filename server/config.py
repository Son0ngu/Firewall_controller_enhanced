"""
Configuration module for the Firewall Controller Server.

This module loads and provides access to all configuration parameters needed by the server.
Configuration is sourced from environment variables, with sensible defaults when not provided.

Sections:
- Flask Application: Core Flask settings and secret keys
- Database: MongoDB connection settings
- Security: JWT configuration, CORS, and CSRF protection
- API: API versioning and rate limiting
- Logging: Log levels and destinations
- Email: Settings for notifications and alerts
"""

import os
import secrets
from datetime import timedelta
from typing import Dict, Any, List, Optional

# ======== CONFIGURATION LOADING ========

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


# ======== FLASK APPLICATION SETTINGS ========

class Config:
    """Base configuration for all environments."""
    
    # Flask core settings
    SECRET_KEY = get_env('SECRET_KEY', secrets.token_hex(32))
    DEBUG = get_env('DEBUG', False)
    TESTING = get_env('TESTING', False)
    SERVER_NAME = get_env('SERVER_NAME', None)  # For URL generation, e.g., 'example.com'
    APPLICATION_ROOT = get_env('APPLICATION_ROOT', '/')
    PREFERRED_URL_SCHEME = get_env('PREFERRED_URL_SCHEME', 'http')
    
    # Session settings
    SESSION_TYPE = get_env('SESSION_TYPE', 'filesystem')
    SESSION_PERMANENT = get_env('SESSION_PERMANENT', True)
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(get_env('SESSION_LIFETIME_DAYS', 1)))
    SESSION_COOKIE_SECURE = get_env('SESSION_COOKIE_SECURE', False)
    SESSION_COOKIE_HTTPONLY = get_env('SESSION_COOKIE_HTTPONLY', True)
    SESSION_COOKIE_SAMESITE = get_env('SESSION_COOKIE_SAMESITE', 'Lax')
    
    # CSRF protection
    WTF_CSRF_ENABLED = get_env('WTF_CSRF_ENABLED', True)
    WTF_CSRF_SECRET_KEY = get_env('WTF_CSRF_SECRET_KEY', SECRET_KEY)
    
    # CORS settings
    CORS_ORIGINS = get_env('CORS_ORIGINS', '*').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']
    CORS_EXPOSE_HEADERS = ['Content-Disposition']
    CORS_SUPPORTS_CREDENTIALS = get_env('CORS_CREDENTIALS', False)
    
    # MongoDB Settings
    MONGO_URI = get_env('MONGO_URI', 'mongodb://localhost:27017/firewall_controller')
    MONGO_DBNAME = get_env('MONGO_DBNAME', 'firewall_controller')
    
    # JWT Authentication
    JWT_SECRET_KEY = get_env('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=int(get_env('JWT_ACCESS_TOKEN_HOURS', 1)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(get_env('JWT_REFRESH_TOKEN_DAYS', 30)))
    JWT_ALGORITHM = get_env('JWT_ALGORITHM', 'HS256')
    
    # API Key Authentication
    API_KEY_HEADER = get_env('API_KEY_HEADER', 'X-API-Key')
    
    # Rate limiting
    RATELIMIT_DEFAULT = get_env('RATELIMIT_DEFAULT', '100/hour')
    RATELIMIT_STORAGE_URI = get_env('RATELIMIT_STORAGE_URI', 'memory://')
    
    # Logging settings
    LOG_LEVEL = get_env('LOG_LEVEL', 'INFO')
    LOG_FORMAT = get_env('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    LOG_FILE = get_env('LOG_FILE', 'server.log')
    LOG_MAX_BYTES = int(get_env('LOG_MAX_BYTES', 10485760))  # 10 MB
    LOG_BACKUP_COUNT = int(get_env('LOG_BACKUP_COUNT', 5))
    
    # Email settings (for alerts and notifications)
    MAIL_SERVER = get_env('MAIL_SERVER', '')
    MAIL_PORT = int(get_env('MAIL_PORT', 587))
    MAIL_USE_TLS = get_env('MAIL_USE_TLS', True)
    MAIL_USERNAME = get_env('MAIL_USERNAME', '')
    MAIL_PASSWORD = get_env('MAIL_PASSWORD', '')
    MAIL_DEFAULT_SENDER = get_env('MAIL_DEFAULT_SENDER', 'noreply@firewall-controller.com')
    
    # Path settings
    UPLOAD_FOLDER = get_env('UPLOAD_FOLDER', '/tmp/firewall-controller/uploads')
    ALLOWED_EXTENSIONS = {'csv', 'json', 'txt'}
    
    # Socket.IO settings
    SOCKETIO_CORS_ALLOWED_ORIGINS = get_env('SOCKETIO_CORS_ORIGINS', '*').split(',')
    SOCKETIO_ASYNC_MODE = get_env('SOCKETIO_ASYNC_MODE', 'eventlet')
    
    # Custom application settings
    DEFAULT_ADMIN_USERNAME = get_env('DEFAULT_ADMIN_USERNAME', 'admin')
    DEFAULT_ADMIN_PASSWORD = get_env('DEFAULT_ADMIN_PASSWORD', None)  # Must be set in production
    DEFAULT_ADMIN_EMAIL = get_env('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
    
    # Agent settings
    AGENT_WHITELIST_UPDATE_INTERVAL = int(get_env('AGENT_WHITELIST_UPDATE_INTERVAL', 3600))  # 1 hour


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    DEVELOPMENT = True
    WTF_CSRF_ENABLED = False  # Disable for easier API testing
    
    # Development MongoDB (can be overridden by env vars)
    MONGO_URI = get_env('MONGO_URI', 'mongodb://localhost:27017/firewall_controller_dev')
    
    # Shorter token expiry for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    
    # Higher rate limits for development
    RATELIMIT_DEFAULT = '1000/hour'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    WTF_CSRF_ENABLED = False
    
    # Use in-memory MongoDB for tests
    MONGO_URI = get_env('MONGO_URI', 'mongomock://localhost/firewall_controller_test')
    
    # Very short token expiry for testing
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=30)
    
    # Disable rate limiting for tests
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    TESTING = False
    
    # Force secure cookies in production
    SESSION_COOKIE_SECURE = True
    
    # Stricter CORS in production
    CORS_ORIGINS = get_env('CORS_ORIGINS', 'https://dashboard.firewall-controller.com').split(',')
    
    # Ensure these are set through environment variables in production
    def __init__(self):
        if not get_env('SECRET_KEY'):
            raise ValueError("SECRET_KEY must be set in production")
        if not get_env('MONGO_URI'):
            raise ValueError("MONGO_URI must be set in production")
        if not get_env('DEFAULT_ADMIN_PASSWORD'):
            raise ValueError("DEFAULT_ADMIN_PASSWORD must be set in production")


# ======== CONFIGURATION SELECTION ========

def get_config():
    """Get configuration based on environment."""
    env = get_env('FLASK_ENV', 'development')
    
    if env == 'production':
        return ProductionConfig()
    elif env == 'testing':
        return TestingConfig()
    else:
        return DevelopmentConfig()