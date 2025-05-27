"""
Configuration and Database Client for Firewall Controller Server
"""

import os
import secrets
import logging
from typing import Any, Optional
from pymongo import MongoClient

# ✅ Import dotenv để load .env file
from dotenv import load_dotenv

# ✅ Load .env file
load_dotenv()

# Setup logging
logger = logging.getLogger(__name__)

# Global MongoDB client instance
_mongo_client: Optional[MongoClient] = None

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
    """Configuration class for the application."""
    
    # Flask core settings
    SECRET_KEY = get_env('SECRET_KEY', secrets.token_hex(32))
    DEBUG = get_env('DEBUG', True)
    TESTING = get_env('TESTING', False)
    
    # ✅ MongoDB Settings - Sẽ đọc từ .env file
    MONGO_URI = get_env('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DBNAME = get_env('MONGO_DBNAME', 'Monitoring')
    
    # MongoDB Client Settings
    MONGO_MAX_POOL_SIZE = int(get_env('MONGO_MAX_POOL_SIZE', 50))
    MONGO_MIN_POOL_SIZE = int(get_env('MONGO_MIN_POOL_SIZE', 5))
    MONGO_MAX_IDLE_TIME_MS = int(get_env('MONGO_MAX_IDLE_TIME_MS', 30000))
    MONGO_SERVER_SELECTION_TIMEOUT_MS = int(get_env('MONGO_SERVER_SELECTION_TIMEOUT_MS', 5000))
    MONGO_CONNECT_TIMEOUT_MS = int(get_env('MONGO_CONNECT_TIMEOUT_MS', 10000))
    MONGO_SOCKET_TIMEOUT_MS = int(get_env('MONGO_SOCKET_TIMEOUT_MS', 20000))
    
    # Logging settings
    LOG_LEVEL = get_env('LOG_LEVEL', 'INFO')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_FILE = get_env('LOG_FILE', 'server.log')
    
    # Socket.IO settings
    SOCKETIO_CORS_ALLOWED_ORIGINS = ["*"]
    SOCKETIO_ASYNC_MODE = get_env('SOCKETIO_ASYNC_MODE', 'eventlet')
    
    # Agent settings
    AGENT_WHITELIST_UPDATE_INTERVAL = int(get_env('AGENT_WHITELIST_UPDATE_INTERVAL', 300))
    
    # Server settings
    HOST = get_env('HOST', '0.0.0.0')
    PORT = int(get_env('PORT', 5000))

def get_mongo_client(mongo_uri: str = None, config: Config = None) -> MongoClient:
    """Get or create MongoDB client"""
    global _mongo_client
    
    if _mongo_client is None:
        try:
            # Use provided URI or get from config
            if mongo_uri is None:
                if config is None:
                    config = get_config()
                mongo_uri = config.MONGO_URI
            
            # Get MongoDB settings from config
            if config is None:
                config = get_config()
            
            logger.info(f"🔗 Connecting to MongoDB: {mongo_uri}")
            
            _mongo_client = MongoClient(
                mongo_uri,
                maxPoolSize=config.MONGO_MAX_POOL_SIZE,
                minPoolSize=config.MONGO_MIN_POOL_SIZE,
                maxIdleTimeMS=config.MONGO_MAX_IDLE_TIME_MS,
                serverSelectionTimeoutMS=config.MONGO_SERVER_SELECTION_TIMEOUT_MS,
                connectTimeoutMS=config.MONGO_CONNECT_TIMEOUT_MS,
                socketTimeoutMS=config.MONGO_SOCKET_TIMEOUT_MS
            )
            
            # Test connection
            _mongo_client.admin.command('ping')
            logger.info("✅ MongoDB client created successfully")
            
        except Exception as e:
            logger.error(f"❌ Failed to create MongoDB client: {e}")
            raise
    
    return _mongo_client

def close_mongo_client():
    """Close MongoDB client"""
    global _mongo_client
    if _mongo_client:
        _mongo_client.close()
        _mongo_client = None
        logger.info("MongoDB client closed")

def get_config() -> Config:
    """Get configuration instance."""
    return Config()

def get_database(config: Config = None):
    """Get database instance"""
    if config is None:
        config = get_config()
    
    client = get_mongo_client(config.MONGO_URI, config)
    return client[config.MONGO_DBNAME]

# Environment-specific configurations
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = 'DEBUG'

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    LOG_LEVEL = 'WARNING'
    
    # More conservative MongoDB settings for production
    MONGO_MAX_POOL_SIZE = 25
    MONGO_SERVER_SELECTION_TIMEOUT_MS = 3000

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    MONGO_DBNAME = 'test_firewall_controller'

def get_config_by_name(config_name: str = None) -> Config:
    """Get configuration by environment name"""
    if config_name is None:
        config_name = get_env('FLASK_ENV', 'development')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    return configs.get(config_name, Config)()

def validate_config(config: Config = None) -> bool:
    """Validate configuration settings"""
    if config is None:
        config = get_config()
    
    required_settings = [
        'SECRET_KEY', 'MONGO_URI', 'MONGO_DBNAME'
    ]
    
    for setting in required_settings:
        if not hasattr(config, setting) or not getattr(config, setting):
            logger.error(f"Missing required configuration: {setting}")
            return False
    
    # Log current MongoDB URI (cẩn thận với credentials)
    mongo_uri = config.MONGO_URI
    if 'mongodb+srv://' in mongo_uri:
        # Mask credentials in log
        masked_uri = mongo_uri.split('@')[1] if '@' in mongo_uri else mongo_uri
        logger.info(f"Using MongoDB Atlas: {masked_uri}")
    else:
        logger.info(f"Using MongoDB: {mongo_uri}")
    
    # Test MongoDB connection
    try:
        client = get_mongo_client(config.MONGO_URI, config)
        client.admin.command('ping')
        logger.info("✅ Configuration validation successful")
        return True
    except Exception as e:
        logger.error(f"❌ MongoDB connection test failed: {e}")
        return False

# Export main functions
__all__ = [
    'Config',
    'DevelopmentConfig', 
    'ProductionConfig',
    'TestingConfig',
    'get_config',
    'get_config_by_name',
    'get_mongo_client',
    'close_mongo_client',
    'get_database',
    'validate_config'
]