"""
MongoDB Client configuration
"""

import logging
from pymongo import MongoClient
from typing import Optional

logger = logging.getLogger(__name__)

_mongo_client: Optional[MongoClient] = None

def get_mongo_client(mongo_uri: str) -> MongoClient:
    """Get or create MongoDB client"""
    global _mongo_client
    
    if _mongo_client is None:
        try:
            _mongo_client = MongoClient(
                mongo_uri,
                maxPoolSize=50,
                minPoolSize=5,
                maxIdleTimeMS=30000,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=20000
            )
            
            # Test connection
            _mongo_client.admin.command('ping')
            logger.info("MongoDB client created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create MongoDB client: {e}")
            raise
    
    return _mongo_client

def close_mongo_client():
    """Close MongoDB client"""
    global _mongo_client
    if _mongo_client:
        _mongo_client.close()
        _mongo_client = None
        logger.info("MongoDB client closed")