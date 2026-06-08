"""
API Key Model - handles API key data operations for agent authentication.
- Clean and simple
"""

import logging
import os
import secrets
import hashlib
import hmac
from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from datetime import datetime, timedelta

# Import time utilities - Vietnam ONLY
from time_utils import now_vietnam

logger = logging.getLogger(__name__)

# HMAC key for API key hashing - must be provided by the environment.
API_KEY_HMAC_SECRET = os.environ.get("API_KEY_HMAC_SECRET", None)
if not API_KEY_HMAC_SECRET:
    raise RuntimeError("API_KEY_HMAC_SECRET must be set in the environment")


class APIKeyModel:
    """Model for API Key data operations"""

    # API Key prefix for identification
    KEY_PREFIX = "fc_"  # FirewallController prefix
    
    def __init__(self, db: Database):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db = db
        self.collection: Collection = self.db.api_keys
        self._setup_indexes()
    
    def _setup_indexes(self):
        """Setup indexes for api_keys collection"""
        try:
            # Unique index on key_hash (we store hash, not plaintext)
            self.collection.create_index([("key_hash", ASCENDING)], unique=True)
            # Index for lookups
            self.collection.create_index([("name", ASCENDING)])
            self.collection.create_index([("is_active", ASCENDING)])
            self.collection.create_index([("expires_at", ASCENDING)])
            self.collection.create_index([("created_at", DESCENDING)])
            self.logger.info("API Key indexes created successfully")
        except Exception as e:
            self.logger.warning(f"Error creating indexes: {e}")
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a new API key.
        Format: fc_<32 random hex characters>
        
        Returns:
            str: New API key (plaintext, only shown once)
        """
        random_part = secrets.token_hex(16)  # 32 hex characters
        return f"{APIKeyModel.KEY_PREFIX}{random_part}"
    
    @staticmethod
    def hash_api_key(api_key: str) -> str:
        """
        Hash an API key for secure storage using HMAC-SHA256.

        Args:
            api_key: Plaintext API key

        Returns:
            str: HMAC-SHA256 hash of the key
        """
        return hmac.new(
            API_KEY_HMAC_SECRET.encode(),
            api_key.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _hash_api_key_legacy(api_key: str) -> str:
        """Legacy plain SHA-256 hash - for backward compat with old keys only."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    def create_api_key(
        self,
        name: str,
        description: str = "",
        expires_in_days: Optional[int] = None,
        permissions: Optional[List[str]] = None,
        created_by: str = "system"
    ) -> Dict:
        """
        Create a new API key.
        
        Args:
            name: Friendly name for the key
            description: Description of what this key is used for
            expires_in_days: Days until expiration (None = never expires)
            permissions: List of permissions ['register', 'sync', 'logs']
            created_by: Who created this key
            
        Returns:
            Dict with key info including plaintext key (only shown once!)
        """
        try:
            current_time = now_vietnam()
            
            # Generate new key
            plaintext_key = self.generate_api_key()
            key_hash = self.hash_api_key(plaintext_key)
            
            # Calculate expiration
            expires_at = None
            if expires_in_days:
                expires_at = current_time + timedelta(days=expires_in_days)
            
            # Default permissions
            if permissions is None:
                permissions = ["register"]  # Default: only registration
            
            # Key document
            key_doc = {
                "key_hash": key_hash,
                "key_prefix": plaintext_key[:12],  # Store prefix for identification (fc_xxxx)
                "name": name,
                "description": description,
                "permissions": permissions,
                "is_active": True,
                "created_at": current_time,
                "created_by": created_by,
                "expires_at": expires_at,
                "last_used_at": None,
                "usage_count": 0,
                "revoked_at": None,
                "revoked_by": None
            }
            
            result = self.collection.insert_one(key_doc)
            key_doc["_id"] = result.inserted_id
            
            # Return with plaintext key (ONLY TIME it's available!)
            return {
                "success": True,
                "api_key": plaintext_key,  # ⚠️ Show only once!
                "key_id": str(result.inserted_id),
                "key_prefix": plaintext_key[:12],
                "name": name,
                "permissions": permissions,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "message": "⚠️ Save this API key now! It won't be shown again."
            }
            
        except Exception as e:
            self.logger.error(f"Error creating API key: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_api_key(self, api_key: str, required_permission: str = "register") -> Dict:
        """
        Validate an API key.
        
        Args:
            api_key: Plaintext API key to validate
            required_permission: Permission required for this operation
            
        Returns:
            Dict with validation result
        """
        try:
            # Check format
            if not api_key or not api_key.startswith(self.KEY_PREFIX):
                return {
                    "valid": False,
                    "error": "Invalid API key format"
                }
            
            # Hash and lookup - try HMAC first, then legacy SHA-256
            key_hash = self.hash_api_key(api_key)
            key_doc = self.collection.find_one({"key_hash": key_hash})

            if not key_doc:
                # Fallback: try legacy plain SHA-256 for old keys
                legacy_hash = self._hash_api_key_legacy(api_key)
                key_doc = self.collection.find_one({"key_hash": legacy_hash})
                if key_doc:
                    # Lazy migration: upgrade to HMAC hash
                    self.collection.update_one(
                        {"_id": key_doc["_id"]},
                        {"$set": {"key_hash": key_hash}}
                    )
                    self.logger.info(f"Migrated API key {key_doc.get('name')} to HMAC hash")

            if not key_doc:
                return {
                    "valid": False,
                    "error": "API key not found"
                }
            
            # Check if active
            if not key_doc.get("is_active", False):
                return {
                    "valid": False,
                    "error": "API key is inactive or revoked"
                }
            
            # Check expiration
            expires_at = key_doc.get("expires_at")
            if expires_at and expires_at < now_vietnam():
                return {
                    "valid": False,
                    "error": "API key has expired"
                }
            
            # Check permission with mapping for old/new format
            permissions = key_doc.get("permissions", [])
            
            # Permission mapping: old format -> new format and vice versa
            permission_aliases = {
                'register': ['register', 'agent_register'],
                'agent_register': ['register', 'agent_register'],
                'sync': ['sync', 'whitelist_sync'],
                'whitelist_sync': ['sync', 'whitelist_sync'],
                'logs': ['logs', 'logs_write'],
                'logs_write': ['logs', 'logs_write'],
                'heartbeat': ['heartbeat'],
                'admin': ['admin'],
                'agent_read': ['agent_read'],
            }
            
            if required_permission:
                # Get all acceptable permissions for this requirement
                acceptable = permission_aliases.get(required_permission, [required_permission])
                has_permission = any(p in permissions for p in acceptable)
                
                if not has_permission:
                    return {
                        "valid": False,
                        "error": f"API key lacks '{required_permission}' permission"
                    }
            
            # Update usage stats
            self.collection.update_one(
                {"_id": key_doc["_id"]},
                {
                    "$set": {"last_used_at": now_vietnam()},
                    "$inc": {"usage_count": 1}
                }
            )
            
            return {
                "valid": True,
                "key_id": str(key_doc["_id"]),
                "name": key_doc.get("name"),
                "permissions": permissions
            }
            
        except Exception as e:
            self.logger.error(f"Error validating API key: {e}")
            return {"valid": False, "error": "Internal validation error"}
    
    def revoke_api_key(self, key_id: str, revoked_by: str = "system") -> Dict:
        """
        Revoke an API key.
        
        Args:
            key_id: ID of the key to revoke
            revoked_by: Who is revoking this key
            
        Returns:
            Dict with result
        """
        try:
            result = self.collection.update_one(
                {"_id": ObjectId(key_id)},
                {
                    "$set": {
                        "is_active": False,
                        "revoked_at": now_vietnam(),
                        "revoked_by": revoked_by
                    }
                }
            )
            
            if result.modified_count > 0:
                return {"success": True, "message": "API key revoked"}
            else:
                return {"success": False, "error": "API key not found"}
                
        except Exception as e:
            self.logger.error(f"Error revoking API key: {e}")
            return {"success": False, "error": str(e)}
    
    def list_api_keys(
        self,
        include_revoked: bool = False,
        page: int = 1,
        limit: int = 20
    ) -> Dict:
        """
        List all API keys (without showing the actual keys).
        
        Args:
            include_revoked: Whether to include revoked keys
            page: Page number
            limit: Items per page
            
        Returns:
            Dict with keys list
        """
        try:
            query = {}
            if not include_revoked:
                query["is_active"] = True
            
            skip = (page - 1) * limit
            
            # Get total count
            total = self.collection.count_documents(query)
            
            # Get keys (exclude key_hash for security)
            cursor = self.collection.find(
                query,
                {"key_hash": 0}  # Never expose hash
            ).sort("created_at", DESCENDING).skip(skip).limit(limit)
            
            keys = []
            for doc in cursor:
                doc["_id"] = str(doc["_id"])
                # Format dates
                for field in ["created_at", "expires_at", "last_used_at", "revoked_at"]:
                    if doc.get(field):
                        doc[field] = doc[field].isoformat()
                keys.append(doc)
            
            return {
                "success": True,
                "keys": keys,
                "total": total,
                "page": page,
                "limit": limit,
                "pages": (total + limit - 1) // limit
            }
            
        except Exception as e:
            self.logger.error(f"Error listing API keys: {e}")
            return {"success": False, "error": str(e), "keys": []}
    
    def get_api_key_by_id(self, key_id: str) -> Optional[Dict]:
        """
        Get API key details by ID (without the actual key).
        
        Args:
            key_id: ID of the key
            
        Returns:
            Key document or None
        """
        try:
            doc = self.collection.find_one(
                {"_id": ObjectId(key_id)},
                {"key_hash": 0}
            )
            if doc:
                doc["_id"] = str(doc["_id"])
                for field in ["created_at", "expires_at", "last_used_at", "revoked_at"]:
                    if doc.get(field):
                        doc[field] = doc[field].isoformat()
            return doc
        except Exception as e:
            self.logger.error(f"Error getting API key: {e}")
            return None
    
    def update_api_key(
        self,
        key_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        is_active: Optional[bool] = None
    ) -> Dict:
        """
        Update API key properties.
        
        Args:
            key_id: ID of the key
            name: New name
            description: New description
            permissions: New permissions list
            is_active: Active status
            
        Returns:
            Dict with result
        """
        try:
            update_fields = {}
            if name is not None:
                update_fields["name"] = name
            if description is not None:
                update_fields["description"] = description
            if permissions is not None:
                update_fields["permissions"] = permissions
            if is_active is not None:
                update_fields["is_active"] = is_active
            
            if not update_fields:
                return {"success": False, "error": "No fields to update"}
            
            result = self.collection.update_one(
                {"_id": ObjectId(key_id)},
                {"$set": update_fields}
            )
            
            if result.modified_count > 0:
                return {"success": True, "message": "API key updated"}
            else:
                return {"success": False, "error": "API key not found or no changes"}
                
        except Exception as e:
            self.logger.error(f"Error updating API key: {e}")
            return {"success": False, "error": str(e)}
    
    def get_stats(self) -> Dict:
        """Get API key statistics."""
        try:
            total = self.collection.count_documents({})
            active = self.collection.count_documents({"is_active": True})
            expired = self.collection.count_documents({
                "expires_at": {"$lt": now_vietnam()},
                "is_active": True
            })
            revoked = self.collection.count_documents({"is_active": False})
            
            return {
                "total": total,
                "active": active,
                "expired": expired,
                "revoked": revoked
            }
        except Exception as e:
            self.logger.error(f"Error getting stats: {e}")
            return {"total": 0, "active": 0, "expired": 0, "revoked": 0}
