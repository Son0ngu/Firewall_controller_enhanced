"""
API Key Service - Business logic for API key operations.
- Clean and simple
"""

import logging
from typing import Dict, List, Optional
from models.api_key_model import APIKeyModel

# Import time utilities - Vietnam ONLY
from time_utils import now_vietnam, now_iso

logger = logging.getLogger(__name__)


class APIKeyService:
    """Service class for API key business logic"""
    
    def __init__(self, api_key_model: APIKeyModel, socketio=None):
        """
        Initialize APIKeyService.
        
        Args:
            api_key_model: APIKeyModel instance
            socketio: SocketIO instance for real-time updates
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = api_key_model
        self.socketio = socketio
        self.logger.info("APIKeyService initialized")
    
    def create_api_key(
        self,
        name: str,
        description: str = "",
        expires_in_days: Optional[int] = None,
        permissions: Optional[List[str]] = None,
        created_by: str = "unknown"
    ) -> Dict:
        """
        Create a new API key.
        
        Args:
            name: Friendly name for the key
            description: Description of what this key is used for
            expires_in_days: Days until expiration (None = never)
            permissions: List of permissions
            created_by: Who created this key
            
        Returns:
            Dict with key info including plaintext key
        """
        try:
            # Validate name
            if not name or len(name.strip()) < 3:
                return {
                    "success": False,
                    "error": "Name must be at least 3 characters"
                }
            
            # Create key
            result = self.model.create_api_key(
                name=name.strip(),
                description=description.strip() if description else "",
                expires_in_days=expires_in_days,
                permissions=permissions,
                created_by=created_by
            )
            
            if result.get("success"):
                self.logger.info(f"API key created: {name} by {created_by}")
                
                # Emit real-time update
                if self.socketio:
                    self.socketio.emit("api_key_created", {
                        "key_id": result.get("key_id"),
                        "name": name,
                        "timestamp": now_iso()
                    })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error creating API key: {e}")
            return {"success": False, "error": str(e)}
    
    def validate_api_key(
        self,
        api_key: str,
        required_permission: str = "register"
    ) -> Dict:
        """
        Validate an API key for a specific permission.
        
        Args:
            api_key: The API key to validate
            required_permission: The permission required
            
        Returns:
            Dict with validation result
        """
        if not api_key:
            return {
                "valid": False,
                "error": "API key is required"
            }
        
        return self.model.validate_api_key(api_key, required_permission)
    
    def revoke_api_key(self, key_id: str, revoked_by: str = "unknown") -> Dict:
        """
        Revoke an API key.
        
        Args:
            key_id: ID of the key to revoke
            revoked_by: Who is revoking
            
        Returns:
            Dict with result
        """
        try:
            result = self.model.revoke_api_key(key_id, revoked_by)
            
            if result.get("success"):
                self.logger.info(f"API key revoked: {key_id} by {revoked_by}")
                
                # Emit real-time update
                if self.socketio:
                    self.socketio.emit("api_key_revoked", {
                        "key_id": key_id,
                        "timestamp": now_iso()
                    })
            
            return result
            
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
        List all API keys.
        
        Args:
            include_revoked: Include revoked keys
            page: Page number
            limit: Items per page
            
        Returns:
            Dict with keys list
        """
        return self.model.list_api_keys(include_revoked, page, limit)
    
    def get_api_key(self, key_id: str) -> Optional[Dict]:
        """
        Get API key details.
        
        Args:
            key_id: ID of the key
            
        Returns:
            Key details or None
        """
        return self.model.get_api_key_by_id(key_id)
    
    def update_api_key(
        self,
        key_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        is_active: Optional[bool] = None,
        updated_by: str = "unknown"
    ) -> Dict:
        """
        Update API key properties.
        
        Args:
            key_id: ID of the key
            name: New name
            description: New description
            permissions: New permissions
            is_active: Active status
            updated_by: Who is updating
            
        Returns:
            Dict with result
        """
        try:
            result = self.model.update_api_key(
                key_id=key_id,
                name=name,
                description=description,
                permissions=permissions,
                is_active=is_active
            )
            
            if result.get("success"):
                self.logger.info(f"API key updated: {key_id} by {updated_by}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error updating API key: {e}")
            return {"success": False, "error": str(e)}
    
    def get_stats(self) -> Dict:
        """Get API key statistics."""
        return self.model.get_stats()
    
    def create_default_key_if_none(self) -> Optional[Dict]:
        """
        Create a default API key if none exist.
        Used for initial setup.
        
        Returns:
            Created key info or None if keys already exist
        """
        try:
            stats = self.model.get_stats()
            
            if stats.get("total", 0) == 0:
                self.logger.info("No API keys found, creating default key...")
                
                result = self.model.create_api_key(
                    name="Default Agent Key",
                    description="Auto-generated default key for agent registration",
                    expires_in_days=365,  # 1 year
                    permissions=["register"],
                    created_by="system"
                )
                
                if result.get("success"):
                    self.logger.warning("="*60)
                    self.logger.warning("DEFAULT API KEY CREATED")
                    self.logger.warning(f"Key ID: {result.get('key_id')}")
                    self.logger.warning(f"Prefix: {result.get('key_prefix')}")
                    self.logger.warning("Plaintext API key is returned to the caller and is not logged.")
                    self.logger.warning("="*60)
                    return result
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error creating default key: {e}")
            return None
