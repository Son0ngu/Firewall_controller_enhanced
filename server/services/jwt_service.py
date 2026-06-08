"""
JWT Service - Token generation, validation, and refresh for agent authentication.
- Clean and simple
"""

import os
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, Any

import jwt
from time_utils import VIETNAM_TZ, now_vietnam, now_iso

logger = logging.getLogger(__name__)

# Token configuration
ACCESS_TOKEN_EXPIRY_HOURS = 24  # 24 hours for access token
REFRESH_TOKEN_EXPIRY_DAYS = 7   # 7 days for refresh token
JWT_ALGORITHM = "HS256"

# Get secret keys from environment - REQUIRED for production stability
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", None)
JWT_REFRESH_SECRET_KEY = os.environ.get("JWT_REFRESH_SECRET_KEY", None)

# In development, fall back to random keys (tokens invalidated on restart)
# In production, set JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY in .env
if not JWT_SECRET_KEY:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("JWT_SECRET_KEY must be set in production environment!")
    JWT_SECRET_KEY = secrets.token_hex(32)
    logger.warning("JWT_SECRET_KEY not set - using random key. Tokens will be invalidated on restart!")

if not JWT_REFRESH_SECRET_KEY:
    if os.environ.get("FLASK_ENV") == "production":
        raise RuntimeError("JWT_REFRESH_SECRET_KEY must be set in production environment!")
    JWT_REFRESH_SECRET_KEY = secrets.token_hex(32)
    logger.warning("JWT_REFRESH_SECRET_KEY not set - using random key.")


class JWTService:
    """Service for JWT token operations"""
    
    def __init__(self, db=None):
        """
        Initialize JWT Service.
        
        Args:
            db: MongoDB database instance for storing revoked tokens
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.db = db
        self.secret_key = JWT_SECRET_KEY
        self.refresh_secret_key = JWT_REFRESH_SECRET_KEY
        self.algorithm = JWT_ALGORITHM
        
        # Initialize revoked tokens collection if db provided
        if self.db is not None:
            self.revoked_tokens = self.db["revoked_tokens"]
            self._setup_indexes()
        else:
            self.revoked_tokens = None
        
        self.logger.info("JWTService initialized")
    
    def _setup_indexes(self):
        """Setup MongoDB indexes for revoked tokens"""
        try:
            if self.revoked_tokens is not None:
                # TTL index to auto-delete expired revoked tokens
                self.revoked_tokens.create_index(
                    "expires_at",
                    expireAfterSeconds=0,
                    name="revoked_tokens_ttl"
                )
                self.revoked_tokens.create_index("jti", unique=True, name="jti_unique")
                self.logger.info("Revoked tokens indexes created")
        except Exception as e:
            self.logger.error(f"Error creating indexes: {e}")
    
    def generate_tokens(self, agent_id: str, user_id: str, 
                       additional_claims: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Generate access and refresh tokens for an agent.
        
        Args:
            agent_id: The agent's unique identifier
            user_id: The user's unique identifier
            additional_claims: Optional additional claims to include
            
        Returns:
            Dict containing access_token, refresh_token, and expiry info
        """
        now = now_vietnam()
        
        # Generate unique token IDs
        access_jti = secrets.token_hex(16)
        refresh_jti = secrets.token_hex(16)
        
        # Access token claims
        access_claims = {
            "sub": agent_id,
            "user_id": user_id,
            "jti": access_jti,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(hours=ACCESS_TOKEN_EXPIRY_HOURS),
            "iss": "firewall-controller",
        }
        
        # Add additional claims if provided
        if additional_claims:
            access_claims.update(additional_claims)
        
        # Refresh token claims (minimal, longer lived)
        refresh_claims = {
            "sub": agent_id,
            "user_id": user_id,
            "jti": refresh_jti,
            "type": "refresh",
            "iat": now,
            "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
            "iss": "firewall-controller",
        }
        
        # Generate tokens
        access_token = jwt.encode(access_claims, self.secret_key, algorithm=self.algorithm)
        refresh_token = jwt.encode(refresh_claims, self.refresh_secret_key, algorithm=self.algorithm)
        
        self.logger.info(f"Generated tokens for agent {agent_id}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "access_expires_in": ACCESS_TOKEN_EXPIRY_HOURS * 3600,  # seconds
            "refresh_expires_in": REFRESH_TOKEN_EXPIRY_DAYS * 24 * 3600,  # seconds
            "access_expires_at": (now + timedelta(hours=ACCESS_TOKEN_EXPIRY_HOURS)).isoformat(),
            "refresh_expires_at": (now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)).isoformat(),
        }
    
    def validate_access_token(self, token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Validate an access token.
        
        Args:
            token: The JWT access token to validate
            
        Returns:
            Tuple of (is_valid, payload, error_message)
        """
        try:
            # Decode and verify
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"require": ["sub", "jti", "type", "exp"]}
            )
            
            # Check token type
            if payload.get("type") != "access":
                return False, None, "Invalid token type"
            
            # Check if token is revoked
            if self._is_token_revoked(payload.get("jti"), payload.get("sub")):
                return False, None, "Token has been revoked"
            
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Token has expired"
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid token: {e}")
            return False, None, f"Invalid token: {str(e)}"
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return False, None, "Token validation failed"
    
    def validate_refresh_token(self, token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Validate a refresh token.
        
        Args:
            token: The JWT refresh token to validate
            
        Returns:
            Tuple of (is_valid, payload, error_message)
        """
        try:
            # Decode and verify
            payload = jwt.decode(
                token,
                self.refresh_secret_key,
                algorithms=[self.algorithm],
                options={"require": ["sub", "jti", "type", "exp"]}
            )
            
            # Check token type
            if payload.get("type") != "refresh":
                return False, None, "Invalid token type"
            
            # Check if token is revoked
            if self._is_token_revoked(payload.get("jti"), payload.get("sub")):
                return False, None, "Refresh token has been revoked"
            
            return True, payload, None
            
        except jwt.ExpiredSignatureError:
            return False, None, "Refresh token has expired"
        except jwt.InvalidTokenError as e:
            self.logger.warning(f"Invalid refresh token: {e}")
            return False, None, f"Invalid refresh token: {str(e)}"
        except Exception as e:
            self.logger.error(f"Refresh token validation error: {e}")
            return False, None, "Refresh token validation failed"
    
    def refresh_access_token(self, refresh_token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Refresh an access token using a valid refresh token.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Tuple of (success, new_tokens_or_None, error_message)
        """
        # Validate refresh token
        is_valid, payload, error = self.validate_refresh_token(refresh_token)
        
        if not is_valid:
            return False, None, error
        
        # Generate new access token only (refresh token stays the same)
        agent_id = payload.get("sub")
        user_id = payload.get("user_id")
        
        now = now_vietnam()
        access_jti = secrets.token_hex(16)
        
        access_claims = {
            "sub": agent_id,
            "user_id": user_id,
            "jti": access_jti,
            "type": "access",
            "iat": now,
            "exp": now + timedelta(hours=ACCESS_TOKEN_EXPIRY_HOURS),
            "iss": "firewall-controller",
        }
        
        access_token = jwt.encode(access_claims, self.secret_key, algorithm=self.algorithm)
        
        self.logger.info(f"Refreshed access token for agent {agent_id}")
        
        return True, {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRY_HOURS * 3600,
            "expires_at": (now + timedelta(hours=ACCESS_TOKEN_EXPIRY_HOURS)).isoformat(),
        }, None
    
    def refresh_tokens_with_rotation(self, refresh_token: str) -> Tuple[bool, Optional[Dict], Optional[str]]:
        """
        Refresh both access and refresh tokens (token rotation for extra security).
        
        The old refresh token is revoked and a new one is issued.
        This prevents refresh token reuse attacks.
        
        Args:
            refresh_token: The current refresh token
            
        Returns:
            Tuple of (success, new_tokens_or_None, error_message)
        """
        # Validate refresh token
        is_valid, payload, error = self.validate_refresh_token(refresh_token)
        
        if not is_valid:
            return False, None, error
        
        agent_id = payload.get("sub")
        user_id = payload.get("user_id")
        old_jti = payload.get("jti")
        
        # Revoke the old refresh token
        if old_jti and self.revoked_tokens is not None:
            try:
                self.revoked_tokens.update_one(
                    {"jti": old_jti},
                    {
                        "$set": {
                            "jti": old_jti,
                            "token_type": "refresh",
                            "agent_id": agent_id,
                            "revoked_at": now_vietnam(),
                            "revoked_reason": "rotation",
                            "expires_at": now_vietnam() + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
                        }
                    },
                    upsert=True
                )
            except Exception as e:
                self.logger.warning(f"Failed to revoke old refresh token: {e}")
        
        # Generate new tokens
        new_tokens = self.generate_tokens(
            agent_id=agent_id,
            user_id=user_id,
            additional_claims=payload.get("additional_claims")
        )
        
        self.logger.info(f"Token rotation completed for agent {agent_id}")
        
        return True, new_tokens, None
    
    def revoke_token(self, token: str, token_type: str = "access") -> bool:
        """
        Revoke a token by adding it to the revoked tokens list.
        
        Args:
            token: The token to revoke
            token_type: "access" or "refresh"
            
        Returns:
            True if successfully revoked
        """
        try:
            # Decode without verification to get JTI
            if token_type == "refresh":
                secret = self.refresh_secret_key
            else:
                secret = self.secret_key
            
            try:
                payload = jwt.decode(
                    token, 
                    secret, 
                    algorithms=[self.algorithm],
                    options={"verify_exp": False}  # Allow expired tokens to be revoked
                )
            except jwt.InvalidTokenError:
                return False
            
            jti = payload.get("jti")
            if not jti:
                return False
            
            # Get expiry for TTL
            exp = payload.get("exp")
            if isinstance(exp, (int, float)):
                expires_at = datetime.fromtimestamp(exp, tz=VIETNAM_TZ)
            else:
                expires_at = now_vietnam() + timedelta(days=7)
            
            # Add to revoked tokens collection
            if self.revoked_tokens is not None:
                self.revoked_tokens.update_one(
                    {"jti": jti},
                    {
                        "$set": {
                            "jti": jti,
                            "token_type": token_type,
                            "agent_id": payload.get("sub"),
                            "revoked_at": now_vietnam(),
                            "expires_at": expires_at,
                        }
                    },
                    upsert=True
                )
            
            self.logger.info(f"Revoked {token_type} token for agent {payload.get('sub')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error revoking token: {e}")
            return False
    
    def revoke_all_agent_tokens(self, agent_id: str) -> int:
        """
        Revoke all tokens for a specific agent.
        
        Args:
            agent_id: The agent's ID
            
        Returns:
            Number of tokens revoked
        """
        if self.revoked_tokens is None:
            return 0
        
        try:
            self.revoked_tokens.update_one(
                {"agent_id": agent_id, "revoke_all": True},
                {"$set": {
                    "agent_id": agent_id,
                    "revoke_all": True,
                    "token_type": "all",
                    "revoked_at": now_vietnam(),
                    "expires_at": now_vietnam() + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
                }},
                upsert=True,
            )
            
            self.logger.info(f"Marked all tokens as revoked for agent {agent_id}")
            return 1
            
        except Exception as e:
            self.logger.error(f"Error revoking all agent tokens: {e}")
            return 0
    
    def _is_token_revoked(self, jti: str, agent_id: Optional[str] = None) -> bool:
        """Check if a token is revoked by its JTI"""
        if not jti or self.revoked_tokens is None:
            if not agent_id or self.revoked_tokens is None:
                return False
        
        try:
            if jti and self.revoked_tokens.find_one({"jti": jti}):
                return True
            if agent_id and self.revoked_tokens.find_one({"agent_id": agent_id, "revoke_all": True}):
                return True
            return False
        except Exception:
            return False
    
    def decode_token_without_verification(self, token: str) -> Optional[Dict]:
        """
        Decode a token without verifying signature (for debugging/logging).
        
        Args:
            token: The JWT token
            
        Returns:
            Decoded payload or None
        """
        try:
            return jwt.decode(
                token,
                options={"verify_signature": False}
            )
        except Exception:
            return None
    
    def get_token_info(self, token: str) -> Dict[str, Any]:
        """
        Get information about a token.
        
        Args:
            token: The JWT token
            
        Returns:
            Dict with token information
        """
        payload = self.decode_token_without_verification(token)
        
        if not payload:
            return {"valid": False, "error": "Cannot decode token"}
        
        now = now_vietnam()
        
        # Get expiry time
        exp = payload.get("exp")
        if isinstance(exp, (int, float)):
            expires_at = datetime.fromtimestamp(exp, tz=VIETNAM_TZ)
            is_expired = now > expires_at
        else:
            expires_at = None
            is_expired = True
        
        return {
            "agent_id": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "token_type": payload.get("type"),
            "jti": payload.get("jti"),
            "issued_at": payload.get("iat"),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "is_expired": is_expired,
            "is_revoked": self._is_token_revoked(payload.get("jti"), payload.get("sub")),
        }


# Singleton instance (initialized in app.py)
_jwt_service: Optional[JWTService] = None


def init_jwt_service(db=None) -> JWTService:
    """Initialize the global JWT service instance"""
    global _jwt_service
    _jwt_service = JWTService(db)
    return _jwt_service


def get_jwt_service() -> Optional[JWTService]:
    """Get the global JWT service instance"""
    return _jwt_service
