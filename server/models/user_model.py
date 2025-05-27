"""
Simplified User Model for Firewall Controller.
Only 2 types: Admin (for monitoring) and Agent (auto-created by IP).
"""

import re
from datetime import datetime
from enum import Enum
from typing import Optional

from bson import ObjectId
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict


class PyObjectId(ObjectId):
    """Custom ObjectId type for proper serialization in Pydantic models."""
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        from pydantic_core import core_schema
        return core_schema.union_schema([
            core_schema.is_instance_schema(ObjectId),
            core_schema.chain_schema([
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(cls.validate),
            ]),
        ])

    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        json_schema = handler(core_schema)
        json_schema.update(type="string", format="objectid")
        return json_schema


class UserRole(str, Enum):
    """Simplified user roles."""
    ADMIN = "admin"    # Admin user for monitoring and whitelist management
    AGENT = "agent"    # Agent user (auto-created by IP)


class UserStatus(str, Enum):
    """User account status."""
    ACTIVE = "active"
    INACTIVE = "inactive"


class AdminUser(BaseModel):
    """
    Admin user model for monitoring dashboard and whitelist management.
    Only one admin user needed for this small project.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field(..., min_length=3, max_length=50)
    password_hash: str  # Hashed password
    email: Optional[EmailStr] = None
    role: UserRole = UserRole.ADMIN
    status: UserStatus = UserStatus.ACTIVE
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class AgentUser(BaseModel):
    """
    Agent user model - auto-created when agent connects.
    User ID = Agent's IP address for simplicity.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    user_id: str = Field(..., description="Agent IP address as user ID")  # IP address
    hostname: Optional[str] = None
    ip_address: str  # Same as user_id
    platform: Optional[str] = None
    os_info: Optional[str] = None
    agent_version: Optional[str] = None
    role: UserRole = UserRole.AGENT
    status: UserStatus = UserStatus.ACTIVE
    
    # Agent-specific info
    agent_token: Optional[str] = None  # For authentication
    last_heartbeat: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @field_validator('user_id')
    def validate_ip_format(cls, v):
        """Validate that user_id is a valid IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('user_id must be a valid IP address')
    
    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )