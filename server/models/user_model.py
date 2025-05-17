import re
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Union, Any

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
    def __modify_schema__(cls, field_schema):
        field_schema.update(type="string")


class UserRole(str, Enum):
    """User role enumeration."""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    """User account status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


class User(BaseModel):
    """
    User model for authentication and authorization.
    Defines user properties, preferences, and permissions.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password_hash: str
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    status: UserStatus = UserStatus.PENDING
    
    # Tracking fields
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    # User preferences
    preferences: Dict = Field(default_factory=dict)
    
    # Security fields
    api_keys: List[Dict] = Field(default_factory=list)
    password_reset_token: Optional[str] = None
    password_reset_expires: Optional[datetime] = None
    login_attempts: int = 0
    
    @field_validator('username')
    def username_alphanumeric(cls, v):
        """Validate username is alphanumeric with underscores and hyphens."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v

    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str},
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "role": "operator",
                "status": "active",
                "preferences": {"theme": "dark", "notifications": True},
            }
        }
    )


class UserCreate(BaseModel):
    """Schema for user creation requests."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER
    
    @field_validator('username')
    def username_alphanumeric(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v

    @field_validator('password')
    def password_strength(cls, v):
        """Check password meets minimum security requirements."""
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    """Schema for user update requests."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    preferences: Optional[Dict] = None


class UserResponse(BaseModel):
    """Schema for user responses (excludes sensitive data)."""
    id: str = Field(..., alias="_id")
    username: str
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole
    status: UserStatus
    created_at: datetime
    last_login: Optional[datetime] = None
    preferences: Dict

    model_config = ConfigDict(
        populate_by_alias=True,
        json_schema_extra={
            "example": {
                "_id": "60d6ec9f5e8e7a721c97195a",
                "username": "johndoe",
                "email": "john.doe@example.com",
                "full_name": "John Doe",
                "role": "operator",
                "status": "active",
                "created_at": "2023-01-01T00:00:00",
                "last_login": "2023-01-02T12:34:56",
                "preferences": {"theme": "dark", "notifications": True},
            }
        }
    )


class UserLogin(BaseModel):
    """Schema for user login requests."""
    username: str
    password: str