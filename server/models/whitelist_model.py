import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Union

from bson import ObjectId
from pydantic import BaseModel, Field, field_validator, ConfigDict


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


class Whitelist(BaseModel):
    """
    Whitelist model for managing allowed domains.
    Keeps track of domains that should not be blocked by the firewall.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    domain: str  # Domain name (can include wildcards, e.g., *.example.com)
    notes: Optional[str] = ""
    added_by: str = "system"
    added_date: datetime = Field(default_factory=datetime.utcnow)
    last_updated: Optional[datetime] = None
    
    # Optional categorization
    category: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    
    # Status flags
    is_wildcard: bool = False
    is_active: bool = True
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Validate domain format - allows wildcard domains."""
        domain = v.strip().lower()
        
        # Handle wildcard domains
        if domain.startswith("*."):
            domain = domain[2:]
            
        # Basic domain format validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")
            
        # Set wildcard flag
        is_wildcard = v.startswith("*.")
        
        return v

    @field_validator('is_wildcard', mode='before')
    def set_is_wildcard(cls, v, info):
        if 'domain' in info.data and info.data['domain'].startswith("*."):
            return True
        return v

    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={
            ObjectId: str,
            datetime: lambda dt: dt.isoformat()
        },
        json_schema_extra={
            "example": {
                "domain": "example.com",
                "notes": "Example domain",
                "added_by": "admin",
                "added_date": "2023-01-01T12:34:56",
                "category": "business",
                "tags": ["trusted", "partner"],
                "is_wildcard": False,
                "is_active": True
            }
        }
    )


class WhitelistCreate(BaseModel):
    """Schema for whitelist domain creation."""
    domain: str
    notes: Optional[str] = ""
    added_by: Optional[str] = "system"
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Validate and clean domain."""
        domain = v.strip().lower()
        
        # Handle wildcard domains
        if domain.startswith("*."):
            domain = domain[2:]
            
        # Basic domain format validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")
            
        return v.strip().lower()


class WhitelistUpdate(BaseModel):
    """Schema for whitelist domain updates."""
    domain: Optional[str] = None
    notes: Optional[str] = None
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    is_active: Optional[bool] = None
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Validate domain if provided."""
        if v is None:
            return v
            
        domain = v.strip().lower()
        
        # Handle wildcard domains
        if domain.startswith("*."):
            domain = domain[2:]
            
        # Basic domain format validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")
            
        return v.strip().lower()


class WhitelistResponse(BaseModel):
    """Schema for whitelist responses."""
    id: str = Field(..., alias="_id")
    domain: str
    notes: Optional[str] = ""
    added_by: str
    added_date: datetime
    last_updated: Optional[datetime] = None
    category: Optional[str] = None
    tags: List[str] = []
    is_wildcard: bool
    is_active: bool
    
    model_config = ConfigDict(
        populate_by_alias=True,
        json_schema_extra={
            "example": {
                "_id": "60d6ec9f5e8e7a721c97195a",
                "domain": "example.com",
                "notes": "Example domain",
                "added_by": "admin",
                "added_date": "2023-01-01T12:34:56",
                "last_updated": "2023-01-02T10:11:12",
                "category": "business",
                "tags": ["trusted", "partner"],
                "is_wildcard": False,
                "is_active": True
            }
        }
    )


class WhitelistBulkCreate(BaseModel):
    """Schema for bulk whitelist domain creation."""
    domains: List[str]
    notes: Optional[str] = "Bulk import"
    added_by: Optional[str] = "system"
    category: Optional[str] = None
    tags: Optional[List[str]] = None
    
    @field_validator('domains')
    def validate_domains(cls, domains):
        """Validate all domains in the list."""
        valid_domains = []
        
        for domain in domains:
            if not isinstance(domain, str):
                continue
                
            domain = domain.strip().lower()
            
            # Skip empty domains
            if not domain:
                continue
                
            # Handle wildcard domains for validation
            check_domain = domain
            if domain.startswith("*."):
                check_domain = domain[2:]
                
            # Basic domain format validation
            pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if not re.match(pattern, check_domain):
                continue
                
            valid_domains.append(domain)
            
        return valid_domains