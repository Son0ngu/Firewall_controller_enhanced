from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

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


class LogAction(str, Enum):
    """Enumeration of possible log actions."""
    BLOCK = "block"
    ALLOW = "allow"
    WARN = "warn"
    DETECT = "detect"


class Protocol(str, Enum):
    """Enumeration of network protocols."""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TCP = "TCP"
    UDP = "UDP"
    UNKNOWN = "UNKNOWN"


class Log(BaseModel):
    """
    Log model for tracking domain access events.
    Records connection attempts, domains, IPs, and actions taken.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    
    # Event information
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    domain: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[Protocol] = None
    action: LogAction
    
    # Agent information
    agent_id: str
    agent_hostname: Optional[str] = None
    
    # Additional context
    process_name: Optional[str] = None
    user_name: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    notes: Optional[str] = None
    
    # Optional metadata
    metadata: Dict = Field(default_factory=dict)
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Basic domain validation."""
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length")
        return v.lower()
    
    @field_validator('dest_port')
    def validate_port(cls, v):
        """Validate port is in valid range."""
        if v is not None and (v < 0 or v > 65535):
            raise ValueError("Port must be between 0 and 65535")
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
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "protocol": "HTTPS",
                "action": "block",
                "agent_id": "desktop-abc123",
                "agent_hostname": "user-laptop",
                "process_name": "chrome.exe",
                "timestamp": "2023-01-01T12:34:56",
            }
        }
    )


class LogCreate(BaseModel):
    """Schema for log creation/submission from agents."""
    timestamp: Optional[datetime] = None
    domain: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[Protocol] = None
    action: LogAction
    agent_id: str
    agent_hostname: Optional[str] = None
    process_name: Optional[str] = None
    user_name: Optional[str] = None
    category: Optional[str] = None
    rule_id: Optional[str] = None
    notes: Optional[str] = None
    metadata: Optional[Dict] = None
    
    @field_validator('domain')
    def validate_domain(cls, v):
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length")
        return v.lower()


class LogResponse(BaseModel):
    """Schema for log responses."""
    id: str = Field(..., alias="_id")
    timestamp: datetime
    domain: str
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str
    agent_id: str
    agent_hostname: Optional[str] = None
    process_name: Optional[str] = None
    user_name: Optional[str] = None
    category: Optional[str] = None
    
    model_config = ConfigDict(
        populate_by_alias=True,
        json_schema_extra={
            "example": {
                "_id": "60d6ec9f5e8e7a721c97195a",
                "timestamp": "2023-01-01T12:34:56",
                "domain": "example.com",
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "protocol": "HTTPS",
                "action": "block",
                "agent_id": "desktop-abc123",
                "agent_hostname": "user-laptop",
                "process_name": "chrome.exe"
            }
        }
    )


class LogFilterParams(BaseModel):
    """Parameters for filtering logs in queries."""
    agent_id: Optional[str] = None
    domain: Optional[str] = None
    action: Optional[LogAction] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    protocol: Optional[Protocol] = None
    limit: int = 100
    skip: int = 0
    sort_field: str = "timestamp"
    sort_order: str = "desc"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "desktop-abc123",
                "domain": "example",  # Partial match
                "action": "block",
                "since": "2023-01-01T00:00:00",
                "until": "2023-01-02T00:00:00",
                "limit": 50,
                "skip": 0
            }
        }
    )


class LogSummary(BaseModel):
    """Schema for log summary statistics."""
    period: str
    since: datetime
    until: datetime
    actions: Dict[str, int]
    top_blocked_domains: List[Dict[str, Union[str, int]]]
    agents: List[Dict[str, Union[str, int]]]
    total_logs: int