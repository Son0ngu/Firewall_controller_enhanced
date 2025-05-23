# Import các thư viện cần thiết
import re  # Thư viện xử lý biểu thức chính quy
from datetime import datetime  # Thư viện xử lý thời gian
from enum import Enum  # Thư viện để định nghĩa các giá trị liệt kê
from typing import Dict, List, Optional, Set, Union, Any  # Thư viện cho kiểu dữ liệu tĩnh

from bson import ObjectId  # Thư viện để làm việc với MongoDB ObjectId
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict  # Thư viện Pydantic


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
    """
    Vai trò người dùng trong hệ thống.
    """
    ADMIN = "admin"  # Quản trị viên: có toàn quyền và có thể đăng nhập để monitoring
    USER = "user"    # Người dùng thông thường: agent gửi log và whitelist


class UserStatus(str, Enum):
    """
    Liệt kê các trạng thái tài khoản người dùng.
    """
    ACTIVE = "active"    # Hoạt động: có thể gửi log và whitelist
    INACTIVE = "inactive"  # Không hoạt động: bị vô hiệu hóa


class AdminUser(BaseModel):
    """
    Model cho tài khoản admin duy nhất.
    Có đầy đủ thông tin xác thực và quyền quản trị.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field(..., min_length=3, max_length=50)
    password_hash: str  # Mật khẩu đã được mã hóa
    email: Optional[EmailStr] = None
    role: UserRole = UserRole.ADMIN  # Luôn là admin
    last_login: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Cấu hình
    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class Agent(BaseModel):
    """
    Model cho các agent gửi log và whitelist lên server.
    Chỉ cần username để định danh, không cần mật khẩu.
    """
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    username: str = Field(..., min_length=3, max_length=50)  # Tên định danh của agent
    hostname: Optional[str] = None  # Tên máy chủ agent đang chạy
    ip_address: Optional[str] = None  # Địa chỉ IP của agent
    platform: Optional[str] = None  # Thông tin nền tảng (Windows, Linux, etc)
    status: UserStatus = UserStatus.ACTIVE
    role: UserRole = UserRole.USER  # Luôn là user
    
    # Thông tin giám sát
    last_seen: Optional[datetime] = None  # Thời điểm cuối cùng agent gửi log
    last_ip: Optional[str] = None  # IP cuối cùng của agent khi gửi log
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Agent key để xác thực API
    api_key: Optional[str] = None
    
    @field_validator('username')
    def username_alphanumeric(cls, v):
        """Xác thực username chỉ chứa ký tự chữ, số, gạch dưới và gạch ngang."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v
    
    # Cấu hình
    model_config = ConfigDict(
        populate_by_alias=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class UserLogin(BaseModel):
    """
    Schema cho việc đăng nhập admin.
    """
    username: str  # Tên người dùng đăng nhập
    password: str  # Mật khẩu đăng nhập (gốc, chưa mã hóa)


class AgentRegistration(BaseModel):
    """
    Schema cho việc đăng ký agent mới.
    """
    username: str  # Tên định danh của agent
    hostname: str  # Tên máy chủ
    ip_address: str  # Địa chỉ IP
    platform: str  # Thông tin nền tảng