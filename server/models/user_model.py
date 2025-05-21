# Import các thư viện cần thiết
import re  # Thư viện xử lý biểu thức chính quy, dùng để xác thực định dạng username, password
from datetime import datetime  # Thư viện xử lý thời gian, dùng cho các trường thời gian như created_at
from enum import Enum  # Thư viện để định nghĩa các giá trị liệt kê như vai trò và trạng thái người dùng
from typing import Dict, List, Optional, Set, Union, Any  # Thư viện cho kiểu dữ liệu tĩnh

from bson import ObjectId  # Thư viện để làm việc với MongoDB ObjectId
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict  # Thư viện Pydantic để xác thực dữ liệu và tạo model


class PyObjectId(ObjectId):
    """Custom ObjectId type for proper serialization in Pydantic models."""
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        """
        Định nghĩa schema cho Pydantic để xử lý ObjectId.
        Phương thức này được gọi bởi Pydantic để biết cách xử lý kiểu dữ liệu này.
        """
        from pydantic_core import core_schema
        return core_schema.union_schema([
            # Cho phép đối tượng ObjectId trực tiếp
            core_schema.is_instance_schema(ObjectId),
            # Hoặc cho phép chuỗi mà sau đó sẽ được chuyển đổi thành ObjectId
            core_schema.chain_schema([
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(cls.validate),
            ]),
        ])

    @classmethod
    def validate(cls, v):
        """
        Xác thực một giá trị là ObjectId hợp lệ.
        Nếu chuỗi không phải định dạng ObjectId hợp lệ, ném ra lỗi.
        """
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        """
        Điều chỉnh schema cho OpenAPI (Swagger) để hiển thị kiểu dữ liệu này là chuỗi.
        Giúp các công cụ tạo tài liệu API hiểu được kiểu dữ liệu này.
        """
        field_schema.update(type="string")


class UserRole(str, Enum):
    """
    Liệt kê các vai trò người dùng trong hệ thống.
    Dùng Enum để đảm bảo chỉ có các giá trị hợp lệ được sử dụng.
    """
    ADMIN = "admin"  # Quản trị viên: có toàn quyền trên hệ thống
    OPERATOR = "operator"  # Vận hành viên: có thể quản lý whitelist, cấu hình, nhưng không quản lý người dùng
    VIEWER = "viewer"  # Người xem: chỉ có thể xem dữ liệu, không thể thay đổi cấu hình


class UserStatus(str, Enum):
    """
    Liệt kê các trạng thái tài khoản người dùng.
    Dùng để kiểm soát quyền truy cập và xác thực.
    """
    ACTIVE = "active"  # Hoạt động: có thể đăng nhập và sử dụng hệ thống
    INACTIVE = "inactive"  # Không hoạt động: tài khoản bị vô hiệu hóa
    PENDING = "pending"  # Đang chờ: tài khoản mới tạo, chưa được kích hoạt


class User(BaseModel):
    """
    User model for authentication and authorization.
    Defines user properties, preferences, and permissions.
    """
    # Thông tin cơ bản
    id: Optional[PyObjectId] = Field(alias="_id", default=None)  # ID MongoDB, sử dụng alias để tương thích với MongoDB
    username: str = Field(..., min_length=3, max_length=50)  # Tên người dùng, bắt buộc, giới hạn độ dài
    email: EmailStr  # Địa chỉ email, tự động xác thực định dạng email
    password_hash: str  # Mật khẩu đã được mã hóa, không lưu mật khẩu gốc
    full_name: Optional[str] = None  # Họ tên đầy đủ, không bắt buộc
    role: UserRole = UserRole.VIEWER  # Vai trò người dùng, mặc định là Viewer
    status: UserStatus = UserStatus.PENDING  # Trạng thái tài khoản, mặc định là Pending
    
    # Các trường theo dõi thời gian
    created_at: datetime = Field(default_factory=datetime.utcnow)  # Thời điểm tạo tài khoản, tự động là thời gian hiện tại
    updated_at: Optional[datetime] = None  # Thời điểm cập nhật gần nhất
    last_login: Optional[datetime] = None  # Thời điểm đăng nhập gần nhất
    
    # Tùy chọn người dùng
    preferences: Dict = Field(default_factory=dict)  # Lưu trữ các tùy chọn như giao diện, ngôn ngữ, v.v.
    
    # Các trường bảo mật
    api_keys: List[Dict] = Field(default_factory=list)  # Danh sách API key của người dùng
    password_reset_token: Optional[str] = None  # Token đặt lại mật khẩu
    password_reset_expires: Optional[datetime] = None  # Thời hạn của token đặt lại mật khẩu
    login_attempts: int = 0  # Số lần đăng nhập thất bại liên tiếp (dùng để chống brute force)
    
    @field_validator('username')
    def username_alphanumeric(cls, v):
        """
        Xác thực username chỉ chứa ký tự chữ, số, gạch dưới và gạch ngang.
        Đảm bảo username không chứa ký tự đặc biệt có thể gây lỗi.
        """
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v

    # Cấu hình chung cho model
    model_config = ConfigDict(
        populate_by_alias=True,  # Cho phép sử dụng alias khi tạo đối tượng
        arbitrary_types_allowed=True,  # Cho phép các kiểu dữ liệu tùy chỉnh
        json_encoders={ObjectId: str},  # Chuyển ObjectId thành chuỗi khi chuyển sang JSON
        json_schema_extra={
            "example": {  # Ví dụ JSON cho tài liệu API
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
    """
    Schema cho việc tạo người dùng mới.
    Chỉ chứa các trường cần thiết khi tạo tài khoản, không bao gồm các trường hệ thống tự sinh.
    """
    username: str = Field(..., min_length=3, max_length=50)  # Tên người dùng
    email: EmailStr  # Email
    password: str = Field(..., min_length=8)  # Mật khẩu gốc (sẽ được mã hóa trước khi lưu)
    full_name: Optional[str] = None  # Họ tên đầy đủ
    role: UserRole = UserRole.VIEWER  # Vai trò, mặc định là Viewer
    
    @field_validator('username')
    def username_alphanumeric(cls, v):
        """Xác thực định dạng tên người dùng."""
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username must contain only alphanumeric characters, underscores, or hyphens')
        return v

    @field_validator('password')
    def password_strength(cls, v):
        """
        Kiểm tra độ mạnh của mật khẩu.
        Đảm bảo mật khẩu đáp ứng các yêu cầu bảo mật tối thiểu.
        """
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
    """
    Schema cho việc cập nhật thông tin người dùng.
    Tất cả các trường đều là tùy chọn, chỉ cập nhật các trường được cung cấp.
    """
    email: Optional[EmailStr] = None  # Email mới
    full_name: Optional[str] = None  # Tên đầy đủ mới
    role: Optional[UserRole] = None  # Vai trò mới
    status: Optional[UserStatus] = None  # Trạng thái tài khoản mới
    preferences: Optional[Dict] = None  # Tùy chọn người dùng mới


class UserResponse(BaseModel):
    """
    Schema cho việc trả về thông tin người dùng qua API.
    Loại bỏ các trường nhạy cảm như password_hash, token, v.v.
    """
    id: str = Field(..., alias="_id")  # ID MongoDB
    username: str  # Tên người dùng
    email: EmailStr  # Email
    full_name: Optional[str] = None  # Họ tên đầy đủ
    role: UserRole  # Vai trò
    status: UserStatus  # Trạng thái
    created_at: datetime  # Thời điểm tạo
    last_login: Optional[datetime] = None  # Thời điểm đăng nhập gần nhất
    preferences: Dict  # Tùy chọn người dùng

    # Cấu hình chung cho model
    model_config = ConfigDict(
        populate_by_alias=True,  # Cho phép sử dụng alias
        json_schema_extra={
            "example": {  # Ví dụ JSON cho tài liệu API
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
    """
    Schema cho việc đăng nhập.
    Chỉ cần username và password.
    """
    username: str  # Tên người dùng đăng nhập
    password: str  # Mật khẩu đăng nhập (gốc, chưa mã hóa)