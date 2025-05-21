from datetime import datetime  # Thư viện xử lý ngày giờ, dùng để ghi thời gian của sự kiện log
from enum import Enum  # Thư viện để tạo các kiểu dữ liệu liệt kê (enum)
from typing import Dict, List, Optional, Union  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

from bson import ObjectId  # Thư viện để làm việc với MongoDB ObjectId
from pydantic import BaseModel, Field, field_validator, ConfigDict  # Thư viện Pydantic để xác thực dữ liệu và tạo model


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
        Chuyển đổi chuỗi thành ObjectId nếu định dạng hợp lệ.
        """
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        """
        Điều chỉnh schema cho OpenAPI (Swagger) để hiển thị kiểu dữ liệu này là chuỗi.
        """
        field_schema.update(type="string")


class LogAction(str, Enum):
    """Enumeration of possible log actions."""
    BLOCK = "block"  # Hành động chặn kết nối
    ALLOW = "allow"  # Hành động cho phép kết nối
    WARN = "warn"    # Hành động cảnh báo nhưng vẫn cho phép kết nối
    DETECT = "detect"  # Chỉ phát hiện kết nối mà không thực hiện hành động


class Protocol(str, Enum):
    """Enumeration of network protocols."""
    HTTP = "HTTP"        # Giao thức HTTP (port 80)
    HTTPS = "HTTPS"      # Giao thức HTTPS (port 443)
    DNS = "DNS"          # Giao thức DNS (port 53)
    TCP = "TCP"          # Giao thức TCP chung
    UDP = "UDP"          # Giao thức UDP chung
    UNKNOWN = "UNKNOWN"  # Không xác định được giao thức


class Log(BaseModel):
    """
    Log model for tracking domain access events.
    Records connection attempts, domains, IPs, and actions taken.
    """
    # ID của log, được tạo tự động bởi MongoDB
    # Sử dụng alias "_id" để phù hợp với quy ước của MongoDB
    id: Optional[PyObjectId] = Field(alias="_id", default=None)
    
    # Thông tin về sự kiện
    timestamp: datetime = Field(default_factory=datetime.utcnow)  # Thời điểm xảy ra sự kiện, mặc định là thời gian hiện tại
    domain: str  # Tên miền được truy cập
    dest_ip: Optional[str] = None  # Địa chỉ IP đích
    dest_port: Optional[int] = None  # Cổng đích
    protocol: Optional[Protocol] = None  # Giao thức mạng sử dụng
    action: LogAction  # Hành động đã thực hiện (block/allow/warn/detect)
    
    # Thông tin về agent
    agent_id: str  # ID của agent báo cáo sự kiện
    agent_hostname: Optional[str] = None  # Tên máy chủ của agent
    
    # Thông tin bổ sung
    process_name: Optional[str] = None  # Tên tiến trình thực hiện kết nối
    user_name: Optional[str] = None  # Tên người dùng thực hiện kết nối
    category: Optional[str] = None  # Phân loại tên miền (ví dụ: quảng cáo, độc hại)
    rule_id: Optional[str] = None  # ID của quy tắc được áp dụng
    notes: Optional[str] = None  # Ghi chú bổ sung
    
    # Metadata tùy chọn - dữ liệu phụ lưu trữ thông tin bổ sung
    metadata: Dict = Field(default_factory=dict)
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Xác thực cơ bản cho tên miền."""
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length")
        return v.lower()  # Chuyển về chữ thường để đồng nhất dữ liệu
    
    @field_validator('dest_port')
    def validate_port(cls, v):
        """Xác thực cổng nằm trong khoảng hợp lệ."""
        if v is not None and (v < 0 or v > 65535):
            raise ValueError("Port must be between 0 and 65535")
        return v

    # Cấu hình chung cho model
    model_config = ConfigDict(
        # Cho phép tạo instance từ dữ liệu có alias
        populate_by_alias=True,
        # Cho phép các kiểu dữ liệu tùy chỉnh không được Pydantic biết trước
        arbitrary_types_allowed=True,
        # Bộ mã hóa JSON tùy chỉnh cho các kiểu dữ liệu đặc biệt
        json_encoders={
            ObjectId: str,  # Chuyển ObjectId thành chuỗi
            datetime: lambda dt: dt.isoformat()  # Chuyển datetime thành chuỗi ISO
        },
        # Ví dụ cho schema JSON
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
    """
    Schema cho việc tạo/gửi log từ các agent.
    Được thiết kế đơn giản hơn Log để dễ dàng gửi dữ liệu từ agent lên server.
    """
    timestamp: Optional[datetime] = None  # Thời điểm xảy ra sự kiện, có thể được tạo tự động nếu không cung cấp
    domain: str  # Tên miền được truy cập
    dest_ip: Optional[str] = None  # Địa chỉ IP đích
    dest_port: Optional[int] = None  # Cổng đích
    protocol: Optional[Protocol] = None  # Giao thức mạng sử dụng
    action: LogAction  # Hành động đã thực hiện
    agent_id: str  # ID của agent báo cáo
    agent_hostname: Optional[str] = None  # Tên máy chủ của agent
    process_name: Optional[str] = None  # Tên tiến trình
    user_name: Optional[str] = None  # Tên người dùng
    category: Optional[str] = None  # Phân loại tên miền
    rule_id: Optional[str] = None  # ID của quy tắc
    notes: Optional[str] = None  # Ghi chú bổ sung
    metadata: Optional[Dict] = None  # Dữ liệu phụ
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """Xác thực cơ bản cho tên miền."""
        if not v or len(v) > 253:
            raise ValueError("Invalid domain length")
        return v.lower()  # Chuyển về chữ thường để đồng nhất dữ liệu


class LogResponse(BaseModel):
    """
    Schema cho việc trả về log trong các API.
    Chỉ chứa các trường cần thiết để hiển thị.
    """
    id: str = Field(..., alias="_id")  # ID của log, bắt buộc phải có
    timestamp: datetime  # Thời điểm sự kiện
    domain: str  # Tên miền
    dest_ip: Optional[str] = None  # Địa chỉ IP đích
    dest_port: Optional[int] = None  # Cổng đích
    protocol: Optional[str] = None  # Giao thức
    action: str  # Hành động đã thực hiện
    agent_id: str  # ID của agent
    agent_hostname: Optional[str] = None  # Tên máy chủ
    process_name: Optional[str] = None  # Tên tiến trình
    user_name: Optional[str] = None  # Tên người dùng
    category: Optional[str] = None  # Phân loại
    
    # Cấu hình chung cho model
    model_config = ConfigDict(
        # Cho phép tạo instance từ dữ liệu có alias
        populate_by_alias=True,
        # Ví dụ cho schema JSON
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
    """
    Tham số để lọc log trong các truy vấn.
    Dùng trong API để lọc và tìm kiếm log.
    """
    agent_id: Optional[str] = None  # Lọc theo ID agent
    domain: Optional[str] = None  # Lọc theo tên miền (có thể là một phần của tên miền)
    action: Optional[LogAction] = None  # Lọc theo hành động
    since: Optional[datetime] = None  # Lọc từ thời điểm này
    until: Optional[datetime] = None  # Lọc đến thời điểm này
    protocol: Optional[Protocol] = None  # Lọc theo giao thức
    limit: int = 100  # Giới hạn số lượng kết quả, mặc định là 100
    skip: int = 0  # Số lượng kết quả bỏ qua, dùng cho phân trang
    sort_field: str = "timestamp"  # Trường sắp xếp, mặc định theo thời gian
    sort_order: str = "desc"  # Thứ tự sắp xếp, mặc định là giảm dần

    # Cấu hình và ví dụ
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "desktop-abc123",
                "domain": "example",  # Khớp một phần
                "action": "block",
                "since": "2023-01-01T00:00:00",
                "until": "2023-01-02T00:00:00",
                "limit": 50,
                "skip": 0
            }
        }
    )


class LogSummary(BaseModel):
    """
    Schema cho thống kê tóm tắt log.
    Dùng để hiển thị dashboard và báo cáo.
    """
    period: str  # Khoảng thời gian của thống kê (ví dụ: "day", "week", "month")
    since: datetime  # Thời điểm bắt đầu thống kê
    until: datetime  # Thời điểm kết thúc thống kê
    actions: Dict[str, int]  # Số lượng mỗi loại hành động (block/allow/warn)
    top_blocked_domains: List[Dict[str, Union[str, int]]]  # Danh sách tên miền bị chặn nhiều nhất
    agents: List[Dict[str, Union[str, int]]]  # Thống kê theo agent
    total_logs: int  # Tổng số log trong khoảng thời gian