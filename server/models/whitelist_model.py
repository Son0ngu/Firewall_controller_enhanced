# Import các thư viện cần thiết
import re  # Thư viện xử lý biểu thức chính quy, dùng để xác thực định dạng tên miền
from datetime import datetime  # Thư viện xử lý ngày giờ, dùng để ghi thời gian thêm và cập nhật tên miền
from typing import Dict, List, Optional, Set, Union  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

from bson import ObjectId  # Thư viện để làm việc với ObjectId của MongoDB
from pydantic import BaseModel, Field, field_validator, ConfigDict  # Thư viện Pydantic để xác thực dữ liệu và tạo model


class PyObjectId(ObjectId):
    """Custom ObjectId type for proper serialization in Pydantic models."""
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        """
        Định nghĩa schema cho Pydantic để xử lý ObjectId.
        Phương thức này được gọi bởi Pydantic để hiểu cách xử lý kiểu dữ liệu ObjectId.
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
        Kiểm tra nếu chuỗi nhập vào có thể chuyển thành ObjectId MongoDB.
        """
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)

    @classmethod
    def __modify_schema__(cls, field_schema):
        """
        Điều chỉnh schema cho OpenAPI (Swagger) để hiển thị kiểu dữ liệu này là chuỗi.
        Giúp tài liệu API hiển thị kiểu dữ liệu một cách rõ ràng.
        """
        field_schema.update(type="string")


class Whitelist(BaseModel):
    """
    Whitelist model for managing allowed domains.
    Keeps track of domains that should not be blocked by the firewall.
    """
    # Thông tin cơ bản của bản ghi whitelist
    id: Optional[PyObjectId] = Field(alias="_id", default=None)  # ID MongoDB, sử dụng alias để tương thích với MongoDB
    domain: str  # Tên miền (có thể bao gồm wildcard, ví dụ: *.example.com)
    notes: Optional[str] = ""  # Ghi chú về tên miền, mặc định là chuỗi rỗng
    added_by: str = "system"  # Người thêm tên miền, mặc định là "system" nếu được thêm tự động
    added_date: datetime = Field(default_factory=datetime.utcnow)  # Thời điểm thêm tên miền, mặc định là thời gian hiện tại
    last_updated: Optional[datetime] = None  # Thời điểm cập nhật gần nhất, ban đầu là None
    
    # Phân loại tùy chọn
    category: Optional[str] = None  # Danh mục của tên miền (như business, social, v.v.)
    tags: List[str] = Field(default_factory=list)  # Các thẻ gắn với tên miền, mặc định là danh sách rỗng
    
    # Cờ trạng thái
    is_wildcard: bool = False  # Đánh dấu nếu là wildcard domain (*.example.com)
    is_active: bool = True  # Đánh dấu nếu tên miền đang hoạt động, cho phép tạm thời vô hiệu hóa mà không cần xóa
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """
        Xác thực định dạng tên miền - cho phép tên miền wildcard.
        Đảm bảo tên miền tuân theo chuẩn định dạng, bao gồm cả trường hợp wildcard.
        """
        domain = v.strip().lower()  # Loại bỏ khoảng trắng đầu/cuối và chuyển thành chữ thường
        
        # Xử lý tên miền wildcard
        if domain.startswith("*."):
            domain = domain[2:]  # Loại bỏ phần "*." để kiểm tra phần còn lại
            
        # Xác thực định dạng tên miền cơ bản
        # Mẫu này đảm bảo tên miền có ít nhất 2 phần, phần mở rộng ít nhất 2 ký tự
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")  # Báo lỗi nếu không đúng định dạng
            
        # Đặt cờ wildcard
        is_wildcard = v.startswith("*.")
        
        return v  # Trả về tên miền gốc nếu hợp lệ

    @field_validator('is_wildcard', mode='before')
    def set_is_wildcard(cls, v, info):
        """
        Tự động xác định cờ is_wildcard dựa trên tên miền.
        Nếu tên miền bắt đầu bằng "*.", đặt is_wildcard = True.
        """
        if 'domain' in info.data and info.data['domain'].startswith("*."):
            return True  # Đặt is_wildcard = True nếu domain bắt đầu bằng "*."
        return v  # Giữ nguyên giá trị hiện tại nếu không

    # Cấu hình chung cho model
    model_config = ConfigDict(
        populate_by_alias=True,  # Cho phép sử dụng alias khi tạo đối tượng
        arbitrary_types_allowed=True,  # Cho phép các kiểu dữ liệu tùy chỉnh
        json_encoders={  # Định nghĩa cách chuyển đổi các kiểu dữ liệu đặc biệt sang JSON
            ObjectId: str,  # Chuyển ObjectId thành chuỗi
            datetime: lambda dt: dt.isoformat()  # Chuyển datetime thành chuỗi ISO
        },
        json_schema_extra={  # Ví dụ JSON cho tài liệu API
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
    """
    Schema cho việc tạo tên miền whitelist mới thông qua API.
    Chỉ chứa các trường cần thiết khi tạo mới.
    """
    domain: str  # Tên miền cần thêm vào whitelist
    notes: Optional[str] = ""  # Ghi chú tùy chọn
    added_by: Optional[str] = "system"  # Người thêm, mặc định là "system"
    category: Optional[str] = None  # Danh mục tùy chọn
    tags: Optional[List[str]] = None  # Các thẻ tùy chọn
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """
        Xác thực và làm sạch tên miền trước khi thêm.
        Đảm bảo tên miền ở dạng chuẩn hóa và hợp lệ.
        """
        domain = v.strip().lower()  # Loại bỏ khoảng trắng và chuyển thành chữ thường
        
        # Xử lý tên miền wildcard
        if domain.startswith("*."):
            domain = domain[2:]  # Loại bỏ phần "*." để kiểm tra phần còn lại
            
        # Xác thực định dạng tên miền cơ bản
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")  # Báo lỗi nếu không đúng định dạng
            
        return v.strip().lower()  # Trả về tên miền đã được chuẩn hóa


class WhitelistUpdate(BaseModel):
    """
    Schema cho việc cập nhật thông tin tên miền whitelist.
    Tất cả các trường đều là tùy chọn, chỉ cập nhật các trường được cung cấp.
    """
    domain: Optional[str] = None  # Tên miền mới (nếu muốn đổi)
    notes: Optional[str] = None  # Ghi chú mới
    category: Optional[str] = None  # Danh mục mới
    tags: Optional[List[str]] = None  # Các thẻ mới
    is_active: Optional[bool] = None  # Trạng thái hoạt động mới
    
    @field_validator('domain')
    def validate_domain(cls, v):
        """
        Xác thực tên miền nếu được cung cấp.
        Chỉ kiểm tra khi trường domain được cập nhật.
        """
        if v is None:  # Nếu không cung cấp domain, bỏ qua việc xác thực
            return v
            
        domain = v.strip().lower()  # Loại bỏ khoảng trắng và chuyển thành chữ thường
        
        # Xử lý tên miền wildcard
        if domain.startswith("*."):
            domain = domain[2:]  # Loại bỏ phần "*." để kiểm tra phần còn lại
            
        # Xác thực định dạng tên miền cơ bản
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, domain):
            raise ValueError("Invalid domain format")  # Báo lỗi nếu không đúng định dạng
            
        return v.strip().lower()  # Trả về tên miền đã được chuẩn hóa


class WhitelistResponse(BaseModel):
    """
    Schema cho việc trả về thông tin whitelist qua API.
    Đảm bảo dữ liệu được định dạng nhất quán khi trả về cho client.
    """
    id: str = Field(..., alias="_id")  # ID MongoDB
    domain: str  # Tên miền
    notes: Optional[str] = ""  # Ghi chú
    added_by: str  # Người thêm
    added_date: datetime  # Thời điểm thêm
    last_updated: Optional[datetime] = None  # Thời điểm cập nhật gần nhất
    category: Optional[str] = None  # Danh mục
    tags: List[str] = []  # Các thẻ
    is_wildcard: bool  # Cờ đánh dấu wildcard
    is_active: bool  # Trạng thái hoạt động
    
    # Cấu hình chung cho model
    model_config = ConfigDict(
        populate_by_alias=True,  # Cho phép sử dụng alias
        json_schema_extra={  # Ví dụ JSON cho tài liệu API
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
    """
    Schema cho việc tạo hàng loạt tên miền whitelist.
    Cho phép thêm nhiều tên miền cùng lúc với thông tin chung.
    """
    domains: List[str]  # Danh sách các tên miền cần thêm
    notes: Optional[str] = "Bulk import"  # Ghi chú mặc định cho nhập hàng loạt
    added_by: Optional[str] = "system"  # Người thêm, mặc định là "system"
    category: Optional[str] = None  # Danh mục tùy chọn
    tags: Optional[List[str]] = None  # Các thẻ tùy chọn
    
    @field_validator('domains')
    def validate_domains(cls, domains):
        """
        Xác thực tất cả các tên miền trong danh sách.
        Lọc ra các tên miền không hợp lệ và chỉ giữ lại các tên miền hợp lệ.
        """
        valid_domains = []  # Danh sách tên miền hợp lệ
        
        for domain in domains:
            if not isinstance(domain, str):  # Kiểm tra kiểu dữ liệu
                continue  # Bỏ qua nếu không phải chuỗi
                
            domain = domain.strip().lower()  # Loại bỏ khoảng trắng và chuyển thành chữ thường
            
            # Bỏ qua tên miền trống
            if not domain:
                continue
                
            # Xử lý tên miền wildcard cho việc xác thực
            check_domain = domain
            if domain.startswith("*."):
                check_domain = domain[2:]  # Loại bỏ phần "*." để kiểm tra phần còn lại
                
            # Xác thực định dạng tên miền cơ bản
            pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            if not re.match(pattern, check_domain):  # Kiểm tra định dạng
                continue  # Bỏ qua nếu không hợp lệ
                
            valid_domains.append(domain)  # Thêm vào danh sách hợp lệ nếu vượt qua kiểm tra
            
        return valid_domains  # Trả về danh sách các tên miền hợp lệ