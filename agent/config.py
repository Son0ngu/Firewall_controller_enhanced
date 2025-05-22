"""
Configuration module for the Firewall Controller Agent.

This module loads and provides access to all configuration parameters needed by the agent.
Configuration can be sourced from environment variables, a configuration file, or defaults.

Sections:
- Server Connection: URLs and connection parameters
- Authentication: API keys and authentication settings
- Whitelist: Sources and update intervals
- Packet Capture: PyDivert and packet filtering settings
- Logging: Log levels, formats, and destinations
- Firewall: Blocking behavior and rule management
"""

import json  # Thư viện xử lý dữ liệu định dạng JSON
import logging  # Thư viện ghi log
import os  # Thư viện tương tác với hệ điều hành
import sys  # Thư viện cung cấp thông tin về môi trường Python
from pathlib import Path  # Thư viện xử lý đường dẫn file một cách hiện đại
from typing import Any, Dict, List, Optional  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

# Cấu hình logging cho chính module cấu hình
# - Tạo logger riêng cho module này để có thể theo dõi quá trình tải cấu hình
logger = logging.getLogger("config")

# Các hằng số định nghĩa đường dẫn file cấu hình
DEFAULT_CONFIG_FILE = "agent_config.json"  # Tên file cấu hình mặc định
CONFIG_PATHS = [
    # Thư mục hiện tại - được kiểm tra đầu tiên
    Path(DEFAULT_CONFIG_FILE),
    # Thư mục home của người dùng - ưu tiên thứ hai
    Path.home() / ".firewall-controller" / DEFAULT_CONFIG_FILE,
    # Thư mục cấu hình hệ thống (Windows) - ưu tiên thứ ba
    # PROGRAMDATA là biến môi trường Windows, thường là C:\ProgramData
    Path(os.environ.get("PROGRAMDATA", "C:\\ProgramData")) / "FirewallController" / DEFAULT_CONFIG_FILE,
]

# Cấu hình mặc định cho toàn bộ ứng dụng
# - Được sử dụng khi không tìm thấy file cấu hình
# - Các giá trị này có thể bị ghi đè bởi file cấu hình hoặc biến môi trường
DEFAULT_CONFIG = {
    # Cấu hình kết nối đến server
    "server": {
        "url": "http://localhost:5000/api",  # URL cơ sở của API server
        "connect_timeout": 10,  # Thời gian chờ kết nối tối đa (giây)
        "read_timeout": 30,  # Thời gian chờ đọc dữ liệu tối đa (giây)
        "retry_interval": 60,  # Thời gian chờ giữa các lần thử lại (giây)
        "max_retries": 5,  # Số lần thử lại tối đa khi kết nối thất bại
    },
    
    # Cấu hình xác thực
    "auth": {
        "api_key": "",  # Khóa API để xác thực với server (để trống = không xác thực)
        "auth_method": "api_key",  # Phương thức xác thực: api_key, jwt, hoặc none
        "jwt_refresh_interval": 3600,  # Thời gian làm mới token JWT (giây) - 1 giờ
    },
    
    # Cấu hình whitelist (danh sách tên miền được phép)
    "whitelist": {
        "source": "both",  # Nguồn whitelist: file (cục bộ), server (từ server), hoặc both (cả hai)
        "file": "whitelist.json",  # Đường dẫn đến file whitelist cục bộ
        "update_interval": 3600,  # Thời gian giữa các lần cập nhật từ server (giây) - 1 giờ
        "max_size": 100000,  # Số tên miền tối đa trong whitelist
    },
    
    # Cấu hình bắt gói tin mạng
    "packet_capture": {
        "engine": "scapy",  # Thư viện bắt gói tin: pydivert hoặc scapy
        "filter": "outbound and (tcp.DstPort == 80 or tcp.DstPort == 443)",  # Bộ lọc gói tin - chỉ quan tâm đến gói tin đi ra cổng 80 (HTTP) và 443 (HTTPS)
        "buffer_size": 4096,  # Kích thước buffer đọc gói tin (bytes)
        "packet_limit": 0,  # Giới hạn số gói tin bắt được (0 = không giới hạn)
        "interfaces": [],  # Danh sách giao diện mạng cần bắt gói tin (rỗng = tất cả)
        "snaplen": 1500,  # Số byte tối đa cần bắt từ mỗi gói tin (thường là MTU)
    },
    
    # Cấu hình ghi log
    "logging": {
        "level": "INFO",  # Mức độ ghi log: DEBUG, INFO, WARNING, ERROR, CRITICAL
        "file": "agent.log",  # Tên file log
        "max_size": 10485760,  # Kích thước tối đa của file log (10 MB)
        "backup_count": 5,  # Số file log cũ được giữ lại khi xoay vòng (rotation)
        "log_to_console": True,  # Có ghi log ra màn hình không
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",  # Định dạng của log
        
        # Cấu hình gửi log đến server
        "sender": {
            "enabled": True,  # Có gửi log đến server không
            "batch_size": 100,  # Số lượng log tối đa gửi trong một lần
            "max_queue_size": 1000,  # Kích thước hàng đợi log tối đa
            "send_interval": 30,  # Thời gian giữa các lần gửi log (giây)
            "failures_before_warn": 3,  # Số lần gửi thất bại trước khi cảnh báo
        }
    },
    
    # Cấu hình tường lửa
    "firewall": {
        "enabled": True,  # Có sử dụng tường lửa để chặn không
        "mode": "block",  # Chế độ: block (chặn), warn (cảnh báo), monitor (chỉ giám sát)
        "rule_prefix": "sown",  # Tiền tố cho tên các quy tắc tường lửa
        "include_domain_in_rule": True,  # Có đưa tên miền vào tên quy tắc không
        "cleanup_on_exit": True,  # Có xóa các quy tắc khi thoát không
        "block_timeout": 0,  # Thời gian chặn (giây), 0 = vĩnh viễn
    },
    
    # Cấu hình chung
    "general": {
        "agent_name": "",  # Tên của agent, tự động tạo nếu để trống
        "startup_delay": 0,  # Thời gian chờ trước khi khởi động (giây)
        "check_admin": True,  # Có kiểm tra quyền admin khi khởi động không
    }
}


def load_config() -> Dict[str, Any]:
    """
    Load configuration from multiple sources, with the following precedence:
    1. Environment variables
    2. Configuration file
    3. Default values
    
    Returns:
        Dict: Complete configuration dictionary
    """
    # Khởi đầu với cấu hình mặc định - sao chép để tránh thay đổi trực tiếp vào DEFAULT_CONFIG
    config = DEFAULT_CONFIG.copy()
    
    # Tải cấu hình từ file nếu có - ưu tiên hơn cấu hình mặc định
    file_config = _load_from_file()
    if file_config:
        _deep_update(config, file_config)  # Cập nhật cấu hình mặc định với cấu hình từ file
    
    # Ghi đè bằng các biến môi trường - ưu tiên cao nhất
    env_config = _load_from_env()
    if env_config:
        _deep_update(config, env_config)  # Cập nhật cấu hình với các giá trị từ biến môi trường
    
    # Xác thực cấu hình cuối cùng - kiểm tra các giá trị không hợp lệ
    _validate_config(config)
    
    return config


def _load_from_file() -> Optional[Dict[str, Any]]:
    """
    Load configuration from the first available config file.
    
    Returns:
        Optional[Dict]: Configuration from file, or None if no file found
    """
    # Kiểm tra đường dẫn cấu hình từ biến môi trường trước tiên
    # - Cho phép chỉ định rõ file cấu hình qua biến môi trường FIREWALL_CONTROLLER_CONFIG
    env_path = os.environ.get("FIREWALL_CONTROLLER_CONFIG")
    if env_path:
        config_paths = [Path(env_path)]  # Nếu có biến môi trường, chỉ kiểm tra file này
    else:
        config_paths = CONFIG_PATHS  # Nếu không, kiểm tra tất cả các đường dẫn mặc định
    
    # Thử từng đường dẫn
    for path in config_paths:
        try:
            if path.exists():
                logger.info(f"Loading configuration from {path}")
                with open(path, "r") as f:
                    return json.load(f)  # Đọc và parse file JSON
        except Exception as e:
            # Ghi log nếu có lỗi khi đọc file nhưng tiếp tục thử file tiếp theo
            logger.warning(f"Error reading config file {path}: {str(e)}")
    
    # Nếu không tìm thấy file cấu hình nào, trả về None
    return None


def _load_from_env() -> Dict[str, Any]:
    """
    Load configuration from environment variables.
    Environment variables should be prefixed with FC_ and use double underscore
    as separator for nested keys, e.g., FC_SERVER__URL for server.url.
    
    Returns:
        Dict: Configuration from environment variables
    """
    config = {}  # Dictionary rỗng để lưu cấu hình từ biến môi trường
    prefix = "FC_"  # Tiền tố cho biến môi trường liên quan đến Firewall Controller
    
    # Duyệt qua tất cả biến môi trường
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Bỏ tiền tố và phân tách theo dấu gạch dưới kép
            # Ví dụ: FC_SERVER__URL -> ["server", "url"]
            key_parts = key[len(prefix):].lower().split("__")
            
            # Xây dựng cấu trúc dict lồng nhau
            current = config  # Bắt đầu từ dictionary gốc
            # Duyệt qua các phần của key (trừ phần cuối)
            for part in key_parts[:-1]:
                if part not in current:
                    current[part] = {}  # Tạo dict con nếu chưa tồn tại
                current = current[part]  # Di chuyển đến dict con
            
            # Gán giá trị cho key cuối cùng, với chuyển đổi kiểu dữ liệu phù hợp
            current[key_parts[-1]] = _convert_value(value)
    
    return config


def _convert_value(value: str) -> Any:
    """
    Convert string values from environment variables to appropriate types.
    
    Args:
        value: String value to convert
        
    Returns:
        Converted value of appropriate type
    """
    # Cố gắng chuyển đổi chuỗi sang kiểu dữ liệu phù hợp
    # Boolean: true/false, yes/no, 1/0
    if value.lower() in ["true", "yes", "1"]:
        return True
    elif value.lower() in ["false", "no", "0"]:
        return False
    # None/null
    elif value.lower() in ["none", "null"]:
        return None
    # Số nguyên
    elif value.isdigit():
        return int(value)
    # Số thực (float)
    elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
        return float(value)
    else:
        # Thử phân tích chuỗi như JSON (cho danh sách, dict)
        try:
            return json.loads(value)  # Có thể parse chuỗi JSON thành list, dict
        except json.JSONDecodeError:
            return value  # Nếu không phải JSON, giữ nguyên chuỗi


def _deep_update(base_dict: Dict, update_dict: Dict) -> None:
    """
    Recursively update a dictionary with another dictionary.
    
    Args:
        base_dict: Dictionary to update
        update_dict: Dictionary with updates
    """
    # Cập nhật từng key trong update_dict vào base_dict
    for key, value in update_dict.items():
        # Nếu cả hai đều là dict, đệ quy để cập nhật sâu hơn
        if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
            _deep_update(base_dict[key], value)  # Đệ quy cập nhật dict con
        else:
            # Nếu không phải cả hai là dict, thì ghi đè giá trị trực tiếp
            base_dict[key] = value


def _validate_config(config: Dict) -> None:
    """
    Validate the configuration.
    
    Args:
        config: Configuration dictionary to validate
    """
    # Kiểm tra các trường bắt buộc
    # URL server là quan trọng vì nhiều tính năng phụ thuộc vào nó
    if not config["server"]["url"]:
        logger.warning("Server URL is not configured")
    
    # Kiểm tra xác thực
    # Nếu dùng api_key nhưng không cung cấp key
    if config["auth"]["auth_method"] == "api_key" and not config["auth"]["api_key"]:
        logger.warning("API key authentication is enabled but no API key is provided")
    
    # Kiểm tra whitelist
    # Nếu lấy whitelist từ server nhưng không có URL server
    if config["whitelist"]["source"] in ["server", "both"] and not config["server"]["url"]:
        logger.warning("Whitelist source includes 'server' but server URL is not configured")
    
    # Kiểm tra engine bắt gói tin
    # Đảm bảo engine được chọn là hợp lệ
    if config["packet_capture"]["engine"] not in ["scapy"]:
        logger.warning(f"Unknown packet capture engine: {config['packet_capture']['engine']}")
    
    # Kiểm tra chế độ tường lửa
    # Đảm bảo mode tường lửa là hợp lệ
    if config["firewall"]["enabled"] and config["firewall"]["mode"] not in ["block", "warn", "monitor"]:
        logger.warning(f"Unknown firewall mode: {config['firewall']['mode']}")


def get_config() -> Dict[str, Any]:
    """
    Get the loaded configuration.
    
    Returns:
        Dict: Complete configuration dictionary
    """
    global _config  # Sử dụng biến toàn cục để lưu trữ cấu hình
    if _config is None:
        _config = load_config()  # Tải cấu hình nếu chưa được tải
    return _config


def save_config(config: Dict[str, Any], path: Optional[str] = None) -> bool:
    """
    Save configuration to a file.
    
    Args:
        config: Configuration dictionary to save
        path: Path to save to, defaults to the first path in CONFIG_PATHS
        
    Returns:
        bool: True if successful, False otherwise
    """
    if path is None:
        # Sử dụng đường dẫn mặc định đầu tiên nếu không chỉ định
        path = os.environ.get("FIREWALL_CONTROLLER_CONFIG", str(CONFIG_PATHS[0]))
    
    try:
        # Đảm bảo thư mục tồn tại
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Ghi file cấu hình
        with open(path, "w") as f:
            json.dump(config, f, indent=2)  # Ghi với định dạng đẹp (có thụt đầu dòng)
        
        logger.info(f"Configuration saved to {path}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration to {path}: {str(e)}")
        return False


# Khởi tạo biến cấu hình toàn cục
_config = None


# Ví dụ sử dụng (khi chạy file này trực tiếp)
if __name__ == "__main__":
    # Cấu hình logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Tải cấu hình
    config = get_config()
    
    # In cấu hình
    print("Current configuration:")
    print(json.dumps(config, indent=2))
    
    # Ví dụ: Cập nhật và lưu cấu hình
    if len(sys.argv) > 1 and sys.argv[1] == "--save-example":
        config["server"]["url"] = "https://example.com/api"
        config["auth"]["api_key"] = "example_key"
        save_config(config, "example_config.json")
        print("Example configuration saved to example_config.json")