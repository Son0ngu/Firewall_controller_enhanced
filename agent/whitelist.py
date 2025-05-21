# Import các thư viện cần thiết
import json  # Thư viện xử lý dữ liệu định dạng JSON
import logging  # Thư viện ghi log
import os  # Thư viện tương tác với hệ điều hành
import re  # Thư viện xử lý biểu thức chính quy
import threading  # Thư viện hỗ trợ đa luồng
import time  # Thư viện xử lý thời gian
from datetime import datetime  # Thư viện xử lý ngày tháng
from typing import Dict, List, Optional, Set, Union  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

import requests  # Thư viện HTTP để lấy dữ liệu từ server

# Cấu hình logger cho module này
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """
    Manages the whitelist of allowed domains.
    Provides functionality to load whitelist from local file or server,
    check if domains are allowed, and update the whitelist periodically.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the whitelist manager.
        
        Args:
            config: Configuration dictionary with keys:
                - server_url: URL of the server API
                - api_key: API key for authentication
                - whitelist_source: "file" or "server" or "both"
                - whitelist_file: Path to local whitelist file
                - update_interval: Seconds between whitelist updates (if server used)
        """
        # Lưu trữ cấu hình gốc để tham chiếu khi cần
        self.config = config
        
        # Trích xuất các giá trị cấu hình với giá trị mặc định
        # - server_url: URL của API server để lấy whitelist
        # - api_key: Khóa API để xác thực với server
        # - whitelist_source: Nguồn của whitelist (file, server hoặc cả hai)
        # - whitelist_file: Đường dẫn tới file whitelist cục bộ
        # - update_interval: Thời gian giữa các lần cập nhật whitelist từ server (giây)
        self.server_url = config.get("server_url", "")
        self.api_key = config.get("api_key", "")
        self.whitelist_source = config.get("whitelist_source", "both")
        self.whitelist_file = config.get("whitelist_file", "whitelist.json")
        self.update_interval = config.get("update_interval", 3600)  # Mặc định: 1 giờ
        
        # Khởi tạo cấu trúc dữ liệu whitelist
        # - domains: Tập hợp (Set) các tên miền được phép, sử dụng Set để tìm kiếm nhanh O(1)
        # - last_updated: Thời điểm cập nhật cuối cùng, dùng cho cập nhật gia tăng
        # - update_lock: Khóa để đồng bộ hóa khi cập nhật whitelist
        # - update_thread: Luồng cho việc cập nhật định kỳ
        # - running: Cờ báo hiệu trạng thái hoạt động của luồng cập nhật
        self.domains: Set[str] = set()  # Tập hợp cho phép tìm kiếm nhanh O(1)
        self.last_updated: Optional[datetime] = None
        self.update_lock = threading.Lock()
        self.update_thread = None
        self.running = False
        
        # Tải whitelist ban đầu
        self.load_whitelist()
    
    def start_periodic_updates(self):
        """Start periodic updates of the whitelist from server."""
        # Kiểm tra nếu đã đang chạy thì không khởi động lại
        if self.running:
            logger.warning("Whitelist updater is already running")
            return
        
        # Chỉ bắt đầu cập nhật định kỳ nếu nguồn whitelist là server hoặc both
        if self.whitelist_source in ["server", "both"]:
            # Đánh dấu là đang chạy
            self.running = True
            
            # Tạo và khởi động luồng cập nhật
            # - target=self._update_loop: Hàm sẽ được thực thi trong luồng
            # - daemon=True: Khi chương trình chính kết thúc, luồng này sẽ tự động kết thúc
            self.update_thread = threading.Thread(target=self._update_loop)
            self.update_thread.daemon = True
            self.update_thread.start()
            
            logger.info("Started periodic whitelist updates every %d seconds", self.update_interval)
        else:
            # Nếu nguồn chỉ là file thì không cần cập nhật định kỳ
            logger.info("Whitelist source is set to 'file', periodic updates disabled")
    
    def stop_periodic_updates(self):
        """Stop periodic updates of the whitelist."""
        # Đánh dấu yêu cầu dừng luồng cập nhật
        self.running = False
        
        # Nếu có luồng cập nhật, chờ cho nó kết thúc
        if self.update_thread:
            # Chờ luồng kết thúc với timeout 3 giây
            # Tránh treo chương trình nếu luồng không kết thúc
            self.update_thread.join(timeout=3)
            
            # Kiểm tra xem luồng có thực sự dừng hay không
            if self.update_thread.is_alive():
                # Ghi log cảnh báo nếu luồng không dừng được
                logger.warning("Whitelist update thread did not terminate gracefully")
    
    def _update_loop(self):
        """Background thread for periodic whitelist updates."""
        # Vòng lặp chạy liên tục khi updater đang hoạt động
        while self.running:
            try:
                # Cập nhật whitelist từ server
                self.update_whitelist_from_server()
                
                # Ngủ theo chu kỳ cập nhật được cấu hình
                # Chia nhỏ thời gian ngủ để có thể dừng nhanh hơn khi cần
                for _ in range(self.update_interval):
                    # Kiểm tra nếu có yêu cầu dừng
                    if not self.running:
                        break
                    # Ngủ 1 giây mỗi lần để có thể phản ứng nhanh khi dừng
                    time.sleep(1)
                    
            except Exception as e:
                # Bắt các lỗi không lường trước để luồng không bị dừng đột ngột
                logger.error("Error in whitelist update loop: %s", str(e))
                # Ngủ 60 giây trước khi thử lại để tránh tạo tải quá mức cho server khi có lỗi
                time.sleep(60)
    
    def load_whitelist(self):
        """
        Load the whitelist from the configured source(s).
        """
        # Sử dụng khóa để đảm bảo chỉ một luồng có thể cập nhật whitelist tại một thời điểm
        with self.update_lock:
            # Reset danh sách tên miền
            self.domains = set()
            
            # Tải từ file nếu được chỉ định
            if self.whitelist_source in ["file", "both"]:
                self._load_from_file()
                
            # Tải từ server nếu được chỉ định
            if self.whitelist_source in ["server", "both"]:
                self.update_whitelist_from_server()
            
            # Ghi log thông tin về số lượng tên miền đã tải
            logger.info("Loaded whitelist with %d domains", len(self.domains))
    
    def _load_from_file(self):
        """Load whitelist from the local file."""
        try:
            # Kiểm tra xem file whitelist có tồn tại không
            if os.path.exists(self.whitelist_file):
                # Mở và đọc file JSON
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                
                # Xử lý dữ liệu tùy thuộc vào định dạng
                if isinstance(data, dict) and "domains" in data:
                    # Định dạng mới: {"domains": [...], "last_updated": "..."}
                    domains = data.get("domains", [])
                    last_updated_str = data.get("last_updated")
                    
                    # Phân tích thời gian cập nhật cuối cùng nếu có
                    if last_updated_str:
                        try:
                            self.last_updated = datetime.fromisoformat(last_updated_str)
                        except ValueError:
                            # Nếu định dạng thời gian không hợp lệ, sử dụng thời gian hiện tại
                            self.last_updated = datetime.now()
                
                elif isinstance(data, list):
                    # Định dạng đơn giản: chỉ là danh sách tên miền
                    domains = data
                    self.last_updated = datetime.now()
                
                else:
                    # Định dạng không hợp lệ
                    domains = []
                    logger.warning("Invalid format in whitelist file %s", self.whitelist_file)
                
                # Thêm tất cả các tên miền hợp lệ vào tập hợp
                for domain in domains:
                    if isinstance(domain, str) and self._is_valid_domain(domain):
                        self.domains.add(domain)
                
                # Ghi log số lượng tên miền đã tải
                logger.info("Loaded %d domains from file %s", len(self.domains), self.whitelist_file)
            
            else:
                # File không tồn tại, ghi log cảnh báo
                logger.warning("Whitelist file not found: %s", self.whitelist_file)
                # Tạo whitelist mặc định với các tên miền phổ biến
                self._create_default_whitelist()
                
        except Exception as e:
            # Bắt các lỗi có thể xảy ra khi đọc file
            logger.error("Error loading whitelist from file: %s", str(e))
            # Tạo whitelist mặc định nếu không thể tải từ file
            self._create_default_whitelist()
    
    def _create_default_whitelist(self):
        """Create a default whitelist with common safe domains."""
        # Danh sách các tên miền phổ biến và an toàn
        default_domains = [
            "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
            "github.com", "www.github.com", "stackoverflow.com", "www.stackoverflow.com",
            "wikipedia.org", "www.wikipedia.org"
        ]
        
        # Thêm các tên miền mặc định vào tập hợp
        for domain in default_domains:
            self.domains.add(domain)
        
        # Cập nhật thời gian cập nhật cuối cùng
        self.last_updated = datetime.now()
        
        # Lưu whitelist mặc định vào file
        self._save_to_file()
        
        # Ghi log thông tin
        logger.info("Created default whitelist with %d domains", len(self.domains))
    
    def update_whitelist_from_server(self) -> bool:
        """
        Fetch the latest whitelist from the server.
        
        Returns:
            bool: True if update successful, False otherwise
        """
        # Kiểm tra xem URL server có được cấu hình không
        if not self.server_url:
            logger.warning("Server URL not configured, cannot update whitelist from server")
            return False
            
        try:
            # Chuẩn bị headers cho request HTTP
            headers = {}
            # Thêm header xác thực nếu có API key
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
            # Chuẩn bị tham số truy vấn
            # Nếu có thời gian cập nhật cuối cùng, gửi nó để chỉ nhận các bản cập nhật mới
            params = {}
            if self.last_updated:
                params["since"] = self.last_updated.isoformat()
                
            # Tạo URL đầy đủ cho API
            url = f"{self.server_url.rstrip('/')}/api/whitelist"
            
            # Gửi request GET đến server
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            # Xử lý phản hồi dựa trên mã trạng thái HTTP
            if response.status_code == 200:
                # Thành công, phân tích dữ liệu JSON
                data = response.json()
                
                # Sử dụng khóa để đảm bảo an toàn khi cập nhật
                with self.update_lock:
                    if "domains" in data:
                        # Trường hợp thay thế hoàn toàn
                        new_domains = set()
                        for domain in data["domains"]:
                            if isinstance(domain, str) and self._is_valid_domain(domain):
                                new_domains.add(domain)
                                
                        # Thay thế tập hợp domains hiện tại
                        self.domains = new_domains
                    
                    elif isinstance(data, list):
                        # Trường hợp danh sách tên miền - cập nhật gia tăng
                        for domain in data:
                            if isinstance(domain, str) and self._is_valid_domain(domain):
                                self.domains.add(domain)
                    
                    # Cập nhật thời gian cập nhật cuối cùng
                    self.last_updated = datetime.now()
                    
                    # Lưu whitelist đã cập nhật vào file nếu sử dụng nguồn "both"
                    if self.whitelist_source == "both":
                        self._save_to_file()
                    
                    # Ghi log thông tin cập nhật
                    logger.info("Updated whitelist from server, now contains %d domains", len(self.domains))
                
                return True
                
            elif response.status_code == 304:
                # Không thay đổi, whitelist của chúng ta đã là mới nhất
                logger.debug("Whitelist is already up-to-date")
                return True
                
            else:
                # Lỗi khác từ server
                logger.error("Failed to update whitelist from server: HTTP %d %s", 
                             response.status_code, response.text)
                return False
                
        except requests.RequestException as e:
            # Bắt lỗi kết nối đến server
            logger.error("Error connecting to server for whitelist update: %s", str(e))
            return False
        except json.JSONDecodeError:
            # Bắt lỗi khi phản hồi không phải JSON hợp lệ
            logger.error("Invalid JSON response from server")
            return False
        except Exception as e:
            # Bắt các lỗi không lường trước khác
            logger.error("Unexpected error updating whitelist from server: %s", str(e))
            return False
    
    def _save_to_file(self):
        """Save the current whitelist to the local file."""
        try:
            # Tạo cấu trúc dữ liệu để lưu
            # Bao gồm danh sách tên miền và thời gian cập nhật
            data = {
                "domains": list(self.domains),  # Chuyển set thành list để có thể serialize
                "last_updated": self.last_updated.isoformat() if self.last_updated else None
            }
            
            # Ghi dữ liệu vào file
            with open(self.whitelist_file, 'w') as f:
                json.dump(data, f, indent=2)  # Sử dụng indent=2 để file dễ đọc hơn
                
            # Ghi log cấp độ debug
            logger.debug("Saved whitelist to file %s", self.whitelist_file)
        
        except Exception as e:
            # Bắt các lỗi có thể xảy ra khi ghi file
            logger.error("Error saving whitelist to file: %s", str(e))
    
    def is_allowed(self, domain: str) -> bool:
        """
        Check if a domain is in the whitelist.
        
        Args:
            domain: The domain name to check
            
        Returns:
            bool: True if domain is allowed, False otherwise
        """
        # Kiểm tra đầu vào hợp lệ
        if not domain:
            return False
            
        # Chuẩn hóa tên miền (loại bỏ khoảng trắng, chuyển thành chữ thường)
        domain = domain.strip().lower()
        
        # Kiểm tra khớp trực tiếp
        if domain in self.domains:
            return True
            
        # Kiểm tra các tên miền cha
        # Ví dụ: nếu sub.example.com không có trong whitelist,
        # kiểm tra xem *.example.com có trong whitelist không
        parts = domain.split('.')
        for i in range(1, len(parts) - 1):
            # Tạo tên miền cha
            parent_domain = '.'.join(parts[i:])
            # Kiểm tra xem wildcard domain có trong whitelist không
            if f"*.{parent_domain}" in self.domains:
                return True
        
        # Nếu không tìm thấy, tên miền không được phép
        return False
    
    def add_domain(self, domain: str) -> bool:
        """
        Add a domain to the whitelist.
        
        Args:
            domain: The domain to add
            
        Returns:
            bool: True if domain was added, False if invalid or already exists
        """
        # Kiểm tra tính hợp lệ của tên miền
        if not domain or not self._is_valid_domain(domain):
            logger.warning("Invalid domain format: %s", domain)
            return False
            
        # Chuẩn hóa tên miền
        domain = domain.strip().lower()
        
        # Sử dụng khóa để đảm bảo an toàn khi cập nhật
        with self.update_lock:
            # Kiểm tra xem tên miền đã có trong whitelist chưa
            if domain in self.domains:
                logger.debug("Domain already in whitelist: %s", domain)
                return False
                
            # Thêm tên miền vào tập hợp
            self.domains.add(domain)
            # Cập nhật thời gian cập nhật cuối cùng
            self.last_updated = datetime.now()
            
            # Lưu vào file nếu sử dụng nguồn file hoặc both
            if self.whitelist_source in ["file", "both"]:
                self._save_to_file()
                
            # Ghi log thông tin
            logger.info("Added domain to whitelist: %s", domain)
            return True
    
    def remove_domain(self, domain: str) -> bool:
        """
        Remove a domain from the whitelist.
        
        Args:
            domain: The domain to remove
            
        Returns:
            bool: True if domain was removed, False if not in whitelist
        """
        # Kiểm tra đầu vào hợp lệ
        if not domain:
            return False
            
        # Chuẩn hóa tên miền
        domain = domain.strip().lower()
        
        # Sử dụng khóa để đảm bảo an toàn khi cập nhật
        with self.update_lock:
            # Kiểm tra xem tên miền có trong whitelist không
            if domain not in self.domains:
                logger.debug("Domain not in whitelist: %s", domain)
                return False
                
            # Xóa tên miền khỏi tập hợp
            self.domains.remove(domain)
            # Cập nhật thời gian cập nhật cuối cùng
            self.last_updated = datetime.now()
            
            # Lưu vào file nếu sử dụng nguồn file hoặc both
            if self.whitelist_source in ["file", "both"]:
                self._save_to_file()
                
            # Ghi log thông tin
            logger.info("Removed domain from whitelist: %s", domain)
            return True
    
    def _is_valid_domain(self, domain: str) -> bool:
        """
        Check if a string is a valid domain name.
        
        Args:
            domain: Domain to validate
            
        Returns:
            bool: True if domain format is valid
        """
        # Kiểm tra độ dài tên miền
        # Tên miền không được trống và không được dài quá 253 ký tự (theo chuẩn DNS)
        if not domain or len(domain) > 253:
            return False
            
        # Cho phép tên miền wildcards (e.g., *.example.com)
        # Nếu tên miền bắt đầu bằng "*.", loại bỏ phần này và kiểm tra phần còn lại
        if domain.startswith("*."):
            domain = domain[2:]
            
        # Sử dụng biểu thức chính quy để kiểm tra tính hợp lệ của tên miền
        # - Mỗi phần tên miền phải bắt đầu và kết thúc bằng chữ cái hoặc số
        # - Các phần có thể chứa dấu gạch ngang (-) ở giữa
        # - Tên miền phải có ít nhất một dấu chấm (.)
        # - Phần mở rộng (TLD) phải chỉ chứa chữ cái và dài ít nhất 2 ký tự
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))


# Phần mã kiểm thử - chạy khi file được chạy trực tiếp
if __name__ == "__main__":
    # Cấu hình logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Cấu hình cho việc kiểm thử
    test_config = {
        "whitelist_source": "file",  # Sử dụng nguồn file cho kiểm thử
        "whitelist_file": "test_whitelist.json",  # File whitelist riêng cho kiểm thử
        "server_url": "http://localhost:5000",  # Server local để kiểm thử
        "api_key": "test_key",  # Khóa API giả cho kiểm thử
        "update_interval": 60  # Thời gian cập nhật ngắn cho kiểm thử
    }
    
    # Tạo đối tượng whitelist manager
    whitelist = WhitelistManager(test_config)
    
    # Kiểm tra một số tên miền
    test_domains = [
        "google.com",  # Mặc định nên được cho phép
        "malware.bad-domain.com",  # Tên miền giả mạo, nên bị chặn
        "www.github.com",  # Mặc định nên được cho phép
        "subdomain.wikipedia.org"  # Subdomain của wikipedia.org
    ]
    
    # In kết quả kiểm tra ban đầu
    print("\nTesting domain checks:")
    for domain in test_domains:
        allowed = whitelist.is_allowed(domain)
        print(f"Domain {domain}: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Thêm một tên miền và kiểm tra lại
    print("\nAdding malware.bad-domain.com to whitelist...")
    whitelist.add_domain("malware.bad-domain.com")
    
    # In kết quả kiểm tra sau khi thêm tên miền
    print("\nTesting again after adding domain:")
    for domain in test_domains:
        allowed = whitelist.is_allowed(domain)
        print(f"Domain {domain}: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Bắt đầu cập nhật định kỳ (để minh họa)
    print("\nStarting periodic updates...")
    whitelist.start_periodic_updates()
    
    try:
        # Chạy trong vài giây, sau đó dừng
        time.sleep(5)
    except KeyboardInterrupt:
        # Bắt sự kiện người dùng nhấn Ctrl+C
        pass
    finally:
        # Đảm bảo dừng whitelist manager
        whitelist.stop_periodic_updates()
        print("\nWhitelist manager stopped.")