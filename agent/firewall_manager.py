# Import các thư viện cần thiết
import logging  # Thư viện ghi log hệ thống
import subprocess  # Thư viện thực thi lệnh hệ điều hành (để chạy lệnh netsh)
import re  # Thư viện xử lý biểu thức chính quy (để kiểm tra định dạng IP)
import time  # Thư viện xử lý thời gian (dùng để tạo timestamp)
from typing import Dict, List, Optional, Set  # Thư viện kiểu dữ liệu tĩnh

# Cấu hình logger cho module này
# Sử dụng một logger riêng để dễ dàng lọc log từ module này
logger = logging.getLogger("firewall_manager")

class FirewallManager:
    """
    Manages Windows Firewall rules to block unauthorized connections.
    Uses netsh advfirewall commands through subprocess to interact with Windows Firewall.
    """
    
    def __init__(self, rule_prefix: str = "FirewallController"):
        """
        Initialize the firewall manager.
        
        Args:
            rule_prefix: Prefix to use for all firewall rules created by this instance
        """
        # Lưu tiền tố cho tên các quy tắc tường lửa
        # Tiền tố này giúp nhận dạng các quy tắc do agent tạo ra,
        # phục vụ cho việc quản lý và xóa quy tắc sau này
        self.rule_prefix = rule_prefix
        
        # Tập hợp lưu trữ các địa chỉ IP đã bị chặn
        # Sử dụng kiểu dữ liệu Set để tránh trùng lặp và tìm kiếm nhanh O(1)
        self.blocked_ips: Set[str] = set()
        
        # Tập hợp lưu trữ các địa chỉ IP được phép
        # Theo dõi các IP được phép để có thể xóa quy tắc nếu cần
        self.allowed_ips = set()  # Track allowed IPs
        
        # Kiểm tra quyền admin - cần thiết để thao tác với tường lửa Windows
        if not self._has_admin_privileges():
            # Cảnh báo nếu không có quyền admin
            logger.warning("Firewall operations require administrator privileges")
        
        # Tải các quy tắc tường lửa hiện có để đồng bộ trạng thái
        # Đảm bảo agent biết được những IP nào đã bị chặn trước đó
        self._load_existing_rules()
    
    def block_ip(self, ip: str, domain: Optional[str] = None) -> bool:
        """
        Block an IP address by creating a firewall rule.
        
        Args:
            ip: The IP address to block
            domain: Associated domain name (used in rule description)
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Kiểm tra tính hợp lệ của địa chỉ IP
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        # Nếu IP đã bị chặn, coi như thành công và trả về ngay
        # Tránh tạo nhiều quy tắc trùng lặp cho cùng một IP
        if ip in self.blocked_ips:
            logger.debug(f"IP {ip} is already blocked")
            return True
            
        # Tạo tên quy tắc với timestamp để đảm bảo duy nhất
        # Sử dụng timestamp tránh trùng lặp tên quy tắc
        # Thay thế dấu chấm trong IP bằng dấu gạch dưới để tạo tên hợp lệ
        timestamp = int(time.time())
        rule_name = f"{self.rule_prefix}{ip.replace('.', '_')}_{timestamp}"
        
        # Xây dựng mô tả cho quy tắc
        # Nếu có tên miền, thêm thông tin tên miền vào mô tả
        if domain:
            description = f"Blocked connection to {domain} ({ip})"
        else:
            description = f"Blocked connection to {ip}"
            
        try:
            # Tạo quy tắc tường lửa sử dụng lệnh netsh
            # Sử dụng mảng để tránh vấn đề về khoảng trắng và ký tự đặc biệt
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",  # Tên quy tắc
                "dir=out",  # Hướng: chặn lưu lượng đi ra (outbound)
                "action=block",  # Hành động: chặn kết nối
                f"remoteip={ip}",  # Địa chỉ IP đích cần chặn
                "enable=yes",  # Bật quy tắc ngay lập tức
                f"description={description}"  # Mô tả để dễ nhận biết
            ]
            
            # Thực thi lệnh netsh
            result = subprocess.run(
                command,
                capture_output=True,  # Bắt đầu ra để phân tích
                text=True,  # Chuyển đầu ra thành chuỗi thay vì byte
                creationflags=subprocess.CREATE_NO_WINDOW  # Không hiển thị cửa sổ CMD
            )
            
            # Kiểm tra kết quả lệnh
            if result.returncode == 0:
                # Thành công: thêm IP vào danh sách đã chặn
                self.blocked_ips.add(ip)
                logger.info(f"Successfully blocked IP: {ip} with rule: {rule_name}")
                return True
            else:
                # Thất bại: ghi log lỗi từ netsh
                logger.error(f"Failed to block IP {ip}. Error: {result.stderr.strip()}")
                return False
                
        except Exception as e:
            # Bắt các ngoại lệ có thể xảy ra (quyền truy cập, lỗi hệ thống, v.v.)
            logger.error(f"Error blocking IP {ip}: {str(e)}")
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address by removing associated firewall rules.
        
        Args:
            ip: The IP address to unblock
            
        Returns:
            bool: True if at least one rule was removed, False otherwise
        """
        # Kiểm tra tính hợp lệ của địa chỉ IP
        if not self._is_valid_ip(ip):
            logger.warning(f"Invalid IP address format: {ip}")
            return False
            
        # Nếu IP không nằm trong danh sách đã chặn, không cần làm gì
        if ip not in self.blocked_ips:
            logger.debug(f"IP {ip} is not in our blocked list")
            return False
            
        try:
            # Tìm tất cả quy tắc liên quan đến IP này
            rules = self._find_rules_for_ip(ip)
            
            # Kiểm tra nếu không tìm thấy quy tắc nào
            if not rules:
                logger.warning(f"No firewall rules found for IP {ip}")
                return False
                
            success = False
            
            # Xóa từng quy tắc đã tìm thấy
            for rule_name in rules:
                # Tạo lệnh xóa quy tắc
                command = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"  # Xóa quy tắc theo tên
                ]
                
                # Thực thi lệnh
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Kiểm tra kết quả
                if result.returncode == 0:
                    logger.info(f"Successfully removed rule: {rule_name}")
                    success = True
                else:
                    logger.error(f"Failed to remove rule {rule_name}. Error: {result.stderr.strip()}")
            
            # Nếu ít nhất một quy tắc đã được xóa thành công
            if success:
                # Xóa IP khỏi danh sách đã chặn
                self.blocked_ips.remove(ip)
                return True
            else:
                return False
                
        except Exception as e:
            # Bắt các ngoại lệ có thể xảy ra
            logger.error(f"Error unblocking IP {ip}: {str(e)}")
            return False
    
    def is_blocked(self, ip: str) -> bool:
        """
        Check if an IP address is blocked.
        
        Args:
            ip: The IP address to check
            
        Returns:
            bool: True if the IP is blocked, False otherwise
        """
        # Kiểm tra xem IP có trong tập hợp các IP đã chặn không
        # Phép kiểm tra này có độ phức tạp O(1) do dùng set
        return ip in self.blocked_ips
    
    def get_blocked_ips(self) -> List[str]:
        """
        Get a list of all IPs blocked by this firewall manager.
        
        Returns:
            List[str]: List of blocked IP addresses
        """
        # Chuyển đổi tập hợp thành danh sách để trả về
        return list(self.blocked_ips)
    
    def clear_all_rules(self) -> bool:
        """
        Remove all firewall rules created by this firewall manager.
        Useful for cleanup on application exit.
        
        Returns:
            bool: True if successful, False if errors occurred
        """
        try:
            # Get all firewall rules
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return False
                
            rule_names = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                if line.strip().startswith("Rule Name:"):
                    rule_name = line.strip()[10:].strip()
                    if rule_name.startswith(self.rule_prefix):
                        rule_names.append(rule_name)
            
            if not rule_names:
                logger.info("No rules to clear")
                return True
                
            success = True
            for rule_name in rule_names:
                command = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={rule_name}"
                ]
                
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # Kiểm tra kết quả của từng lệnh xóa
                if result.returncode == 0:
                    logger.info(f"Successfully removed rule: {rule_name}")
                else:
                    logger.error(f"Failed to remove rule {rule_name}. Error: {result.stderr.strip()}")
                    success = False
            
            # Xóa tập hợp các IP đã chặn nếu tất cả quy tắc đã được xóa thành công
            if success:
                self.blocked_ips.clear()
                
            return success
                
        except Exception as e:
            # Bắt các ngoại lệ có thể xảy ra
            logger.error(f"Error clearing firewall rules: {str(e)}")
            return False
    
    def _load_existing_rules(self):
        """
        Load existing firewall rules that match our prefix.
        Used during initialization to sync our state with the firewall.
        """
        try:
            # Get all firewall rules instead of using wildcard
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            # Execute command
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,  # ← Thêm timeout 30 giây
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Check for errors
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return
                
            # Parse output to extract IPs
            current_rule = None
            current_ip = None
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Start of a new rule
                if line.startswith("Rule Name:"):
                    current_rule = line[10:].strip()
                    # Only process rules with our prefix
                    if not current_rule.startswith(self.rule_prefix):
                        current_rule = None
                    current_ip = None
                    
                # Only process lines if we're in a rule with our prefix
                elif current_rule and line.startswith("RemoteIP:"):
                    ip_part = line[9:].strip()
                    
                    if ip_part and ip_part != "Any":
                        ip_parts = ip_part.split(',')
                        for part in ip_parts:
                            part = part.strip()
                            if self._is_valid_ip(part):
                                current_ip = part
                                self.blocked_ips.add(part)
                                logger.debug(f"Found existing block for IP: {part} in rule: {current_rule}")
            
            logger.info(f"Loaded {len(self.blocked_ips)} blocked IPs from existing firewall rules")
            
        except subprocess.TimeoutExpired:
            logger.error("Timeout while loading existing firewall rules")
        except Exception as e:
            logger.error(f"Error loading existing firewall rules: {str(e)}")
    
    def _find_rules_for_ip(self, ip: str) -> List[str]:
        """
        Find all firewall rules that block the given IP.
        
        Args:
            ip: The IP address to find rules for
            
        Returns:
            List[str]: List of rule names
        """
        rule_names = []
        
        try:
            # Get all firewall rules
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                "name=all", "verbose"
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            if result.returncode != 0:
                logger.error(f"Failed to list rules: {result.stderr.strip()}")
                return rule_names
                
            # Alternative method: search by our rule naming pattern directly
            ip_pattern = ip.replace('.', '_')
            lines = result.stdout.split('\n')
            
            for line in lines:
                line = line.strip()
                
                if line.startswith("Rule Name:"):
                    rule_name = line[10:].strip()
                    # Look for rules with our prefix AND the IP in the name
                    if rule_name.startswith(self.rule_prefix) and ip_pattern in rule_name:
                        rule_names.append(rule_name)
                        logger.debug(f"Found rule for IP {ip}: {rule_name}")
            
            if not rule_names:
                # Use full output for debugging
                logger.debug(f"No rules found with pattern {self.rule_prefix}{ip_pattern}")
            
            return rule_names
            
        except Exception as e:
            logger.error(f"Error finding rules for IP {ip}: {str(e)}")
            return rule_names
    
    def _has_admin_privileges(self) -> bool:
        """
        Check if the application is running with administrator privileges.
        
        Returns:
            bool: True if running as admin, False otherwise
        """
        try:
            # Thử chạy một lệnh tường lửa đơn giản đòi hỏi quyền admin
            # Lệnh này chỉ hiển thị thông tin về profile hiện tại, không thay đổi cấu hình
            command = ["netsh", "advfirewall", "show", "currentprofile"]
            
            # Thực thi lệnh
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Nếu lệnh thành công, chúng ta có quyền admin
            return result.returncode == 0
            
        except Exception as e:
            # Bắt các ngoại lệ có thể xảy ra
            logger.error(f"Error checking admin privileges: {str(e)}")
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate if a string is a valid IPv4 address.
        
        Args:
            ip: The string to check
            
        Returns:
            bool: True if the string is a valid IPv4 address
        """
        # Mẫu (pattern) để kiểm tra địa chỉ IPv4
        # Cấu trúc: 4 nhóm số từ 0-255 phân cách bởi dấu chấm
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, ip)
        
        # Nếu không khớp mẫu cơ bản
        if not match:
            return False
            
        # Xác thực từng octet (phải từ 0-255)
        for i in range(1, 5):
            octet = int(match.group(i))
            if octet < 0 or octet > 255:
                return False
                
        return True

    def allow_ip(self, ip_address: str, reason: str = None):
        """Create allow rule for IP address."""
        try:
            if ip_address in self.allowed_ips:
                logger.debug(f"IP {ip_address} already has allow rule")
                return True
            
            rule_name = f"{self.rule_prefix}_Allow_{ip_address.replace('.', '_').replace(':', '_')}"
            
            # Create allow rule (higher priority than block rules)
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=allow",
                f"remoteip={ip_address}",
                "protocol=any"
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            
            if result.returncode == 0:
                self.allowed_ips.add(ip_address)
                logger.info(f"✅ Allow rule created for {ip_address}" + (f" ({reason})" if reason else ""))
                return True
            else:
                logger.error(f"❌ Failed to create allow rule for {ip_address}: {result.stderr}")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed for allow rule {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error creating allow rule for {ip_address}: {str(e)}")
            return False
    
    def unallow_ip(self, ip_address: str, reason: str = None):
        """Remove allow rule for IP address."""
        try:
            if ip_address not in self.allowed_ips:
                logger.debug(f"No allow rule exists for {ip_address}")
                return True
            
            rule_name = f"{self.rule_prefix}_Allow_{ip_address.replace('.', '_').replace(':', '_')}"
            
            command = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ]
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            
            if result.returncode == 0:
                self.allowed_ips.discard(ip_address)
                logger.info(f"🗑️ Allow rule removed for {ip_address}" + (f" ({reason})" if reason else ""))
                return True
            else:
                logger.warning(f"Failed to remove allow rule for {ip_address}: {result.stderr}")
                return False
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed for removing allow rule {ip_address}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Error removing allow rule for {ip_address}: {str(e)}")
            return False


# Example usage (for testing)
if __name__ == "__main__":
    # Phần mã này chỉ chạy khi file được thực thi trực tiếp (không phải import)
    
    # Cấu hình logging cho mục đích kiểm thử
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Tạo đối tượng firewall manager
    firewall = FirewallManager()
    
    # Kiểm thử chặn và bỏ chặn
    test_ip = "93.184.216.34"  # Địa chỉ IP của example.com
    test_domain = "example.com"
    
    print(f"\nBlocking IP {test_ip} ({test_domain})...")
    if firewall.block_ip(test_ip, test_domain):
        print(f"Successfully blocked {test_ip}")
    else:
        print(f"Failed to block {test_ip}")
    
    # Kiểm tra xem IP đã bị chặn chưa
    print(f"\nChecking if {test_ip} is blocked...")
    if firewall.is_blocked(test_ip):
        print(f"{test_ip} is blocked")
    else:
        print(f"{test_ip} is not blocked")
    
    # Liệt kê tất cả các IP đã bị chặn
    print("\nAll blocked IPs:")
    for ip in firewall.get_blocked_ips():
        print(f"- {ip}")
    
    # Bỏ chặn IP
    print(f"\nUnblocking IP {test_ip}...")
    if firewall.unblock_ip(test_ip):
        print(f"Successfully unblocked {test_ip}")
    else:
        print(f"Failed to unblock {test_ip}")
    
    # Xóa tất cả các quy tắc
    print("\nClearing all firewall rules...")
    if firewall.clear_all_rules():
        print("Successfully cleared all rules")
    else:
        print("Failed to clear all rules")