import json  # Thư viện để xử lý dữ liệu định dạng JSON
import logging  # Thư viện để ghi log
import queue  # Thư viện cung cấp cấu trúc hàng đợi thread-safe
import threading  # Thư viện hỗ trợ đa luồng
import time  # Thư viện xử lý thời gian
from datetime import datetime  # Thư viện xử lý ngày tháng
from typing import Dict, List, Optional  # Thư viện hỗ trợ kiểu dữ liệu tĩnh

import requests  # Thư viện HTTP để gửi dữ liệu đến server

# Cấu hình logger cho module này
# Tạo logger riêng để dễ dàng phân biệt với log từ các module khác
logger = logging.getLogger("log_sender")

class LogSender:
    """
    Queues and sends log events to the central server.
    Handles connection issues, retries, and authentication.
    """
    
    def __init__(self, config: Dict):
        """
        Initialize the log sender.
        
        Args:
            config: Configuration dictionary with keys:
                - server_url: URL of the server API
                - api_key: API key for authentication
                - max_queue_size: Maximum number of logs to queue (default: 1000)
                - batch_size: Number of logs to send in one request (default: 100)
                - retry_interval: Seconds to wait between retry attempts (default: 30)
                - max_retries: Maximum number of retry attempts (default: 5)
        """
        # Lưu cấu hình gốc để tham chiếu nếu cần
        self.config = config
        
        # Trích xuất các giá trị cấu hình với giá trị mặc định
        # - server_url: URL của API server để gửi log đến
        # - api_key: Khóa API để xác thực với server
        # - max_queue_size: Số lượng log tối đa có thể lưu trong hàng đợi trước khi bị loại bỏ
        # - batch_size: Số lượng log gửi trong một lần (tối ưu hóa số lượng request)
        # - retry_interval: Thời gian chờ giữa các lần thử lại khi gửi thất bại (giây)
        # - max_retries: Số lần thử lại tối đa trước khi bỏ các log thất bại
        self.server_url = config.get("server_url", "")
        self.api_key = config.get("api_key", "")
        self.max_queue_size = config.get("max_queue_size", 1000)
        self.batch_size = config.get("batch_size", 100)
        self.retry_interval = config.get("retry_interval", 30)
        self.max_retries = config.get("max_retries", 5)
        
        # Khởi tạo hàng đợi và cơ chế đồng bộ hóa
        # - log_queue: Hàng đợi thread-safe để lưu trữ các log chờ gửi
        # - sender_thread: Luồng xử lý gửi log chạy ngầm
        # - running: Cờ điều khiển trạng thái của luồng gửi log
        # - send_lock: Khóa để đảm bảo chỉ một luồng gửi log tại một thời điểm
        self.log_queue = queue.Queue(maxsize=self.max_queue_size)
        self.sender_thread = None
        self.running = False
        self.send_lock = threading.Lock()
        
        # Định danh agent
        # Mỗi agent cần một ID duy nhất để server phân biệt nguồn gửi log
        self.agent_id = config.get("agent_id", self._generate_agent_id())
        
        # Theo dõi việc thử lại
        # - retry_count: Số lần đã thử lại hiện tại
        # - failed_logs: Danh sách lưu các log gửi thất bại để thử lại sau
        self.retry_count = 0
        self.failed_logs = []
        
    def start(self):
        """Start the log sender thread."""
        # Kiểm tra nếu đã đang chạy thì không khởi động lại
        if self.running:
            logger.warning("Log sender is already running")
            return
        
        # Đánh dấu trạng thái đang chạy    
        self.running = True
        
        # Tạo và khởi động luồng gửi log
        # - target=self._sender_loop: Hàm sẽ được thực thi trong luồng
        # - daemon=True: Khi chương trình chính kết thúc, luồng này sẽ tự động kết thúc
        self.sender_thread = threading.Thread(target=self._sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        
        logger.info("Log sender started")
    
    def stop(self):
        """Stop the log sender thread and flush remaining logs."""
        # Kiểm tra nếu không đang chạy thì không cần dừng
        if not self.running:
            logger.warning("Log sender is not running")
            return
        
        # Đánh dấu yêu cầu dừng luồng    
        logger.info("Stopping log sender and flushing queue...")
        self.running = False
        
        if self.sender_thread:
            # Cố gắng đẩy tất cả log còn lại trong hàng đợi đến server
            try:
                self._flush_queue()
            except Exception as e:
                logger.error(f"Error flushing log queue on shutdown: {str(e)}")
                
            # Chờ luồng kết thúc với timeout để tránh treo chương trình
            self.sender_thread.join(timeout=10)
            if self.sender_thread.is_alive():
                logger.warning("Log sender thread did not terminate gracefully")
        
        logger.info("Log sender stopped")
    
    def queue_log(self, log_data: Dict) -> bool:
        """
        Add a log event to the queue for sending to the server.
        
        Args:
            log_data: Dictionary with log event details
            
        Returns:
            bool: True if log was queued, False if queue is full
        """
        try:
            # Thêm ID của agent vào log nếu chưa có
            # Giúp server xác định log đến từ agent nào
            if "agent_id" not in log_data:
                log_data["agent_id"] = self.agent_id
                
            # Thêm timestamp nếu chưa có để ghi nhận thời điểm tạo log
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.now().isoformat()
                
            # Thêm log vào hàng đợi không chờ (non-blocking)
            # Nếu hàng đợi đầy, sẽ ném ngoại lệ queue.Full
            self.log_queue.put_nowait(log_data)
            return True
            
        except queue.Full:
            # Nếu hàng đợi đầy, ghi log cảnh báo và báo thất bại
            logger.warning("Log queue is full, log event dropped")
            return False
    
    def _sender_loop(self):
        """Background thread for sending logs to the server."""
        # Vòng lặp chạy liên tục khi sender đang hoạt động
        while self.running:
            try:
                # Kiểm tra điều kiện để gửi log:
                # 1. Đã đạt đủ số lượng log trong batch, hoặc
                # 2. Có log và không đang trong trạng thái thử lại
                if self.log_queue.qsize() >= self.batch_size or (self.log_queue.qsize() > 0 and self.retry_count == 0):
                    self._send_logs()
                
                # Xử lý các log đã thất bại trước đó theo chu kỳ retry_interval
                # time.time() % self.retry_interval < 1 đảm bảo chỉ thực hiện một lần mỗi retry_interval giây
                if self.failed_logs and time.time() % self.retry_interval < 1:
                    self._retry_failed_logs()
                    
                # Ngủ một chút để tránh tiêu tốn CPU
                time.sleep(1)
                    
            except Exception as e:
                # Bắt các lỗi không lường trước để luồng không bị dừng đột ngột
                logger.error(f"Error in log sender loop: {str(e)}")
                time.sleep(5)  # Ngủ lâu hơn để tránh lỗi liên tục
    
    def _flush_queue(self):
        """Flush all logs in the queue to the server."""
        # Lấy tất cả log từ hàng đợi
        logs = []
        try:
            # Lấy từng log cho đến khi hàng đợi rỗng
            while not self.log_queue.empty():
                logs.append(self.log_queue.get_nowait())
                self.log_queue.task_done()  # Đánh dấu công việc đã hoàn thành
        except queue.Empty:
            # Hàng đợi có thể đã rỗng do một luồng khác đã lấy các log
            pass
            
        # Thêm các log đã thất bại trước đó vào batch để gửi lại
        if self.failed_logs:
            logs.extend(self.failed_logs)
            self.failed_logs = []  # Xóa danh sách thất bại vì sẽ thử lại
            
        # Gửi tất cả log nếu có
        if logs:
            logger.info(f"Flushing {len(logs)} logs")
            success = self._send_batch(logs)
            if not success and len(logs) <= self.max_queue_size:
                # Nếu gửi thất bại và số lượng log không quá lớn, lưu lại để thử lại sau
                self.failed_logs = logs
    
    def _send_logs(self):
        """Send a batch of logs to the server."""
        logs = []
        # Xác định số lượng log cần lấy từ hàng đợi (không quá batch_size)
        batch_size = min(self.batch_size, self.log_queue.qsize())
        
        # Lấy log từ hàng đợi theo số lượng đã xác định
        for _ in range(batch_size):
            try:
                log = self.log_queue.get_nowait()
                logs.append(log)
                self.log_queue.task_done()  # Đánh dấu đã xử lý xong item này
            except queue.Empty:
                # Hàng đợi đã rỗng, thoát vòng lặp
                break
                
        if logs:
            # Gửi batch log đến server
            success = self._send_batch(logs)
            
            if not success:
                # Nếu gửi thất bại, thêm vào danh sách thử lại sau
                self.failed_logs.extend(logs)
                logger.warning(f"Failed to send logs, queued {len(logs)} for retry")
    
    def _retry_failed_logs(self):
        """Retry sending previously failed logs."""
        # Nếu không có log thất bại, không cần làm gì
        if not self.failed_logs:
            return
            
        # Kiểm tra nếu đã vượt quá số lần thử lại tối đa
        if self.retry_count >= self.max_retries:
            logger.error(f"Maximum retry attempts reached, dropping {len(self.failed_logs)} logs")
            self.failed_logs = []  # Xóa các log thất bại
            self.retry_count = 0  # Reset số lần thử
            return
            
        logger.info(f"Retrying {len(self.failed_logs)} failed logs (attempt {self.retry_count + 1})")
        
        # Gửi lại các log thất bại
        success = self._send_batch(self.failed_logs)
        
        if success:
            # Nếu thành công, xóa danh sách log thất bại và reset số lần thử
            logger.info("Successfully sent previously failed logs")
            self.failed_logs = []
            self.retry_count = 0
        else:
            # Nếu vẫn thất bại, tăng số lần thử lên và chờ đến lần thử tiếp theo
            self.retry_count += 1
            logger.warning(f"Retry failed, will try again in {self.retry_interval} seconds")
    
    def _send_batch(self, logs: List[Dict]) -> bool:
        """
        Send a batch of logs to the server.
        
        Args:
            logs: List of log dictionaries to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Kiểm tra điều kiện URL server đã được cấu hình
        if not self.server_url:
            logger.error("Server URL not configured, cannot send logs")
            return False
            
        try:
            # Chuẩn bị headers cho request HTTP
            headers = {"Content-Type": "application/json"}  # Định dạng dữ liệu gửi là JSON
            
            # Thêm header xác thực nếu có API key
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
            # Xây dựng URL đích, đảm bảo không có dấu / thừa ở cuối
            url = f"{self.server_url.rstrip('/')}/api/logs"
            
            # Gửi request với khóa để đảm bảo chỉ một request được gửi tại một thời điểm
            with self.send_lock:
                response = requests.post(
                    url=url,
                    headers=headers,
                    json={"logs": logs},  # Đóng gói logs vào trường "logs" của JSON
                    timeout=30  # Thời gian chờ tối đa là 30 giây
                )
                
            # Kiểm tra mã phản hồi HTTP
            # 200, 201, 202 đều là các mã thành công
            if response.status_code in (200, 201, 202):
                logger.info(f"Successfully sent {len(logs)} logs to server")
                return True
            else:
                # Ghi log lỗi nếu server trả về mã lỗi
                logger.error(f"Failed to send logs: HTTP {response.status_code} - {response.text}")
                return False
                
        except requests.RequestException as e:
            # Bắt lỗi mạng khi gửi request
            logger.error(f"Network error sending logs: {str(e)}")
            return False
        except Exception as e:
            # Bắt các lỗi khác không xác định trước
            logger.error(f"Error sending logs: {str(e)}")
            return False
    
    def _generate_agent_id(self) -> str:
        """
        Generate a unique agent ID based on hostname and other system identifiers.
        
        Returns:
            str: A unique identifier for this agent
        """
        # Import các module cần thiết để lấy thông tin hệ thống
        import socket  # Để lấy hostname
        import uuid  # Để lấy MAC address dưới dạng số
        import platform  # Để lấy thông tin hệ điều hành
        
        # Lấy tên máy chủ
        hostname = socket.gethostname()
        
        # Lấy thông tin hệ điều hành (tên + phiên bản)
        system_info = platform.system() + platform.release()
        
        # Lấy địa chỉ MAC và định dạng thành chuỗi
        # uuid.getnode() trả về số biểu diễn địa chỉ MAC
        # Chuyển đổi số này thành định dạng XX:XX:XX:XX:XX:XX
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                              for elements in range(0, 2*6, 2)][::-1])
        
        # Tạo ID duy nhất bằng cách kết hợp:
        # 1. Tên máy chủ
        # 2. Địa chỉ MAC
        # 3. Hash từ thông tin hệ thống (lấy 4 chữ số cuối)
        agent_id = f"{hostname}-{mac_address}-{hash(system_info) % 10000:04d}"
        return agent_id


# Phần mã kiểm thử - chạy khi file được chạy trực tiếp
if __name__ == "__main__":
    # Cấu hình logging cho việc kiểm thử
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Cấu hình mẫu cho việc kiểm thử
    test_config = {
        "server_url": "http://localhost:5000",  # URL server local để kiểm thử
        "api_key": "test_key",  # Khóa API giả cho kiểm thử
        "batch_size": 10,  # Kích thước batch nhỏ để dễ theo dõi
        "retry_interval": 10  # Thời gian thử lại ngắn để kiểm thử nhanh
    }
    
    # Tạo đối tượng LogSender
    log_sender = LogSender(test_config)
    
    # Bắt đầu luồng gửi log
    log_sender.start()
    
    # Tạo một số log kiểm thử
    for i in range(25):
        # Tạo dữ liệu log mẫu với các giá trị khác nhau
        log_data = {
            "domain": f"test-domain-{i}.com",  # Tên miền mẫu
            "dest_ip": f"192.168.1.{i % 255}",  # Địa chỉ IP đích mẫu
            "action": "block" if i % 3 == 0 else "allow",  # Luân phiên các hành động
            "protocol": "HTTP" if i % 2 == 0 else "HTTPS"  # Luân phiên các giao thức
        }
        # Đưa log vào hàng đợi
        log_sender.queue_log(log_data)
        time.sleep(0.1)  # Tạm dừng một chút giữa các log
    
    # Để luồng gửi log hoạt động cho đến khi người dùng nhấn Ctrl+C
    try:
        print("Sending logs. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        # Dừng LogSender (sẽ cố gắng gửi các log còn lại)
        log_sender.stop()
        print("Log sender stopped.")