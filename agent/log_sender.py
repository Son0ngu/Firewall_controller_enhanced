import json
import logging
import queue
import threading
import time
from datetime import datetime
from typing import Dict, List
import pytz  # ✅ ADD TIMEZONE SUPPORT

import requests

# Cấu hình logger
logger = logging.getLogger("log_sender")

# ✅ SET TIMEZONE
LOCAL_TIMEZONE = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone

class LogSender:
    """Gửi log từ agent lên server trung tâm"""
    
    def __init__(self, config: Dict):
        """Khởi tạo log sender với cấu hình cơ bản"""
        # Lưu cấu hình URL server
        self.server_url = config.get("server_url", "https://firewall-controller-vu7f.onrender.com")
        
        # Cấu hình hàng đợi log
        self.max_queue_size = config.get("max_queue_size", 1000)
        self.batch_size = config.get("batch_size", 100)
        self.send_interval = config.get("send_interval", 30)
        
        # Khởi tạo hàng đợi và trạng thái
        self.log_queue = queue.Queue(maxsize=self.max_queue_size)
        self.running = False
        self.sender_thread = None
        
        # Khởi tạo định danh agent
        self.agent_id = config.get("agent_id", self._generate_agent_id())
        
        # ✅ ADD TIMEZONE
        self.timezone = LOCAL_TIMEZONE
        
        # ✅ Thêm tracking thời gian với timezone
        self.last_send_time = time.time()
        
        logger.info(f"LogSender initialized with agent_id: {self.agent_id}")
    
    def start(self):
        """Bắt đầu thread gửi log"""
        if self.running:
            return
            
        self.running = True
        self.sender_thread = threading.Thread(target=self._sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        logger.info("Log sender started")
    
    def stop(self):
        """Dừng thread gửi log và đẩy các log còn lại"""
        if not self.running:
            return
            
        self.running = False
        
        if self.sender_thread:
            try:
                self._flush_queue()  # Gửi tất cả log còn lại
            except Exception as e:
                logger.error(f"Error flushing logs: {str(e)}")
                
            self.sender_thread.join(timeout=5)
            
        logger.info("Log sender stopped")
    
    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)
    
    def queue_log(self, log_data: Dict) -> bool:
        """Thêm log vào hàng đợi để gửi"""
        try:
            # Thêm ID agent và timestamp
            if "agent_id" not in log_data:
                log_data["agent_id"] = self.agent_id
                
            if "timestamp" not in log_data:
                # ✅ USE TIMEZONE-AWARE TIMESTAMP
                log_data["timestamp"] = self._get_current_time().isoformat()
            
            # Thêm log vào hàng đợi
            self.log_queue.put_nowait(log_data)
            return True
        except queue.Full:
            logger.warning("Log queue is full, dropping log")
            return False
    
    def _sender_loop(self):
        """Vòng lặp gửi log theo định kỳ với tối ưu hóa"""
        while self.running:
            try:
                # ✅ Thêm logic gửi định kỳ
                current_time = time.time()
                queue_size = self.log_queue.qsize()
                
                # Gửi nếu đủ batch_size HOẶC đã qua send_interval
                should_send = (
                    queue_size >= self.batch_size or 
                    (queue_size > 0 and (current_time - self.last_send_time) >= self.send_interval)
                )
                
                if should_send:
                    self._send_logs()
                    self.last_send_time = current_time
                    
                # Ngủ ngắn để không tốn CPU
                time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in sender loop: {str(e)}")
                time.sleep(5)
    
    def _flush_queue(self):
        """Gửi tất cả log còn lại trong hàng đợi"""
        logs = []
        try:
            while not self.log_queue.empty():
                logs.append(self.log_queue.get_nowait())
                self.log_queue.task_done()
        except queue.Empty:
            pass
            
        if logs:
            self._send_batch(logs)
    
    def _send_logs(self):
        """Gửi một batch log từ hàng đợi"""
        logs = []
        batch_size = min(self.batch_size, self.log_queue.qsize())
        
        for _ in range(batch_size):
            try:
                log = self.log_queue.get_nowait()
                logs.append(log)
                self.log_queue.task_done()
            except queue.Empty:
                break
                
        if logs:
            self._send_batch(logs)
    
    def _send_batch(self, logs: List[Dict]) -> bool:
        """Gửi một batch log lên server"""
        if not self.server_url:
            logger.error("Server URL not configured")
            return False
            
        try:
            # Gửi request đơn giản không cần xác thực
            url = f"{self.server_url.rstrip('/')}/api/logs"
            response = requests.post(
                url=url,
                json={"logs": logs},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            # Kiểm tra kết quả
            if response.status_code in (200, 201, 202):
                logger.info(f"Successfully sent {len(logs)} logs to server")
                return True
            else:
                logger.error(f"Failed to send logs: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error sending logs: {str(e)}")
            return False
    
    def _generate_agent_id(self) -> str:
        """Tạo ID định danh cho agent"""
        import socket
        import uuid
        import platform
        
        hostname = socket.gethostname()
        system_info = platform.system() + platform.release()
        mac = ':'.join([f'{(uuid.getnode() >> elements) & 0xff:02x}' 
                      for elements in range(0, 12, 2)][::-1])
        
        return f"{hostname}-{mac}"


# Phần mã kiểm thử - chạy khi file được chạy trực tiếp
if __name__ == "__main__":
    # Cấu hình logging cho việc kiểm thử
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Cấu hình mẫu cho việc kiểm thử
    test_config = {
        "server_url": "https://firewall-controller-vu7f.onrender.com",  # URL server local để kiểm thử
        "api_key": "test_key",  # Khóa API giả cho kiểm thử
        "batch_size": 10  # Kích thước batch nhỏ để dễ theo dõi
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