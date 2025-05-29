import json
import logging
import queue
import threading
import time
from datetime import datetime
from typing import Dict, List

import requests

# Cấu hình logger
logger = logging.getLogger("log_sender")

class LogSender:
    """Gửi log từ agent lên server trung tâm"""
    
    def __init__(self, config: Dict):
        """Khởi tạo log sender với cấu hình cơ bản"""
        # ✅ SỬA: Đọc từ config với fallback
        server_config = config.get("server", {})
        
        # Ưu tiên urls array, fallback về single url
        if "urls" in server_config and server_config["urls"]:
            self.server_urls = server_config["urls"]
        else:
            # Fallback: dùng server_url hoặc url từ config
            primary_url = (
                config.get("server_url") or 
                server_config.get("url", "https://project2-bpvw.onrender.com")
            )
            self.server_urls = [
                primary_url,
                "http://localhost:5000"
            ]
        
        # Cấu hình hàng đợi log
        self.max_queue_size = config.get("max_queue_size", 1000)
        self.batch_size = config.get("batch_size", 100)
        self.send_interval = config.get("send_interval", 10)
        
        # Khởi tạo hàng đợi và trạng thái
        self.log_queue = queue.Queue(maxsize=self.max_queue_size)
        self.running = False
        self.sender_thread = None
        
        # Khởi tạo định danh agent
        self.agent_id = config.get("agent_id", self._generate_agent_id())
        
        # ✅ Thêm tracking thời gian
        self.last_send_time = time.time()
        
        logger.info(f"LogSender initialized with agent_id: {self.agent_id}")
        logger.info(f"Will send logs to: {', '.join(self.server_urls)}")
    
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
    
    def queue_log(self, log_data: Dict) -> bool:
        """Thêm log vào hàng đợi để gửi"""
        try:
            # Thêm ID agent và timestamp
            if "agent_id" not in log_data:
                log_data["agent_id"] = self.agent_id
                
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.now().astimezone().isoformat()  # ✅ SỬA: Thêm múi giờ
        
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
        if not self.server_urls:
            logger.error("Server URL not configured")
            return False
            
        try:
            # Gửi request đơn giản không cần xác thực
            url = f"{self.server_urls[0].rstrip('/')}/api/logs"
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
