import json
import logging
import queue
import threading
from typing import Dict, List

import requests

# Import time utilities - UTC ONLY
from time_utils import now, now_iso, sleep

# Cấu hình logger
logger = logging.getLogger("log_sender")

class LogSender:
    """Gửi log từ agent lên server trung tâm - UTC ONLY"""
    
    def __init__(self, config: Dict):
        """Khởi tạo log sender với cấu hình cơ bản"""
        #  SỬA: Đọc từ config với fallback
        server_config = config.get("server", {})
        
        # Ưu tiên urls array, fallback về single url
        if "urls" in server_config and server_config["urls"]:
            self.server_urls = server_config["urls"]
        else:
            # Fallback: dùng server_url hoặc url từ config
            primary_url = (
                config.get("server_url") or 
                server_config.get("url", "https://firewall-controller.onrender.com")
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
        
        #  Thêm tracking thời gian - using time_utils UTC only
        self.last_send_time = now()  # UTC timestamp
        
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
        """Thêm log vào hàng đợi để gửi - UTC only"""
        try:
            #  FIX: Serialize datetime objects trước khi queue
            serialized_log = self._serialize_log_data(log_data.copy())
            
            # Thêm ID agent và timestamp
            if "agent_id" not in serialized_log:
                serialized_log["agent_id"] = self.agent_id
                
            if "timestamp" not in serialized_log:
                serialized_log["timestamp"] = now_iso()  # UTC ISO timestamp
        
            # Thêm log vào hàng đợi
            self.log_queue.put_nowait(serialized_log)
            return True
        except queue.Full:
            logger.warning("Log queue is full, dropping log")
            return False
        except Exception as e:
            logger.error(f"Error queueing log: {e}")
            return False
    
    def _serialize_log_data(self, log_data: Dict) -> Dict:
        """Serialize datetime objects và ensure all fields có value - UTC only"""
        try:
            serialized = {}
            
            for key, value in log_data.items():
                if hasattr(value, 'isoformat'):  # datetime object
                    #  FIX: Convert datetime to ISO string
                    serialized[key] = value.isoformat()
                elif isinstance(value, dict):
                    # Recursively serialize nested dicts
                    serialized[key] = self._serialize_log_data(value)
                elif isinstance(value, list):
                    # Handle lists that might contain datetime objects
                    serialized[key] = [
                        item.isoformat() if hasattr(item, 'isoformat') 
                        else (self._serialize_log_data(item) if isinstance(item, dict) else item)
                        for item in value
                    ]
                elif value is None:
                    #  FIX: Convert None to "unknown"
                    serialized[key] = "unknown"
                else:
                    serialized[key] = value
            
            #  FIX: Ensure essential fields exist - UTC only
            essential_fields = {
                "timestamp": now_iso(),  # UTC ISO timestamp
                "agent_id": self.agent_id,
                "level": "INFO",
                "action": "UNKNOWN",
                "domain": "unknown",
                "destination": "unknown", 
                "source_ip": "unknown",
                "dest_ip": "unknown",
                "protocol": "unknown",
                "port": "unknown",
                "message": "Log entry"
            }
            
            for field, default_value in essential_fields.items():
                if field not in serialized or not serialized[field]:
                    serialized[field] = default_value
            
            return serialized
            
        except Exception as e:
            logger.error(f"Error serializing log data: {e}")
            #  Fallback: return complete basic log data - UTC only
            return {
                "timestamp": now_iso(),  # UTC ISO timestamp
                "agent_id": self.agent_id,
                "level": "ERROR",
                "action": "ERROR",
                "domain": "serialization_error",
                "destination": "serialization_error",
                "source_ip": "unknown",
                "dest_ip": "unknown",
                "protocol": "unknown", 
                "port": "unknown",
                "message": f"Log serialization failed: {str(e)}",
                "source": "log_sender_error",
                "original_data": str(log_data)[:200] + "..." if len(str(log_data)) > 200 else str(log_data),
                "serialization_error": str(e)
            }
    
    def _sender_loop(self):
        """Vòng lặp gửi log theo định kỳ với tối ưu hóa - UTC only"""
        while self.running:
            try:
                #  Thêm logic gửi định kỳ - using time_utils UTC only
                current_time = now()  # UTC timestamp
                queue_size = self.log_queue.qsize()
                
                # Gửi nếu đủ batch_size HOẶC đã qua send_interval
                should_send = (
                    queue_size >= self.batch_size or 
                    (queue_size > 0 and (current_time - self.last_send_time) >= self.send_interval)
                )
                
                if should_send:
                    self._send_logs()
                    self.last_send_time = current_time
                    
                # Ngủ ngắn để không tốn CPU - using time_utils
                sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in sender loop: {str(e)}")
                sleep(5)
    
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
        """Gửi một batch log lên server - UTC only"""
        if not self.server_urls:
            logger.error("Server URL not configured")
            return False
        
        #  FIX: Additional serialization check before sending
        try:
            #  Test JSON serialization trước khi gửi
            serialized_logs = []
            for log in logs:
                try:
                    #  Ensure all datetime objects are converted
                    clean_log = self._ensure_json_serializable(log)
                    serialized_logs.append(clean_log)
                except Exception as e:
                    logger.error(f"Failed to serialize log: {e}")
                    #  Create fallback log entry - UTC only
                    fallback_log = {
                        "message": f"Log serialization failed: {str(e)}",
                        "level": "error",
                        "timestamp": now_iso(),  # UTC ISO timestamp
                        "agent_id": self.agent_id,
                        "original_log_preview": str(log)[:200] + "..." if len(str(log)) > 200 else str(log)
                    }
                    serialized_logs.append(fallback_log)
            
            #  Test JSON serialization
            test_json = json.dumps({"logs": serialized_logs})
            
        except Exception as e:
            logger.error(f"JSON serialization test failed: {e}")
            return False
            
        try:
            # Gửi request đơn giản không cần xác thực
            url = f"{self.server_urls[0].rstrip('/')}/api/logs"
            
            #  FIX: Use serialized logs
            payload = {"logs": serialized_logs}
            
            response = requests.post(
                url=url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=15  #  Increase timeout for Render
            )
            
            # Kiểm tra kết quả
            if response.status_code in (200, 201, 202):
                logger.info(f"Successfully sent {len(serialized_logs)} logs to server")
                return True
            else:
                logger.error(f"Failed to send logs: HTTP {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error("Timeout sending logs to server")
            return False
        except requests.exceptions.ConnectionError:
            logger.error("Connection error sending logs to server")
            return False
        except Exception as e:
            logger.error(f"Error sending logs: {str(e)}")
            return False
    
    def _ensure_json_serializable(self, obj):
        """Ensure object is JSON serializable"""
        if hasattr(obj, 'isoformat'):  # datetime object
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._ensure_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._ensure_json_serializable(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        else:
            #  Convert unknown types to string
            return str(obj)
    
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

    def get_status(self) -> Dict:
        """Get log sender status - UTC only"""
        return {
            "running": self.running,
            "agent_id": self.agent_id,
            "queue_size": self.log_queue.qsize(),
            "max_queue_size": self.max_queue_size,
            "batch_size": self.batch_size,
            "send_interval": self.send_interval,
            "last_send_time": self.last_send_time,  # UTC Unix timestamp
            "server_urls": self.server_urls,
            "status_timestamp": now_iso()  # UTC ISO timestamp
        }
