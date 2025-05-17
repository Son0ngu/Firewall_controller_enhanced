import json
import logging
import queue
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional

import requests

# Configure logging
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
        self.config = config
        
        # Default configuration values
        self.server_url = config.get("server_url", "")
        self.api_key = config.get("api_key", "")
        self.max_queue_size = config.get("max_queue_size", 1000)
        self.batch_size = config.get("batch_size", 100)
        self.retry_interval = config.get("retry_interval", 30)
        self.max_retries = config.get("max_retries", 5)
        
        # Log queue and synchronization
        self.log_queue = queue.Queue(maxsize=self.max_queue_size)
        self.sender_thread = None
        self.running = False
        self.send_lock = threading.Lock()
        
        # Agent identification
        self.agent_id = config.get("agent_id", self._generate_agent_id())
        
        # Retry tracking
        self.retry_count = 0
        self.failed_logs = []
        
    def start(self):
        """Start the log sender thread."""
        if self.running:
            logger.warning("Log sender is already running")
            return
            
        self.running = True
        self.sender_thread = threading.Thread(target=self._sender_loop)
        self.sender_thread.daemon = True
        self.sender_thread.start()
        logger.info("Log sender started")
    
    def stop(self):
        """Stop the log sender thread and flush remaining logs."""
        if not self.running:
            logger.warning("Log sender is not running")
            return
            
        logger.info("Stopping log sender and flushing queue...")
        self.running = False
        
        if self.sender_thread:
            # Try to flush the queue
            try:
                self._flush_queue()
            except Exception as e:
                logger.error(f"Error flushing log queue on shutdown: {str(e)}")
                
            # Wait for thread to terminate
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
            # Add agent ID and timestamp if not present
            if "agent_id" not in log_data:
                log_data["agent_id"] = self.agent_id
                
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.now().isoformat()
                
            # Try to add to queue without blocking
            self.log_queue.put_nowait(log_data)
            return True
            
        except queue.Full:
            logger.warning("Log queue is full, log event dropped")
            return False
    
    def _sender_loop(self):
        """Background thread for sending logs to the server."""
        while self.running:
            try:
                # If we have enough logs or the queue has been idle for a while, send them
                if self.log_queue.qsize() >= self.batch_size or (self.log_queue.qsize() > 0 and self.retry_count == 0):
                    self._send_logs()
                
                # Handle previously failed logs
                if self.failed_logs and time.time() % self.retry_interval < 1:
                    self._retry_failed_logs()
                    
                # Sleep to avoid busy-waiting
                time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in log sender loop: {str(e)}")
                time.sleep(5)  # Sleep to avoid rapid error cycles
    
    def _flush_queue(self):
        """Flush all logs in the queue to the server."""
        # Get all logs from the queue
        logs = []
        try:
            while not self.log_queue.empty():
                logs.append(self.log_queue.get_nowait())
                self.log_queue.task_done()
        except queue.Empty:
            pass
            
        # Add any previously failed logs
        if self.failed_logs:
            logs.extend(self.failed_logs)
            self.failed_logs = []
            
        # Send all logs
        if logs:
            logger.info(f"Flushing {len(logs)} logs")
            success = self._send_batch(logs)
            if not success and len(logs) <= self.max_queue_size:
                # If send failed and we still have capacity, store for next run
                self.failed_logs = logs
    
    def _send_logs(self):
        """Send a batch of logs to the server."""
        logs = []
        batch_size = min(self.batch_size, self.log_queue.qsize())
        
        # Collect logs up to batch size
        for _ in range(batch_size):
            try:
                log = self.log_queue.get_nowait()
                logs.append(log)
                self.log_queue.task_done()
            except queue.Empty:
                break
                
        if logs:
            # Send the batch
            success = self._send_batch(logs)
            
            if not success:
                # If send failed, put logs in failed_logs for retry
                self.failed_logs.extend(logs)
                logger.warning(f"Failed to send logs, queued {len(logs)} for retry")
    
    def _retry_failed_logs(self):
        """Retry sending previously failed logs."""
        if not self.failed_logs:
            return
            
        # Check if we've exceeded max retries
        if self.retry_count >= self.max_retries:
            logger.error(f"Maximum retry attempts reached, dropping {len(self.failed_logs)} logs")
            self.failed_logs = []
            self.retry_count = 0
            return
            
        logger.info(f"Retrying {len(self.failed_logs)} failed logs (attempt {self.retry_count + 1})")
        
        # Send the logs
        success = self._send_batch(self.failed_logs)
        
        if success:
            # Clear the failed logs on success
            logger.info("Successfully sent previously failed logs")
            self.failed_logs = []
            self.retry_count = 0
        else:
            # Increment retry count
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
        if not self.server_url:
            logger.error("Server URL not configured, cannot send logs")
            return False
            
        try:
            # Prepare headers
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
                
            # Build the URL
            url = f"{self.server_url.rstrip('/')}/api/logs"
            
            # Send the request
            with self.send_lock:
                response = requests.post(
                    url=url,
                    headers=headers,
                    json={"logs": logs},
                    timeout=30
                )
                
            # Check response
            if response.status_code in (200, 201, 202):
                logger.info(f"Successfully sent {len(logs)} logs to server")
                return True
            else:
                logger.error(f"Failed to send logs: HTTP {response.status_code} - {response.text}")
                return False
                
        except requests.RequestException as e:
            logger.error(f"Network error sending logs: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error sending logs: {str(e)}")
            return False
    
    def _generate_agent_id(self) -> str:
        """
        Generate a unique agent ID based on hostname and other system identifiers.
        
        Returns:
            str: A unique identifier for this agent
        """
        import socket
        import uuid
        import platform
        
        hostname = socket.gethostname()
        system_info = platform.system() + platform.release()
        mac_address = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                              for elements in range(0, 2*6, 2)][::-1])
        
        agent_id = f"{hostname}-{mac_address}-{hash(system_info) % 10000:04d}"
        return agent_id


# Example usage (for testing)
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration for testing
    test_config = {
        "server_url": "http://localhost:5000",
        "api_key": "test_key",
        "batch_size": 10,
        "retry_interval": 10
    }
    
    # Create log sender
    log_sender = LogSender(test_config)
    
    # Start sender
    log_sender.start()
    
    # Send some test logs
    for i in range(25):
        log_data = {
            "domain": f"test-domain-{i}.com",
            "dest_ip": f"192.168.1.{i % 255}",
            "action": "block" if i % 3 == 0 else "allow",
            "protocol": "HTTP" if i % 2 == 0 else "HTTPS"
        }
        log_sender.queue_log(log_data)
        time.sleep(0.1)  # Small delay between logs
    
    # Let the sender process the logs
    try:
        print("Sending logs. Press Ctrl+C to stop...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        # Stop the sender (will try to flush remaining logs)
        log_sender.stop()
        print("Log sender stopped.")