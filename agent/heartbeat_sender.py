"""
Heartbeat Sender - Gửi tín hiệu sống định kỳ lên server
UTC ONLY - Clean and simple
"""

import json
import logging
import threading
import requests
from typing import Dict, Optional
import psutil  # For system metrics  
import platform

# Import time utilities - UTC ONLY
from time_utils import now, now_iso, sleep

logger = logging.getLogger("heartbeat_sender")

class HeartbeatSender:
    """Gửi heartbeat định kỳ lên server - UTC only"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.heartbeat_config = config.get("heartbeat", {})
        self.server_config = config.get("server", {})
        
        # Heartbeat settings
        self.enabled = self.heartbeat_config.get("enabled", True)
        self.interval = self.heartbeat_config.get("interval", 20)  # 20 seconds
        self.timeout = self.heartbeat_config.get("timeout", 10)
        self.retry_interval = self.heartbeat_config.get("retry_interval", 5)  # 5 seconds
        self.max_failures = self.heartbeat_config.get("max_failures", 3)  # 3 failures
        
        # Retry logic cho failed heartbeats
        self.max_retries = 3
        self.retry_delay = 2  # 2 seconds between retries
        
        # Agent info
        self.agent_id = None
        self.agent_token = None
        self.server_urls = self._get_server_urls()
        
        # State
        self._running = False
        self._thread = None
        self._consecutive_failures = 0
        self._last_successful_heartbeat = None
        
    def _get_server_urls(self) -> list:
        """Get list of server URLs to try"""
        urls = []
        
        # Try multiple URLs from config
        if isinstance(self.server_config.get("urls"), list):
            urls.extend(self.server_config["urls"])
        
        # Add main URL if specified
        if self.server_config.get("url"):
            main_url = self.server_config["url"]
            if main_url not in urls:
                urls.append(main_url)
        
        return urls or ["http://localhost:5000"]
    
    def set_agent_credentials(self, agent_id: str, token: str):
        """Set agent credentials for heartbeat"""
        self.agent_id = agent_id
        self.agent_token = token
    
    def start(self):
        """Start heartbeat sender"""
        if not self.enabled:
            logger.info("Heartbeat sender disabled")
            return
        
        if not self.agent_id or not self.agent_token:
            logger.warning("Cannot start heartbeat - missing agent credentials")
            return
        
        if self._running:
            logger.warning("Heartbeat sender already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._thread.start()
        logger.info(f"Heartbeat sender started (interval: {self.interval}s)")
    
    def stop(self):
        """Stop heartbeat sender"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Heartbeat sender stopped")
    
    def _heartbeat_loop(self):
        """Main heartbeat loop - UTC only"""
        while self._running:
            try:
                success = self._send_heartbeat()
                
                if success:
                    self._consecutive_failures = 0
                    self._last_successful_heartbeat = now()  # UTC timestamp
                    sleep_time = self.interval
                else:
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= self.max_failures:
                        logger.error(f"Too many consecutive heartbeat failures ({self._consecutive_failures}), stopping")
                        break
                    sleep_time = self.retry_interval
                
                # Sleep with periodic checks for shutdown
                for _ in range(int(sleep_time)):
                    if not self._running:
                        break
                    sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                sleep(self.retry_interval)
    
    def _send_heartbeat(self) -> bool:
        """Send heartbeat to server - UTC only"""
        # Collect system metrics
        metrics = self._collect_metrics()
        
        # Create heartbeat data với UTC timestamp
        heartbeat_data = {
            "agent_id": self.agent_id,
            "token": self.agent_token,
            "timestamp": now_iso(),  # UTC ISO timestamp
            "metrics": metrics,
            "status": "active",
            "platform": platform.system(),
            "os_info": f"{platform.system()} {platform.release()}",
            "agent_version": "1.0.0"
        }
        
        # Try each server URL
        for server_url in self.server_urls:
            try:
                url = f"{server_url.rstrip('/')}/api/agents/heartbeat"
                
                response = requests.post(
                    url,
                    json=heartbeat_data,
                    timeout=self.timeout,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        logger.debug(f"✅ Heartbeat sent successfully to {server_url}")
                        return True
                    else:
                        logger.warning(f"Server rejected heartbeat: {data.get('error', 'Unknown error')}")
                else:
                    logger.warning(f"Heartbeat failed with status {response.status_code}: {response.text}")
                    
            except requests.exceptions.ConnectTimeout:
                logger.warning(f"Connection timeout to {server_url}")
            except requests.exceptions.ConnectionError:
                logger.warning(f"Connection error to {server_url}")
            except Exception as e:
                logger.warning(f"Error sending heartbeat to {server_url}: {e}")
        
        logger.error("Failed to send heartbeat to any server")
        return False
    
    def _collect_metrics(self) -> Dict:
        """Collect system metrics - UTC only"""
        try:
            # Get disk usage for root drive (cross-platform)
            if platform.system() == "Windows":
                disk_path = "C:\\"
            else:
                disk_path = "/"
            
            return {
                "cpu_percent": round(psutil.cpu_percent(interval=0.1), 2),
                "memory_percent": round(psutil.virtual_memory().percent, 2),
                "disk_percent": round(psutil.disk_usage(disk_path).percent, 2),
                "uptime_seconds": int(now() - psutil.boot_time()),  # UTC calculation
                "network_connections": len(psutil.net_connections()),
                "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
                "timestamp": now_iso()  # UTC ISO timestamp
            }
        except Exception as e:
            logger.warning(f"Error collecting metrics: {e}")
            return {
                "cpu_percent": 0,
                "memory_percent": 0,
                "disk_percent": 0,
                "uptime_seconds": 0,
                "network_connections": 0,
                "timestamp": now_iso()  # UTC ISO timestamp
            }
    
    def get_status(self) -> Dict:
        """Get heartbeat sender status - UTC only"""
        last_heartbeat_iso = None
        if self._last_successful_heartbeat:
            # Convert UTC timestamp to ISO string
            last_heartbeat_iso = now_iso() if self._last_successful_heartbeat > 0 else "never"
        
        return {
            "enabled": self.enabled,
            "running": self._running,
            "agent_id": self.agent_id,
            "consecutive_failures": self._consecutive_failures,
            "last_successful_heartbeat": last_heartbeat_iso,
            "last_successful_timestamp": self._last_successful_heartbeat,  # UTC Unix timestamp
            "interval": self.interval,
            "status_timestamp": now_iso()  # UTC ISO timestamp
        }