# Import các thư viện cần thiết
import json  # Thư viện xử lý dữ liệu định dạng JSON
import logging
import os  # Thư viện tương tác với hệ điều hành
import re  # Thư viện xử lý biểu thức chính quy
import threading
import time
import requests
from datetime import datetime
from typing import Dict, Set, Optional

# Cấu hình logger cho module này
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """Simplified whitelist manager - only fetches from server"""
    
    def __init__(self, config: Dict):
        """
        Initialize the whitelist manager.
        
        Args:
            config: Configuration dictionary with keys:
                - update_interval: Seconds between whitelist updates
                - retry_interval: Seconds between retries on failure
                - max_retries: Maximum number of retries
                - timeout: Request timeout in seconds
        """
        # ✅ Thêm validation config
        if not isinstance(config, dict):
            raise ValueError("Config must be a dictionary")
            
        # ✅ Xử lý trường hợp thiếu config sections
        server_config = config.get("server", {})
        whitelist_config = config.get("whitelist", {})
        
        # Lấy server URL từ config chính
        self.server_url = server_config.get("url", "")
        
        # Cấu hình whitelist với default values
        self.update_interval = whitelist_config.get("update_interval", 300)
        self.retry_interval = whitelist_config.get("retry_interval", 60)
        self.max_retries = whitelist_config.get("max_retries", 5)
        self.timeout = whitelist_config.get("timeout", 10)
        
        # ✅ Validation
        if not self.server_url:
            logger.warning("Server URL not configured in config")
            
        # Chỉ lưu trong memory
        self.domains: Set[str] = set()
        self.last_updated: Optional[datetime] = None
        self.update_lock = threading.Lock()
        
        # Thread management
        self.update_thread = None
        self.running = False
        
        # Load whitelist ban đầu từ server
        self._load_initial_whitelist()
    
    def _load_initial_whitelist(self):
        """Load whitelist khi khởi động với retry logic"""
        retry_count = 0
        
        while retry_count < self.max_retries:
            success = self.update_whitelist_from_server()
            if success:
                logger.info(f"Successfully loaded initial whitelist with {len(self.domains)} domains")
                return
                
            retry_count += 1
            if retry_count < self.max_retries:
                logger.warning(f"Failed to load whitelist (attempt {retry_count}/{self.max_retries}), retrying in {self.retry_interval}s")
                time.sleep(self.retry_interval)
        
        # Nếu tất cả retry đều thất bại, dùng fallback
        logger.error("Failed to load whitelist from server after all retries, using minimal fallback")
        self._create_minimal_whitelist()
    
    def is_allowed(self, domain: str) -> bool:
        """
        Kiểm tra domain có được phép không.
        Thread-safe và hiệu quả với O(1) lookup.
        """
        if not domain:
            return False
            
        domain = domain.strip().lower()
        
        with self.update_lock:
            # Kiểm tra khớp trực tiếp
            if domain in self.domains:
                return True
                
            # Kiểm tra wildcard match
            parts = domain.split('.')
            for i in range(1, len(parts)):
                wildcard = f"*.{'.'.join(parts[i:])}"
                if wildcard in self.domains:
                    return True
                    
        return False
    
    def update_whitelist_from_server(self) -> bool:
        """Cập nhật từ server với error handling tốt hơn"""
        if not self.server_url:
            logger.error("Server URL not configured")
            return False
            
        try:
            url = f"{self.server_url.rstrip('/')}/api/whitelist/agent-sync"
            
            # Thêm parameters nếu có last_updated
            params = {}
            if self.last_updated:
                params['since'] = self.last_updated.isoformat()
                
            response = requests.get(
                url, 
                params=params,
                timeout=self.timeout,
                headers={'User-Agent': 'FirewallController-Agent/1.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                domains_list = data.get("domains", [])
                
                with self.update_lock:
                    if params.get('since'):
                        # Incremental update - merge với existing domains
                        new_domains = set(domains_list)
                        self.domains.update(new_domains)
                        logger.info(f"Incremental update: added {len(new_domains)} domains, total: {len(self.domains)}")
                    else:
                        # Full update - replace toàn bộ
                        self.domains = set(domains_list)
                        logger.info(f"Full update: loaded {len(self.domains)} domains")
                    
                    self.last_updated = datetime.now()
                
                return True
            else:
                logger.error(f"Server returned status {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to server (after {self.timeout}s)")
            return False
        except requests.exceptions.ConnectionError:
            logger.error("Connection error - server may be down")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error updating whitelist: {e}")
            return False
    
    def start_periodic_updates(self):
        """Bắt đầu cập nhật định kỳ với error handling"""
        if self.running:
            logger.warning("Periodic updates already running")
            return
            
        self.running = True
        self.update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self.update_thread.start()
        logger.info(f"Started periodic whitelist updates (interval: {self.update_interval}s)")
    
    def stop_periodic_updates(self):
        """Dừng cập nhật định kỳ một cách graceful"""
        if not self.running:
            return
            
        self.running = False
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
            if self.update_thread.is_alive():
                logger.warning("Update thread did not stop gracefully")
            else:
                logger.info("Periodic updates stopped")
    
    def _update_loop(self):
        """Background update loop với exponential backoff"""
        consecutive_failures = 0
        
        while self.running:
            try:
                success = self.update_whitelist_from_server()
                
                if success:
                    consecutive_failures = 0
                    sleep_time = self.update_interval
                else:
                    consecutive_failures += 1
                    # Exponential backoff: min(retry_interval * 2^failures, update_interval)
                    backoff_time = min(self.retry_interval * (2 ** consecutive_failures), self.update_interval)
                    sleep_time = backoff_time
                    logger.warning(f"Update failed {consecutive_failures} times, backing off for {sleep_time}s")
                
                # Sleep với khả năng interrupt
                for _ in range(int(sleep_time)):
                    if not self.running:
                        break
                    time.sleep(1)
                    
            except Exception as e:
                logger.error(f"Error in update loop: {e}")
                time.sleep(self.retry_interval)
    
    def _create_minimal_whitelist(self):
        """Tạo whitelist tối thiểu khi không thể kết nối server"""
        minimal_domains = {
            # Essential services
            "google.com", "www.google.com",
            "microsoft.com", "www.microsoft.com", 
            "github.com", "api.github.com",
            "stackoverflow.com",
            "wikipedia.org",
            
            # System updates
            "windowsupdate.microsoft.com",
            "update.microsoft.com",
            "download.microsoft.com",
            
            # Security
            "*.antivirus-vendors.com"  # Example wildcard
        }
        
        with self.update_lock:
            self.domains = minimal_domains
            self.last_updated = datetime.now()
        
        logger.warning(f"Created minimal whitelist with {len(minimal_domains)} domains")
    
    def get_stats(self) -> Dict:
        """Lấy thống kê về whitelist (useful for monitoring)"""
        with self.update_lock:
            return {
                "domain_count": len(self.domains),
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
                "is_running": self.running,
                "server_url": self.server_url
            }

# Test script đơn giản hơn
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Config đơn giản cho test
    test_config = {
        "server": {
            "url": "http://localhost:5000"
        },
        "whitelist": {
            "update_interval": 30,
            "retry_interval": 5,
            "max_retries": 3,
            "timeout": 10
        }
    }
    
    # Test WhitelistManager
    whitelist = WhitelistManager(test_config)
    
    # Test domain checking
    test_domains = ["google.com", "malware.example.com", "github.com"]
    
    print("\nTesting domain checks:")
    for domain in test_domains:
        allowed = whitelist.is_allowed(domain)
        print(f"Domain {domain}: {'ALLOWED' if allowed else 'BLOCKED'}")
    
    # Show stats
    print(f"\nWhitelist stats: {whitelist.get_stats()}")
    
    # Start periodic updates for demo
    print(f"\nStarting periodic updates for 10 seconds...")
    whitelist.start_periodic_updates()
    
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        whitelist.stop_periodic_updates()
        print("Whitelist manager stopped.")