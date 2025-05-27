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
        
        # ✅ THÊM: Lưu agent info nếu có
        self.agent_id = config.get("agent_id")
        self.agent_token = config.get("agent_token")
        
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
        
        # ✅ THÊM: Reference đến firewall manager
        self.firewall_manager = None
        self.auto_sync_firewall = config.get("whitelist", {}).get("auto_sync_firewall", True)
        
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
    
    def set_firewall_manager(self, firewall_manager):
        """Set reference to firewall manager for auto-sync."""
        self.firewall_manager = firewall_manager
        logger.info("Firewall manager linked to whitelist for auto-sync")
    
    def update_whitelist_from_server(self) -> bool:
        """Cập nhật từ server và sync với firewall"""
        if not self.server_url:
            logger.error("Server URL not configured")
            return False
            
        try:
            # ✅ SỬA: Đảm bảo URL được build đúng
            base_url = self.server_url.rstrip('/')
            if not base_url.endswith('/api'):
                url = f"{base_url}/api/whitelist/agent-sync"
            else:
                url = f"{base_url}/whitelist/agent-sync"
            
            params = {}
            if self.last_updated:
                params['since'] = self.last_updated.isoformat()
                
            if hasattr(self, 'agent_id') and self.agent_id:
                params['agent_id'] = self.agent_id
                
            logger.debug(f"Requesting whitelist from: {url}")
            
            response = requests.get(
                url, 
                params=params,
                timeout=self.timeout,
                headers={'User-Agent': 'FirewallController-Agent/0.1'}
            )
            
            if response.status_code == 200:
                data = response.json()
                domains_list = data.get("domains", [])
                sync_type = data.get("type", "full")
                
                old_domains = self.domains.copy()
                
                with self.update_lock:
                    if sync_type == "incremental" and self.domains:
                        # Incremental update - merge với existing domains
                        new_domains = set(domains_list)
                        self.domains.update(new_domains)
                        logger.info(f"Incremental update: added {len(new_domains)} domains, total: {len(self.domains)}")
                    else:
                        # Full update - replace toàn bộ
                        self.domains = set(domains_list)
                        logger.info(f"Full update: loaded {len(self.domains)} domains")
                    
                    self.last_updated = datetime.now()
                
                # ✅ THÊM: Auto-sync với firewall nếu có thay đổi
                if self.auto_sync_firewall and self.firewall_manager:
                    self._sync_with_firewall(old_domains, self.domains)
                
                return True
            else:
                logger.error(f"Server returned status {response.status_code}: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Error updating whitelist: {e}")
            return False
    
    def _sync_with_firewall(self, old_domains: set, new_domains: set):
        """Sync whitelist changes with firewall rules."""
        try:
            # Tìm domains được thêm và bị xóa
            added_domains = new_domains - old_domains
            removed_domains = old_domains - new_domains
            
            if not added_domains and not removed_domains:
                logger.debug("No whitelist changes, skipping firewall sync")
                return
            
            logger.info(f"Syncing firewall: +{len(added_domains)} domains, -{len(removed_domains)} domains")
            
            # Xóa rules cho domains không còn trong whitelist
            for domain in removed_domains:
                try:
                    # Resolve domain to IPs và xóa firewall rules
                    ips = self._resolve_domain_to_ips(domain)
                    for ip in ips:
                        self.firewall_manager.unblock_ip(ip, f"Removed from whitelist: {domain}")
                except Exception as e:
                    logger.warning(f"Error removing firewall rule for {domain}: {e}")
            
            # Thêm allow rules cho domains mới (tùy chọn)
            if self.firewall_manager.config.get("create_allow_rules", False):
                for domain in added_domains:
                    try:
                        # Resolve domain to IPs và tạo allow rules
                        ips = self._resolve_domain_to_ips(domain)
                        for ip in ips:
                            self.firewall_manager.allow_ip(ip, f"Whitelisted domain: {domain}")
                    except Exception as e:
                        logger.warning(f"Error creating allow rule for {domain}: {e}")
            
            logger.info("Firewall sync completed")
            
        except Exception as e:
            logger.error(f"Error syncing with firewall: {e}")
    
    def _resolve_domain_to_ips(self, domain: str) -> list:
        """Resolve domain to IP addresses."""
        import socket
        
        ips = []
        try:
            # Remove wildcard prefix
            clean_domain = domain.replace("*.", "")
            
            # Get IPv4 addresses
            try:
                ipv4_info = socket.getaddrinfo(clean_domain, None, socket.AF_INET)
                ipv4_ips = [info[4][0] for info in ipv4_info]
                ips.extend(ipv4_ips)
            except socket.gaierror:
                pass
            
            # Get IPv6 addresses (optional)
            try:
                ipv6_info = socket.getaddrinfo(clean_domain, None, socket.AF_INET6)
                ipv6_ips = [info[4][0] for info in ipv6_info]
                ips.extend(ipv6_ips)
            except socket.gaierror:
                pass
                
        except Exception as e:
            logger.warning(f"Error resolving {domain}: {e}")
        
        return list(set(ips))  # Remove duplicates
    
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
    
    def get_stats(self) -> Dict:
        """Lấy thống kê về whitelist (useful for monitoring)"""
        with self.update_lock:
            return {
                "domain_count": len(self.domains),
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
                "is_running": self.running,
                "server_url": self.server_url
            }
