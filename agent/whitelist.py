# Import các thư viện cần thiết
import json  # Thư viện xử lý dữ liệu định dạng JSON
import logging
import os  # Thư viện tương tác với hệ điều hành
import re  # Thư viện xử lý biểu thức chính quy
import socket  # Thư viện xử lý kết nối mạng
import threading
import time
import requests
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone  # ✅ FIX: Rename import to avoid conflict
from typing import Dict, Set, Optional

# Cấu hình logger cho module này
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """Simplified whitelist manager - only fetches from server"""
    
    def __init__(self, config: Dict):
        """Initialize the whitelist manager"""
        # ✅ FIX: Lấy config từ whitelist section
        whitelist_config = config.get("whitelist", {})
        
        # Basic settings từ config
        self.update_interval = whitelist_config.get("update_interval", 60)  # 5 minutes default
        self.retry_interval = whitelist_config.get("retry_interval", 60)     # 1 minute retry
        self.max_retries = whitelist_config.get("max_retries", 3)
        self.timeout = whitelist_config.get("timeout", 30)
        
        # ✅ FIX: Server connection từ config
        server_config = config.get("server", {})
        
        # ✅ THAY ĐỔI: Hỗ trợ nhiều server URLs với fallback
        server_urls = server_config.get("urls", [])
        if not server_urls:
            # Fallback to single URL for backward compatibility
            single_url = server_config.get("url", "https://firewall-controller-vu7f.onrender.com")
            server_urls = [single_url]
        
        # Chọn server URL đầu tiên làm primary
        self.primary_server_url = server_urls[0]
        self.fallback_urls = server_urls[1:] if len(server_urls) > 1 else []
        
        # Build sync endpoint URL
        if self.primary_server_url.endswith('/'):
            self.server_url = f"{self.primary_server_url}api/whitelist/agent-sync"
        else:
            self.server_url = f"{self.primary_server_url}/api/whitelist/agent-sync"
        
        # ✅ FIX: Auto-sync settings từ config
        self.auto_sync_enabled = whitelist_config.get("auto_sync", True)
        self.sync_on_startup = whitelist_config.get("sync_on_startup", True)
        self.auto_sync_firewall = whitelist_config.get("auto_sync_firewall", True)
        
        # ✅ THÊM: Connection settings từ server config
        self.connect_timeout = server_config.get("connect_timeout", 10)
        self.read_timeout = server_config.get("read_timeout", 30)
        
        # State management
        self.domains: Set[str] = set()
        self.last_updated: Optional[datetime] = None
        self.firewall_manager = None
        self.update_lock = threading.Lock()
        
        # ✅ ADD: Threading for periodic updates
        self._update_thread = None
        self._stop_event = threading.Event()
        self._running = False
        
        # Load saved state
        self._load_whitelist_state()
        
        logger.info(f"WhitelistManager initialized:")
        logger.info(f"  - Primary server: {self.primary_server_url}")
        logger.info(f"  - Sync URL: {self.server_url}")
        logger.info(f"  - Fallback URLs: {len(self.fallback_urls)}")
        logger.info(f"  - Update interval: {self.update_interval}s")
        logger.info(f"  - Auto-sync: {self.auto_sync_enabled}")
        logger.info(f"  - Auto-sync firewall: {self.auto_sync_firewall}")
        logger.info(f"  - Loaded {len(self.domains)} cached domains")
        
        # ✅ ADD: Start auto-sync if enabled
        if self.auto_sync_enabled:
            self.start_periodic_updates()
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        try:
            # Try to use zoneinfo (Python 3.9+)
            from zoneinfo import ZoneInfo
            vn_tz = ZoneInfo("Asia/Ho_Chi_Minh")
        except ImportError:
            # Fallback for older Python versions
            vn_tz = dt_timezone(timedelta(hours=7), name="UTC+7")  # ✅ FIX: Use dt_timezone
        
        utc_now = datetime.now(dt_timezone.utc)  # ✅ FIX: Use dt_timezone.utc
        return utc_now.astimezone(vn_tz)
    
    def _load_whitelist_state(self):
        """Load whitelist state from file"""
        state_file = "whitelist_state.json"
        try:
            if os.path.exists(state_file):
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                    
                self.domains = set(state.get("domains", []))
                
                # Parse last_updated
                last_updated_str = state.get("last_updated")
                if last_updated_str:
                    try:
                        self.last_updated = datetime.fromisoformat(last_updated_str.replace('Z', '+00:00'))
                    except ValueError:
                        self.last_updated = None
                
                logger.info(f"Loaded {len(self.domains)} domains from cache")
                if self.last_updated:
                    logger.info(f"Last updated: {self.last_updated}")
            else:
                logger.info("No cached whitelist found, will do full sync")
                
        except Exception as e:
            logger.error(f"Error loading whitelist state: {e}")
            self.domains = set()
            self.last_updated = None
    
    def _save_whitelist_state(self):
        """Save whitelist state to file"""
        state_file = "whitelist_state.json"
        try:
            state = {
                "domains": list(self.domains),
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
                "domain_count": len(self.domains),
                "saved_at": self._now_local().isoformat()
            }
            
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
                
            logger.debug(f"Saved {len(self.domains)} domains to cache")
            
        except Exception as e:
            logger.error(f"Error saving whitelist state: {e}")
    
    def _load_initial_whitelist(self):
        """Load minimal whitelist for offline operation"""
        try:
            # Essential domains that should always be allowed
            essential_domains = [
                "localhost",
                "127.0.0.1",
                self.server_url.split("://")[1].split("/")[0] if "://" in self.server_url else "localhost"
            ]
            
            self.domains.update(essential_domains)
            logger.info(f"Loaded {len(essential_domains)} essential domains")
            
        except Exception as e:
            logger.error(f"Error loading initial whitelist: {e}")
    
    def is_allowed(self, domain: str) -> bool:
        """Check if domain is in whitelist"""
        if not domain:
            return False
            
        domain = domain.lower().strip()
        
        # Direct match
        if domain in self.domains:
            return True
            
        # Wildcard match (*.example.com matches sub.example.com)
        for whitelisted in self.domains:
            if whitelisted.startswith("*."):
                parent_domain = whitelisted[2:]
                if domain.endswith("." + parent_domain) or domain == parent_domain:
                    return True
        
        return False
    
    def set_firewall_manager(self, firewall_manager):
        """Set firewall manager for automatic rule updates"""
        self.firewall_manager = firewall_manager
        logger.info("Firewall manager connected to whitelist")
    
    def update_whitelist_from_server(self) -> bool:
        """Update whitelist from server với fallback support"""
        if not self.server_url:
            logger.error("Server URL not configured")
            return False
        
        # ✅ FIX: Try primary server first, then fallbacks
        urls_to_try = [self.server_url]
        
        # Add fallback URLs
        for fallback_url in self.fallback_urls:
            if fallback_url.endswith('/'):
                fallback_sync_url = f"{fallback_url}api/whitelist/agent-sync"
            else:
                fallback_sync_url = f"{fallback_url}/api/whitelist/agent-sync"
            urls_to_try.append(fallback_sync_url)
        
        last_error = None
        
        for attempt, url in enumerate(urls_to_try):
            try:
                logger.info(f"Attempting sync from: {url} (attempt {attempt + 1}/{len(urls_to_try)})")
                
                # ✅ FIX: Prepare sync parameters
                params = {}
                
                # Add since parameter for incremental sync
                if self.last_updated:
                    since_str = self.last_updated.isoformat()
                    if not since_str.endswith('Z') and '+' not in since_str:
                        since_str += '+07:00'  # Add timezone if missing
                    params['since'] = since_str
                    logger.debug(f"Requesting incremental sync since: {since_str}")
                else:
                    logger.debug("Requesting full sync (no last_updated)")
                
                # Add agent ID if available
                if hasattr(self, 'agent_id'):
                    params['agent_id'] = self.agent_id
                
                # ✅ FIX: Make request with proper timeout and headers
                headers = {
                    'Accept': 'application/json',
                    'User-Agent': 'FirewallAgent/1.0'
                }
                
                logger.debug(f"Sync parameters: {params}")
                
                response = requests.get(
                    url, 
                    params=params,
                    headers=headers,
                    timeout=(self.connect_timeout, self.read_timeout)
                )
                
                logger.debug(f"Server response: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    logger.debug(f"Received data structure: {list(data.keys()) if isinstance(data, dict) else type(data)}")
                    
                    # ✅ FIX: Handle response format
                    domains_list = data.get("domains", [])
                    sync_type = data.get("type", "full")
                    server_timestamp = data.get("timestamp")
                    
                    if not isinstance(domains_list, list):
                        logger.error(f"Invalid domains data type: {type(domains_list)}")
                        continue  # Try next URL
                    
                    old_domains = self.domains.copy()
                    
                    with self.update_lock:
                        if sync_type == "incremental" and self.domains:
                            # Incremental update - add new domains
                            new_domains = set(domains_list)
                            added_domains = new_domains - self.domains
                            self.domains.update(new_domains)
                            logger.info(f"Incremental sync: added {len(added_domains)} domains, total: {len(self.domains)}")
                            if added_domains:
                                logger.debug(f"Added domains: {list(added_domains)[:10]}...")  # Show first 10
                        else:
                            # Full update - replace all domains
                            self.domains = set(domains_list)
                            logger.info(f"Full sync: loaded {len(self.domains)} domains")
                        
                        # ✅ FIX: Update timestamp from server or use current time
                        if server_timestamp:
                            try:
                                self.last_updated = datetime.fromisoformat(server_timestamp.replace('Z', '+00:00'))
                            except ValueError:
                                self.last_updated = self._now_local()
                        else:
                            self.last_updated = self._now_local()
                    
                    # ✅ ADD: Apply firewall changes if enabled and manager is available
                    if self.auto_sync_firewall and self.firewall_manager:
                        self._sync_with_firewall(old_domains, self.domains)
                    
                    # Save state after successful sync
                    self._save_whitelist_state()
                    
                    logger.info(f"✅ Whitelist sync completed successfully from {url}")
                    return True
                    
                elif response.status_code == 404:
                    logger.error(f"Agent sync endpoint not found on {url}")
                    last_error = f"404 Not Found on {url}"
                elif response.status_code == 500:
                    logger.error(f"Server error on {url}")
                    last_error = f"500 Server Error on {url}"
                else:
                    logger.error(f"Server {url} responded with status {response.status_code}: {response.text[:200]}")
                    last_error = f"HTTP {response.status_code} from {url}"
                    
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Cannot connect to {url}: {e}")
                last_error = f"Connection error to {url}: {e}"
            except requests.exceptions.Timeout as e:
                logger.warning(f"Request to {url} timed out: {e}")
                last_error = f"Timeout to {url}: {e}"
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error to {url}: {e}")
                last_error = f"Request error to {url}: {e}"
            except Exception as e:
                logger.error(f"Unexpected error with {url}: {e}")
                last_error = f"Unexpected error with {url}: {e}"
        
        # If all URLs failed
        logger.error(f"❌ All sync attempts failed. Last error: {last_error}")
        logger.warning("Using cached whitelist")
        return False
    
    def _sync_with_firewall(self, old_domains: set, new_domains: set):
        """Sync whitelist changes with firewall rules"""
        try:
            if not self.firewall_manager:
                logger.debug("No firewall manager available for sync")
                return
            
            # Find changes
            added_domains = new_domains - old_domains
            removed_domains = old_domains - new_domains
            
            if not added_domains and not removed_domains:
                logger.debug("No whitelist changes detected")
                return
            
            logger.info(f"Syncing firewall: +{len(added_domains)} domains, -{len(removed_domains)} domains")
            
            # Apply changes to firewall
            success_count = 0
            error_count = 0
            
            # Add rules for new domains
            for domain in added_domains:
                try:
                    # Resolve domain to IPs and create firewall rules
                    ips = self._resolve_domain_to_ips(domain)
                    for ip in ips:
                        if self.firewall_manager.allow_ip(ip, f"Whitelist: {domain}"):
                            success_count += 1
                        else:
                            error_count += 1
                except Exception as e:
                    logger.warning(f"Error adding firewall rule for {domain}: {e}")
                    error_count += 1
            
            # Remove rules for removed domains
            for domain in removed_domains:
                try:
                    # This would need firewall manager to support domain-based rule removal
                    # For now, just log it
                    logger.debug(f"Should remove firewall rules for: {domain}")
                except Exception as e:
                    logger.warning(f"Error removing firewall rule for {domain}: {e}")
            
            if success_count > 0:
                logger.info(f"Applied {success_count} firewall rule changes")
            if error_count > 0:
                logger.warning(f"Failed to apply {error_count} firewall rule changes")
                
        except Exception as e:
            logger.error(f"Error syncing with firewall: {e}")
    
    def _resolve_domain_to_ips(self, domain: str) -> list:
        """Resolve domain to IP addresses"""
        try:
            # Remove wildcard prefix if present
            clean_domain = domain.replace("*.", "")
            
            # Get IP addresses
            ips = []
            try:
                # IPv4
                ipv4_results = socket.getaddrinfo(clean_domain, None, socket.AF_INET)
                ipv4_ips = [result[4][0] for result in ipv4_results]
                ips.extend(ipv4_ips)
            except:
                pass
            
            try:
                # IPv6
                ipv6_results = socket.getaddrinfo(clean_domain, None, socket.AF_INET6)
                ipv6_ips = [result[4][0] for result in ipv6_results]
                ips.extend(ipv6_ips)
            except:
                pass
            
            # Remove duplicates and return
            unique_ips = list(set(ips))
            logger.debug(f"Resolved {domain} to {len(unique_ips)} IPs: {unique_ips}")
            return unique_ips
            
        except Exception as e:
            logger.warning(f"Failed to resolve {domain}: {e}")
            return []
    
    def start_periodic_updates(self):
        """Start periodic whitelist updates"""
        if self._running:
            logger.warning("Periodic updates already running")
            return
        
        if not self.auto_sync_enabled:
            logger.info("Auto-sync disabled, not starting periodic updates")
            return
        
        self._running = True
        self._stop_event.clear()
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        
        logger.info(f"Started periodic whitelist updates (interval: {self.update_interval}s)")
        
        # ✅ ADD: Initial sync on startup
        if self.sync_on_startup:
            logger.info("Performing initial whitelist sync...")
            threading.Thread(target=self._initial_sync, daemon=True).start()
    
    def _initial_sync(self):
        """Perform initial sync with retries"""
        max_startup_retries = 5
        retry_delay = 10
        
        for attempt in range(max_startup_retries):
            try:
                if self.update_whitelist_from_server():
                    logger.info("✅ Initial whitelist sync completed successfully")
                    return
                else:
                    logger.warning(f"Initial sync attempt {attempt + 1} failed")
            except Exception as e:
                logger.error(f"Initial sync attempt {attempt + 1} error: {e}")
            
            if attempt < max_startup_retries - 1:
                logger.info(f"Retrying initial sync in {retry_delay}s...")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)  # Exponential backoff
        
        logger.error("❌ All initial sync attempts failed - using cached whitelist")
    
    def stop_periodic_updates(self):
        """Stop periodic whitelist updates"""
        if not self._running:
            return
        
        logger.info("Stopping periodic whitelist updates...")
        self._stop_event.set()
        self._running = False
        
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=5)
        
        logger.info("Periodic whitelist updates stopped")
    
    def _update_loop(self):
        """Main update loop for periodic syncing"""
        consecutive_failures = 0
        
        while not self._stop_event.is_set():
            try:
                logger.debug("Starting periodic whitelist update...")
                
                if self.update_whitelist_from_server():
                    consecutive_failures = 0
                    logger.debug(f"✅ Periodic sync completed, next update in {self.update_interval}s")
                else:
                    consecutive_failures += 1
                    logger.warning(f"❌ Periodic sync failed (attempt {consecutive_failures})")
                    
                    # If too many failures, increase retry interval
                    if consecutive_failures >= self.max_retries:
                        sleep_time = self.retry_interval * 2
                        logger.warning(f"Multiple sync failures, waiting {sleep_time}s before retry")
                    else:
                        sleep_time = self.retry_interval
                        
                    if self._stop_event.wait(sleep_time):
                        break
                    continue
                
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Error in update loop: {e}")
            
            # Wait for next update
            if self._stop_event.wait(self.update_interval):
                break
        
        logger.info("Update loop terminated")
    
    def get_stats(self) -> Dict:
        """Get whitelist statistics"""
        return {
            "total_domains": len(self.domains),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "update_interval": self.update_interval,
            "auto_sync_enabled": self.auto_sync_enabled,
            "server_url": self.server_url,
            "is_running": self._running
        }
    
    def _create_minimal_whitelist(self):
        """Create minimal whitelist for offline operation"""
        self._load_initial_whitelist()
        logger.info("Created minimal whitelist for offline operation")
    
    def force_sync(self) -> bool:
        """Force immediate sync with server"""
        logger.info("🔄 Forcing immediate whitelist sync...")
        return self.update_whitelist_from_server()
    
    def get_domain_list(self) -> list:
        """Get current domain list"""
        return list(self.domains)
