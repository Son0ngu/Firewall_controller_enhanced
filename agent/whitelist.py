# Import các thư viện cần thiết
import json  # Thư viện xử lý dữ liệu định dạng JSON
import os  # Thư viện tương tác với hệ điều hành
import re  # Thư viện xử lý biểu thức chính quy
import socket  # Thư viện xử lý kết nối mạng
import threading
import time
import requests
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone  # ✅ FIX: Rename import to avoid conflict
from typing import Dict, Set, Optional, List

# Cấu hình logger cho module này
import logging
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """Enhanced Whitelist manager for whitelist-only firewall mode"""
    
    def __init__(self, config: Dict):
        """Initialize the whitelist manager với enhanced features"""
        # ✅ FIX: Lấy config từ whitelist section
        whitelist_config = config.get("whitelist", {})
        
        # Basic settings từ config
        self.update_interval = whitelist_config.get("update_interval", 300)  # 5 minutes default
        self.retry_interval = whitelist_config.get("retry_interval", 60)     # 1 minute retry
        self.max_retries = whitelist_config.get("max_retries", 3)
        self.timeout = whitelist_config.get("timeout", 30)
        
        # ✅ FIX: Server connection từ config
        server_config = config.get("server", {})
        
        # ✅ THAY ĐỔI: Hỗ trợ nhiều server URLs với fallback
        server_urls = server_config.get("urls", [])
        if not server_urls:
            # Fallback to single URL for backward compatibility
            single_url = server_config.get("url", "https://project2-bpvw.onrender.com")
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
        
        # ✅ ENHANCED: IP resolution and caching system
        self.ip_cache: Dict[str, Dict] = {}  # domain -> {ipv4: [...], ipv6: [...], timestamp: ...}
        self.ip_cache_timestamps: Dict[str, datetime] = {}  # domain -> last_resolved
        self.ip_cache_ttl = whitelist_config.get("ip_cache_ttl", 300)  # 5 minutes
        self.ip_refresh_interval = whitelist_config.get("ip_refresh_interval", 600)  # 10 minutes
        self.resolve_ips_on_startup = whitelist_config.get("resolve_ips_on_startup", True)
        
        # ✅ ENHANCED: Track current resolved IPs for firewall sync
        self.current_resolved_ips: Set[str] = set()
        self.previous_resolved_ips: Set[str] = set()
        
        # ✅ ENHANCED: State management
        self.domains: Set[str] = set()
        self.last_updated: Optional[datetime] = None
        self.firewall_manager = None
        self.sync_in_progress = False
        self.startup_sync_completed = False
        
        # ✅ ENHANCED: Threading control
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None
        self._ip_refresh_thread: Optional[threading.Thread] = None
        self._running = False
        
        # ✅ ENHANCED: Statistics and monitoring
        self.stats = {
            "sync_count": 0,
            "last_sync_time": None,
            "last_sync_duration": 0,
            "sync_errors": 0,
            "ip_resolution_count": 0,
            "ip_resolution_errors": 0,
            "firewall_sync_count": 0,
            "cache_hit_count": 0,
            "cache_miss_count": 0
        }
        
        # ✅ ENHANCED: Load cached data
        self._load_whitelist_state()
        self._load_ip_cache()
        
        # ✅ ENHANCED: Initial sync if enabled
        if self.sync_on_startup:
            logger.info("🔄 Performing initial whitelist sync...")
            if self.update_whitelist_from_server():
                logger.info("✅ Initial whitelist sync completed")
                
                # ✅ ENHANCED: Resolve IPs on startup for whitelist-only mode
                if self.resolve_ips_on_startup:
                    logger.info("🔍 Resolving IPs for all domains on startup...")
                    self._resolve_all_domain_ips()
                    logger.info("✅ Initial IP resolution completed")
                
                self.startup_sync_completed = True
            else:
                logger.warning("❌ Initial whitelist sync failed")
        
        # ✅ ENHANCED: Start background update thread
        if self.auto_sync_enabled:
            self.start_periodic_updates()
    
    # ✅ ENHANCED: IP Resolution Methods
    def _resolve_all_domain_ips(self, force_refresh: bool = False) -> bool:
        """Resolve IPs for all domains in whitelist"""
        try:
            if not self.domains:
                logger.debug("No domains to resolve")
                return True
            
            logger.info(f"🔍 Resolving IPs for {len(self.domains)} domains...")
            success_count = 0
            error_count = 0
            total_ips = set()
            
            for domain in self.domains:
                try:
                    ips = self._resolve_domain_ips_cached(domain, force_refresh)
                    if ips:
                        all_domain_ips = ips.get("ipv4", []) + ips.get("ipv6", [])
                        total_ips.update(all_domain_ips)
                        success_count += 1
                        logger.debug(f"✅ {domain} -> {len(all_domain_ips)} IPs")
                    else:
                        error_count += 1
                        logger.warning(f"❌ Failed to resolve {domain}")
                        
                except Exception as e:
                    error_count += 1
                    logger.warning(f"❌ Error resolving {domain}: {e}")
            
            # ✅ ENHANCED: Update tracking
            self.previous_resolved_ips = self.current_resolved_ips.copy()
            self.current_resolved_ips = total_ips
            
            # ✅ ENHANCED: Update stats
            self.stats["ip_resolution_count"] += success_count
            self.stats["ip_resolution_errors"] += error_count
            
            logger.info(f"🔍 IP resolution completed: {success_count} success, {error_count} errors, {len(total_ips)} total IPs")
            
            # ✅ ENHANCED: Save updated cache
            self._save_ip_cache()
            
            return error_count == 0
            
        except Exception as e:
            logger.error(f"Error in _resolve_all_domain_ips: {e}")
            return False
    
    def _resolve_domain_ips_cached(self, domain: str, force_refresh: bool = False) -> Dict[str, List[str]]:
        """Resolve domain IPs with caching"""
        try:
            clean_domain = domain.replace("*.", "")
            current_time = self._now_local()
            
            # ✅ ENHANCED: Check cache first (unless force refresh)
            cache_key = clean_domain
            if not force_refresh and cache_key in self.ip_cache:
                cache_entry = self.ip_cache[cache_key]
                cache_time = self.ip_cache_timestamps.get(cache_key)
                
                # Check if cache is still valid
                if cache_time and (current_time - cache_time).total_seconds() < self.ip_cache_ttl:
                    self.stats["cache_hit_count"] += 1
                    logger.debug(f"📋 Cache hit for {domain}")
                    return cache_entry
            
            # ✅ ENHANCED: Cache miss - resolve from DNS
            self.stats["cache_miss_count"] += 1
            logger.debug(f"🔍 Resolving {domain} (cache miss/expired/forced)")
            
            ip_data = self._resolve_domain_to_ips(domain)
            
            # ✅ ENHANCED: Cache the result if successful
            if ip_data and (ip_data.get("ipv4") or ip_data.get("ipv6")):
                self.ip_cache[cache_key] = ip_data
                self.ip_cache_timestamps[cache_key] = current_time
                logger.debug(f"📋 Cached IPs for {domain}")
            
            return ip_data
            
        except Exception as e:
            logger.warning(f"Error resolving {domain} with cache: {e}")
            return {"ipv4": [], "ipv6": []}
    
    def _resolve_domain_to_ips(self, domain: str) -> Dict[str, List[str]]:
        """Enhanced domain to IP resolution"""
        try:
            clean_domain = domain.replace("*.", "")
            
            # Skip if already an IP
            if self._is_ip_address(clean_domain):
                return {"ipv4": [clean_domain], "ipv6": []}
            
            result = {"ipv4": [], "ipv6": []}
            
            # ✅ ENHANCED: IPv4 resolution with better error handling
            try:
                ipv4_results = socket.getaddrinfo(
                    clean_domain, None, 
                    socket.AF_INET, 
                    socket.SOCK_STREAM
                )
                ipv4_ips = [res[4][0] for res in ipv4_results]
                result["ipv4"] = list(set(ipv4_ips))  # Remove duplicates
                logger.debug(f"🌐 IPv4 for {domain}: {result['ipv4']}")
            except socket.gaierror as e:
                logger.debug(f"No IPv4 records for {domain}: {e}")
            
            # ✅ ENHANCED: IPv6 resolution (optional, often not needed for firewalls)
            try:
                ipv6_results = socket.getaddrinfo(
                    clean_domain, None, 
                    socket.AF_INET6, 
                    socket.SOCK_STREAM
                )
                ipv6_ips = [res[4][0] for res in ipv6_results]
                result["ipv6"] = list(set(ipv6_ips))
                logger.debug(f"🌐 IPv6 for {domain}: {result['ipv6']}")
            except socket.gaierror as e:
                logger.debug(f"No IPv6 records for {domain}: {e}")
            
            total_ips = len(result["ipv4"]) + len(result["ipv6"])
            if total_ips > 0:
                logger.debug(f"✅ Resolved {domain} to {total_ips} IPs")
            else:
                logger.warning(f"❌ No IPs resolved for {domain}")
            
            return result
            
        except Exception as e:
            logger.warning(f"Failed to resolve {domain}: {e}")
            return {"ipv4": [], "ipv6": []}
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if string is an IP address (IPv4 or IPv6)"""
        try:
            # Try IPv4
            parts = address.split('.')
            if len(parts) == 4:
                return all(0 <= int(part) <= 255 for part in parts)
        except:
            pass
        
        try:
            # Try IPv6 (basic check)
            import ipaddress
            ipaddress.ip_address(address)
            return True
        except:
            pass
        
        return False
    
    # ✅ ENHANCED: Firewall Integration Methods
    def get_all_whitelisted_ips(self, force_refresh: bool = False) -> Set[str]:
        """Get all IP addresses from whitelisted domains với enhanced caching"""
        try:
            if force_refresh or not self.current_resolved_ips:
                logger.debug("🔄 Refreshing all whitelisted IPs...")
                self._resolve_all_domain_ips(force_refresh)
            
            return self.current_resolved_ips.copy()
            
        except Exception as e:
            logger.error(f"Error getting whitelisted IPs: {e}")
            return set()
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP address is allowed (either directly or via domain resolution)"""
        if not ip:
            return False
        
        try:
            # ✅ ENHANCED: Check if IP is directly in whitelist as domain
            if ip in self.domains:
                return True
            
            # ✅ ENHANCED: Check if IP belongs to any whitelisted domain
            return ip in self.current_resolved_ips
            
        except Exception as e:
            logger.warning(f"Error checking IP {ip}: {e}")
            return False
    
    def set_firewall_manager(self, firewall_manager):
        """Set firewall manager for auto-sync"""
        self.firewall_manager = firewall_manager
        logger.info("🔗 Firewall manager linked for auto-sync")
        
        # ✅ ENHANCED: Perform initial firewall sync if startup completed
        if self.startup_sync_completed and self.auto_sync_firewall:
            self._sync_with_firewall_initial()
    
    def _sync_with_firewall_initial(self):
        """Initial firewall sync for whitelist-only mode"""
        try:
            if not self.firewall_manager:
                logger.debug("No firewall manager available for initial sync")
                return
            
            logger.info("🔄 Performing initial firewall sync...")
            
            # ✅ ENHANCED: Get all current whitelisted IPs
            whitelisted_ips = self.get_all_whitelisted_ips()
            
            if not whitelisted_ips:
                logger.warning("No whitelisted IPs found for firewall sync")
                return
            
            # ✅ ENHANCED: Setup whitelist-only firewall
            success = self.firewall_manager.setup_whitelist_firewall(whitelisted_ips)
            
            if success:
                self.stats["firewall_sync_count"] += 1
                logger.info(f"✅ Initial firewall sync completed: {len(whitelisted_ips)} IPs")
            else:
                logger.error("❌ Initial firewall sync failed")
                
        except Exception as e:
            logger.error(f"Error in initial firewall sync: {e}")
    
    def _sync_with_firewall(self, old_domains: set, new_domains: set):
        """Enhanced firewall sync for runtime changes"""
        try:
            if not self.firewall_manager or not self.auto_sync_firewall:
                return
            
            # ✅ ENHANCED: Calculate IP changes instead of domain changes
            old_ips = self.previous_resolved_ips
            
            # ✅ ENHANCED: Resolve new domains to get current IPs
            if old_domains != new_domains:
                logger.info("🔄 Domain changes detected, resolving IPs...")
                self._resolve_all_domain_ips(force_refresh=True)
            
            new_ips = self.current_resolved_ips
            
            # ✅ ENHANCED: Sync IP changes with firewall
            if old_ips != new_ips:
                logger.info(f"🔄 IP changes detected: {len(old_ips)} -> {len(new_ips)}")
                success = self.firewall_manager.sync_whitelist_changes(old_ips, new_ips)
                
                if success:
                    self.stats["firewall_sync_count"] += 1
                    logger.info("✅ Runtime firewall sync completed")
                else:
                    logger.warning("❌ Runtime firewall sync had errors")
            else:
                logger.debug("No IP changes detected, skipping firewall sync")
            
        except Exception as e:
            logger.error(f"Error syncing with firewall: {e}")
    
    # ✅ ENHANCED: Periodic Update Methods
    def start_periodic_updates(self):
        """Start background threads for periodic updates"""
        if self._running:
            logger.warning("Periodic updates already running")
            return
        
        self._running = True
        self._stop_event.clear()
        
        # ✅ ENHANCED: Start whitelist update thread
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        
        # ✅ ENHANCED: Start IP refresh thread
        self._ip_refresh_thread = threading.Thread(target=self._ip_refresh_loop, daemon=True)
        self._ip_refresh_thread.start()
        
        logger.info("🔄 Periodic update threads started")
    
    def _update_loop(self):
        """Main update loop for periodic whitelist syncing"""
        consecutive_failures = 0
        
        while not self._stop_event.is_set():
            try:
                if self.update_whitelist_from_server():
                    consecutive_failures = 0
                    logger.debug(f"✅ Periodic whitelist sync completed")
                else:
                    consecutive_failures += 1
                    logger.warning(f"❌ Periodic whitelist sync failed (attempt {consecutive_failures})")
                
                # ✅ ENHANCED: Adaptive retry interval
                sleep_interval = self.update_interval
                if consecutive_failures > 0:
                    # Exponential backoff for failures
                    sleep_interval = min(self.update_interval * (2 ** min(consecutive_failures - 1, 3)), 1800)  # Max 30 minutes
                
                if self._stop_event.wait(sleep_interval):
                    break
                    
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Error in update loop: {e}")
                if self._stop_event.wait(self.retry_interval):
                    break
        
        logger.debug("Update loop stopped")
    
    def _ip_refresh_loop(self):
        """Background loop for periodic IP resolution refresh"""
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(self.ip_refresh_interval):
                    break
                
                if self.domains:
                    logger.debug("🔄 Performing periodic IP refresh...")
                    old_ips = self.current_resolved_ips.copy()
                    
                    # ✅ ENHANCED: Refresh IP resolution
                    self._resolve_all_domain_ips(force_refresh=True)
                    
                    # ✅ ENHANCED: Check for changes and sync firewall if needed
                    if old_ips != self.current_resolved_ips:
                        logger.info(f"📍 IP changes detected during refresh: {len(old_ips)} -> {len(self.current_resolved_ips)}")
                        if self.firewall_manager and self.auto_sync_firewall:
                            self.firewall_manager.sync_whitelist_changes(old_ips, self.current_resolved_ips)
                    else:
                        logger.debug("No IP changes detected during refresh")
                
            except Exception as e:
                logger.error(f"Error in IP refresh loop: {e}")
                if self._stop_event.wait(60):  # Wait 1 minute on error
                    break
        
        logger.debug("IP refresh loop stopped")
    
    def stop_periodic_updates(self):
        """Stop all background update threads"""
        if not self._running:
            return
        
        logger.info("🛑 Stopping periodic updates...")
        self._stop_event.set()
        self._running = False
        
        # ✅ ENHANCED: Wait for threads to finish
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=5)
        
        if self._ip_refresh_thread and self._ip_refresh_thread.is_alive():
            self._ip_refresh_thread.join(timeout=5)
        
        # ✅ ENHANCED: Save state before stopping
        self._save_whitelist_state()
        self._save_ip_cache()
        
        logger.info("✅ Periodic updates stopped and state saved")
    
    # ✅ ENHANCED: Server Communication Methods
    def update_whitelist_from_server(self) -> bool:
        """Enhanced whitelist update from server with better error handling"""
        if self.sync_in_progress:
            logger.debug("Sync already in progress, skipping")
            return False
        
        self.sync_in_progress = True
        start_time = time.time()
        
        try:
            # ✅ ENHANCED: Build request with since parameter
            params = {}
            if self.last_updated:
                params['since'] = self.last_updated.isoformat()
            
            logger.debug(f"📡 Syncing whitelist from server: {self.server_url}")
            
            # ✅ ENHANCED: Make request with timeout
            response = requests.get(
                self.server_url,
                params=params,
                timeout=(self.connect_timeout, self.read_timeout),
                headers={'User-Agent': 'FirewallController-Agent/1.0'
            })
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success', True):  # Default to True for backward compatibility
                    domains = data.get('domains', [])
                    
                    # ✅ ENHANCED: Store old domains for comparison
                    old_domains = self.domains.copy()
                    
                    # ✅ ENHANCED: Update domains
                    if isinstance(domains, list):
                        self.domains = set(domain.lower().strip() for domain in domains if domain)
                        logger.info(f"📦 Updated whitelist: {len(self.domains)} domains")
                    else:
                        logger.warning("Invalid domains format in response")
                        return False
                    
                    # ✅ ENHANCED: Update timestamp
                    self.last_updated = self._now_local()
                    
                    # ✅ ENHANCED: Update stats
                    self.stats["sync_count"] += 1
                    self.stats["last_sync_time"] = self.last_updated
                    self.stats["last_sync_duration"] = time.time() - start_time
                    
                    # ✅ ENHANCED: Save state
                    self._save_whitelist_state()
                    
                    # ✅ ENHANCED: Sync with firewall if domains changed
                    if old_domains != self.domains:
                        logger.info(f"🔄 Domain changes detected: {len(old_domains)} -> {len(self.domains)}")
                        self._sync_with_firewall(old_domains, self.domains)
                    
                    logger.info(f"✅ Whitelist sync completed successfully in {time.time() - start_time:.2f}s")
                    return True
                else:
                    logger.error(f"Server error: {data.get('error', 'Unknown error')}")
                    return False
            else:
                logger.error(f"HTTP error {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            logger.warning("Request timeout - server may be slow")
            self.stats["sync_errors"] += 1
            return False
        except requests.exceptions.ConnectionError:
            logger.warning("Connection error - server may be unreachable")
            self.stats["sync_errors"] += 1
            return False
        except Exception as e:
            logger.error(f"Error updating whitelist: {e}")
            self.stats["sync_errors"] += 1
            return False
        finally:
            self.sync_in_progress = False
    
    # ✅ ENHANCED: State Management Methods
    def _save_whitelist_state(self):
        """Enhanced save whitelist state to file"""
        state_file = "whitelist_state.json"
        try:
            state = {
                "domains": list(self.domains),
                "last_updated": self.last_updated.isoformat() if self.last_updated else None,
                "domain_count": len(self.domains),
                "current_resolved_ips": list(self.current_resolved_ips),
                "stats": self.stats,
                "saved_at": self._now_local().isoformat(),
                "version": "2.0"  # Version for future compatibility
            }
            
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"💾 Saved whitelist state: {len(self.domains)} domains")
            
        except Exception as e:
            logger.error(f"Error saving whitelist state: {e}")
    
    def _load_whitelist_state(self):
        """Enhanced load whitelist state from file"""
        state_file = "whitelist_state.json"
        try:
            if os.path.exists(state_file):
                with open(state_file, 'r', encoding='utf-8') as f:
                    state = json.load(f)
                
                # ✅ ENHANCED: Load with version compatibility
                version = state.get("version", "1.0")
                
                self.domains = set(state.get("domains", []))
                
                if state.get("last_updated"):
                    try:
                        self.last_updated = datetime.fromisoformat(state["last_updated"])
                    except:
                        self.last_updated = None
                
                # ✅ ENHANCED: Load resolved IPs if available (v2.0+)
                if version >= "2.0" and "current_resolved_ips" in state:
                    self.current_resolved_ips = set(state["current_resolved_ips"])
                
                # ✅ ENHANCED: Load stats if available
                if "stats" in state:
                    self.stats.update(state["stats"])
                
                logger.info(f"📂 Loaded whitelist state: {len(self.domains)} domains")
                
        except Exception as e:
            logger.warning(f"Could not load whitelist state: {e}")
    
    def _save_ip_cache(self):
        """Enhanced save IP cache to file"""
        cache_file = "ip_cache.json"
        try:
            # ✅ ENHANCED: Prepare timestamp data for JSON serialization
            timestamp_data = {}
            for domain, timestamp in self.ip_cache_timestamps.items():
                timestamp_data[domain] = timestamp.isoformat()
            
            cache_data = {
                "cache": self.ip_cache,
                "timestamps": timestamp_data,
                "cache_ttl": self.ip_cache_ttl,
                "stats": {
                    "cache_hits": self.stats["cache_hit_count"],
                    "cache_misses": self.stats["cache_miss_count"]
                },
                "saved_at": self._now_local().isoformat(),
                "version": "2.0"
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"💾 Saved IP cache: {len(self.ip_cache)} entries")
            
        except Exception as e:
            logger.error(f"Error saving IP cache: {e}")
    
    def _load_ip_cache(self):
        """Enhanced load IP cache from file"""
        cache_file = "ip_cache.json"
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                
                self.ip_cache = cache_data.get("cache", {})
                
                # ✅ ENHANCED: Parse timestamps with error handling
                timestamp_data = cache_data.get("timestamps", {})
                for domain, timestamp_str in timestamp_data.items():
                    try:
                        self.ip_cache_timestamps[domain] = datetime.fromisoformat(timestamp_str)
                    except:
                        # Remove invalid entries
                        self.ip_cache.pop(domain, None)
                
                # ✅ ENHANCED: Clean expired entries on load
                self._clean_expired_cache()
                
                logger.debug(f"📂 Loaded IP cache: {len(self.ip_cache)} entries")
                
        except Exception as e:
            logger.warning(f"Could not load IP cache: {e}")
            self.ip_cache = {}
            self.ip_cache_timestamps = {}
    
    def _clean_expired_cache(self):
        """Clean expired cache entries"""
        current_time = self._now_local()
        expired_domains = []
        
        for domain, timestamp in self.ip_cache_timestamps.items():
            if (current_time - timestamp).total_seconds() > self.ip_cache_ttl:
                expired_domains.append(domain)
        
        for domain in expired_domains:
            self.ip_cache.pop(domain, None)
            self.ip_cache_timestamps.pop(domain, None)
        
        if expired_domains:
            logger.debug(f"🧹 Cleaned {len(expired_domains)} expired cache entries")
    
    # ✅ ENHANCED: Utility Methods
    def _now_local(self) -> datetime:
        """Get current local time"""
        return datetime.now()
    
    def is_allowed(self, domain: str) -> bool:
        """Enhanced check if domain is in whitelist với wildcard support"""
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        # ✅ ENHANCED: Direct match
        if domain in self.domains:
            return True
        
        # ✅ ENHANCED: Wildcard match (*.example.com matches sub.example.com)
        for whitelisted in self.domains:
            if whitelisted.startswith("*."):
                parent_domain = whitelisted[2:]
                if domain.endswith("." + parent_domain) or domain == parent_domain:
                    return True
        
        return False
    
    # ✅ ENHANCED: Status and Monitoring Methods
    def get_status(self) -> Dict:
        """Get comprehensive status information"""
        current_time = self._now_local()
        
        return {
            "domains_count": len(self.domains),
            "resolved_ips_count": len(self.current_resolved_ips),
            "cache_entries": len(self.ip_cache),
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "auto_sync_enabled": self.auto_sync_enabled,
            "sync_in_progress": self.sync_in_progress,
            "startup_sync_completed": self.startup_sync_completed,
            "firewall_linked": self.firewall_manager is not None,
            "stats": self.stats.copy(),
            "cache_stats": {
                "hit_rate": self.stats["cache_hit_count"] / max(self.stats["cache_hit_count"] + self.stats["cache_miss_count"], 1) * 100,
                "entries": len(self.ip_cache),
                "ttl_seconds": self.ip_cache_ttl
            },
            "current_time": current_time.isoformat()
        }
    
    def get_domain_details(self, domain: str = None) -> Dict:
        """Get detailed information about domains and their IPs"""
        if domain:
            # ✅ ENHANCED: Single domain details
            domain = domain.lower().strip()
            if domain not in self.domains:
                return {"error": "Domain not in whitelist"}
            
            ip_data = self._resolve_domain_ips_cached(domain)
            cache_time = self.ip_cache_timestamps.get(domain.replace("*.", ""))
            
            return {
                "domain": domain,
                "in_whitelist": True,
                "ipv4_addresses": ip_data.get("ipv4", []),
                "ipv6_addresses": ip_data.get("ipv6", []),
                "total_ips": len(ip_data.get("ipv4", [])) + len(ip_data.get("ipv6", [])),
                "cache_time": cache_time.isoformat() if cache_time else None,
                "cache_age_seconds": (self._now_local() - cache_time).total_seconds() if cache_time else None
            }
        else:
            # ✅ ENHANCED: All domains summary
            return {
                "total_domains": len(self.domains),
                "total_resolved_ips": len(self.current_resolved_ips),
                "cached_domains": len(self.ip_cache),
                "cache_hit_rate": f"{self.stats['cache_hit_count'] / max(self.stats['cache_hit_count'] + self.stats['cache_miss_count'], 1) * 100:.1f}%",
                "sample_domains": list(self.domains)[:10] if self.domains else []
            }
    
    def force_refresh(self) -> bool:
        """Force refresh of whitelist and IP resolution"""
        try:
            logger.info("🔄 Forcing complete refresh...")
            
            # ✅ ENHANCED: Force whitelist update
            whitelist_success = self.update_whitelist_from_server()
            
            # ✅ ENHANCED: Force IP resolution
            ip_success = self._resolve_all_domain_ips(force_refresh=True)
            
            success = whitelist_success and ip_success
            logger.info(f"✅ Force refresh completed: {'success' if success else 'partial'}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error in force refresh: {e}")
            return False


# ✅ NEW: Example usage and testing
if __name__ == "__main__":
    # Test whitelist manager
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Test configuration
    test_config = {
        "server": {
            "url": "https://project2-bpvw.onrender.com",
            "connect_timeout": 10,
            "read_timeout": 30
        },
        "whitelist": {
            "auto_sync": True,
            "sync_on_startup": True,
            "update_interval": 60,
            "ip_cache_ttl": 300,
            "resolve_ips_on_startup": True
        }
    }
    
    print("\n=== Testing Enhanced WhitelistManager ===")
    
    # Initialize whitelist manager
    whitelist = WhitelistManager(test_config)
    
    # Test status
    status = whitelist.get_status()
    print(f"\nStatus: {status}")
    
    # Test domain details
    if whitelist.domains:
        sample_domain = next(iter(whitelist.domains))
        details = whitelist.get_domain_details(sample_domain)
        print(f"\nSample domain details: {details}")
    
    # Test IP checking
    test_ips = ["8.8.8.8", "1.1.1.1", "127.0.0.1"]
    for ip in test_ips:
        allowed = whitelist.is_ip_allowed(ip)
        print(f"IP {ip} allowed: {allowed}")
    
    # Stop manager
    whitelist.stop_periodic_updates()
    print("\nTesting completed")
