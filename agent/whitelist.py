# Import các thư viện cần thiết
import json
import os
import socket
import threading
import requests
from typing import Dict, Set, Optional, List

# Import time utilities
from time_utils import now, now_server_compatible, sleep

# Cấu hình logger cho module này
import logging
logger = logging.getLogger("whitelist")

class WhitelistManager:
    """Enhanced Whitelist manager for whitelist-only firewall mode"""
    
    def __init__(self, config: Dict):
        """Initialize the whitelist manager - SERVER SYNC ONLY"""
        #  FIX: Lấy config từ whitelist section
        whitelist_config = config.get("whitelist", {})
        
        # Basic settings từ config
        self.update_interval = whitelist_config.get("update_interval", 300)  # 5 minutes default
        self.retry_interval = whitelist_config.get("retry_interval", 60)     # 1 minute retry
        self.max_retries = whitelist_config.get("max_retries", 3)
        self.timeout = whitelist_config.get("timeout", 30)
        
        #  FIX: Server connection từ config
        server_config = config.get("server", {})
        
        #  THAY ĐỔI: Hỗ trợ nhiều server URLs với fallback
        server_urls = server_config.get("urls", [])
        if not server_urls:
            # Fallback to single URL for backward compatibility
            single_url = server_config.get("url", "https://firewall-controller.onrender.com")
            server_urls = [single_url]
        
        # Chọn server URL đầu tiên làm primary
        self.primary_server_url = server_urls[0]
        self.fallback_urls = server_urls[1:] if len(server_urls) > 1 else []
        
        # Build sync endpoint URL
        if self.primary_server_url.endswith('/'):
            self.server_url = f"{self.primary_server_url}api/whitelist/agent-sync"
        else:
            self.server_url = f"{self.primary_server_url}/api/whitelist/agent-sync"
        
        #  FIX: Auto-sync settings từ config
        self.auto_sync_enabled = whitelist_config.get("auto_sync", True)
        self.sync_on_startup = whitelist_config.get("sync_on_startup", True)
        self.auto_sync_firewall = whitelist_config.get("auto_sync_firewall", True)
        
        #  THÊM: Connection settings từ server config
        self.connect_timeout = server_config.get("connect_timeout", 10)
        self.read_timeout = server_config.get("read_timeout", 30)
        
        #  ENHANCED: IP resolution and caching system
        self.ip_cache: Dict[str, Dict] = {}
        self.ip_cache_timestamps: Dict[str, float] = {}  # Using timestamp instead of datetime
        self.ip_cache_ttl = whitelist_config.get("ip_cache_ttl", 300)  # 5 minutes
        self.ip_refresh_interval = whitelist_config.get("ip_refresh_interval", 600)  # 10 minutes
        self.resolve_ips_on_startup = whitelist_config.get("resolve_ips_on_startup", True)
        
        #  ENHANCED: Track current resolved IPs for firewall sync
        self.current_resolved_ips: Set[str] = set()
        self.previous_resolved_ips: Set[str] = set()
        
        #  ENHANCED: State management
        self.domains: Set[str] = set()  # Start with empty set - only server domains
        self.last_updated: Optional[float] = None  # Using timestamp instead of datetime
        self.firewall_manager = None
        self.sync_in_progress = False
        self.startup_sync_completed = False
        
        #  ENHANCED: Threading control
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None
        self._ip_refresh_thread: Optional[threading.Thread] = None
        self._running = False
        
        #  ENHANCED: Statistics and monitoring
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
        
        #  ENHANCED: Load cached data (may be empty)
        self._load_whitelist_state()
        self._load_ip_cache()
        
        #  CRITICAL: ONLY sync from server - no fallback domains
        if self.sync_on_startup:
            logger.info("🔄 Performing initial whitelist sync from server...")
            if self.update_whitelist_from_server():
                logger.info(" Initial whitelist sync completed")
                
                if len(self.domains) == 0:
                    logger.warning("⚠️ Server returned no domains - proceeding with empty whitelist")
                
                #  ENHANCED: Resolve IPs only if we have domains
                if self.resolve_ips_on_startup and len(self.domains) > 0:
                    logger.info("🔍 Resolving IPs for server domains...")
                    self._resolve_all_domain_ips()
                    logger.info(" Initial IP resolution completed")
                
                self.startup_sync_completed = True
            else:
                logger.error("❌ Initial whitelist sync failed - no domains available")
                logger.error("   Agent will have empty whitelist until server sync succeeds")
        else:
            logger.info("📋 Startup sync disabled - domains will be loaded on first periodic sync")
        
        #  ENHANCED: Start background update thread
        if self.auto_sync_enabled:
            self.start_periodic_updates()

    # ========================================
    # CORE WHITELIST METHODS
    # ========================================

    def is_allowed(self, domain: str) -> bool:
        """Check if a domain is in the whitelist"""
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        #  ENHANCED: Direct domain match
        if domain in self.domains:
            return True
        
        #  ENHANCED: Wildcard domain check
        for whitelist_domain in self.domains:
            if whitelist_domain.startswith("*."):
                # Wildcard domain (e.g., *.google.com)
                base_domain = whitelist_domain[2:]
                if domain == base_domain or domain.endswith("." + base_domain):
                    return True
        
        return False

    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP address is allowed (either directly or via domain resolution)"""
        if not ip:
            return False
        
        try:
            #  ENHANCED: Check if IP is directly in whitelist as domain
            if ip in self.domains:
                return True
            
            #  ENHANCED: Check if IP belongs to any whitelisted domain
            if ip in self.current_resolved_ips:
                return True
            
            #  NEW: Check if IP is in essential_ips (DNS servers, localhost, etc.)
            if self.firewall_manager and hasattr(self.firewall_manager, 'essential_ips'):
                if ip in self.firewall_manager.essential_ips:
                    return True
            
            #  FALLBACK: Check against common essential IPs directly
            essential_fallback = {
                "127.0.0.1", "::1", "0.0.0.0",
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "208.67.222.222", "208.67.220.220"
            }
            if ip in essential_fallback:
                return True
                
            return False
            
        except Exception as e:
            logger.warning(f"Error checking IP {ip}: {e}")
            return False

    # ========================================
    # IP RESOLUTION METHODS
    # ========================================

    def _resolve_all_domain_ips(self, force_refresh: bool = False) -> bool:
        """Resolve IPs for all domains with DNS safety checks"""
        try:
            if not self.domains:
                logger.warning("❌ No domains to resolve!")
                return False
            
            logger.info(f"🔍 Resolving IPs for {len(self.domains)} domains...")
            
            #  THÊM: Test DNS connectivity first
            if not self._test_dns_connectivity():
                logger.warning("⚠️ DNS connectivity issues detected - proceeding anyway")
            
            total_ips = set()
            success_count = 0
            
            for domain in self.domains:
                try:
                    ip_data = self._resolve_domain_ips_cached(domain, force_refresh)
                    if ip_data and (ip_data.get("ipv4") or ip_data.get("ipv6")):
                        ipv4_ips = ip_data.get("ipv4", [])
                        ipv6_ips = ip_data.get("ipv6", [])
                        
                        total_ips.update(ipv4_ips)
                        total_ips.update(ipv6_ips)  #  THÊM IPv6 support
                        
                        success_count += 1
                        logger.debug(f"    {domain}: {len(ipv4_ips)} IPv4, {len(ipv6_ips)} IPv6")
                    else:
                        logger.warning(f"   ❌ No IPs resolved for {domain}")
                except Exception as e:
                    logger.error(f"   ❌ Error resolving {domain}: {e}")
            
            #  UPDATE tracking
            self.previous_resolved_ips = self.current_resolved_ips.copy()
            self.current_resolved_ips = total_ips
            
            logger.info(f"🔍 Resolution completed: {success_count}/{len(self.domains)} domains, {len(total_ips)} total IPs")
            
            if len(total_ips) == 0:
                logger.error("❌ CRITICAL: No IPs resolved for any domain!")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error in IP resolution: {e}")
            return False

    def _test_dns_connectivity(self) -> bool:
        """Test DNS connectivity before domain resolution"""
        try:
            # Test với Google DNS
            socket.getaddrinfo("8.8.8.8", None, socket.AF_INET)
            # Test với một domain đơn giản
            socket.getaddrinfo("google.com", None, socket.AF_INET)
            return True
        except Exception as e:
            logger.warning(f"DNS connectivity test failed: {e}")
            return False

    def _resolve_domain_ips_cached(self, domain: str, force_refresh: bool = False) -> Dict[str, List[str]]:
        """Resolve domain IPs with caching"""
        try:
            clean_domain = domain.replace("*.", "")
            current_time = now()
            
            #  ENHANCED: Check cache first (unless force refresh)
            cache_key = clean_domain
            if not force_refresh and cache_key in self.ip_cache:
                cache_entry = self.ip_cache[cache_key]
                cache_time = self.ip_cache_timestamps.get(cache_key)
                
                # Check if cache is still valid
                if cache_time and (current_time - cache_time) < self.ip_cache_ttl:
                    self.stats["cache_hit_count"] += 1
                    logger.debug(f"📋 Cache hit for {domain}")
                    return cache_entry
            
            #  ENHANCED: Cache miss - resolve from DNS
            self.stats["cache_miss_count"] += 1
            logger.debug(f"🔍 Resolving {domain} (cache miss/expired/forced)")
            
            ip_data = self._resolve_domain_to_ips(domain)
            
            #  ENHANCED: Cache the result if successful
            if ip_data and (ip_data.get("ipv4") or ip_data.get("ipv6")):
                self.ip_cache[cache_key] = ip_data
                self.ip_cache_timestamps[cache_key] = current_time
                logger.debug(f"📋 Cached IPs for {domain}")
            
            return ip_data
            
        except Exception as e:
            logger.warning(f"Error resolving {domain} with cache: {e}")
            return {"ipv4": [], "ipv6": []}

    def _resolve_domain_to_ips(self, domain: str) -> Dict[str, List[str]]:
        """Enhanced domain to IP resolution with comprehensive coverage"""
        try:
            clean_domain = domain.replace("*.", "")
            
            # Skip if already an IP
            if self._is_ip_address(clean_domain):
                return {"ipv4": [clean_domain], "ipv6": []}
            
            result = {"ipv4": [], "ipv6": []}
            
            #  ENHANCED: Multiple resolution methods for better coverage
            
            # Method 1: Standard getaddrinfo (IPv4)
            try:
                ipv4_results = socket.getaddrinfo(
                    clean_domain, None, 
                    socket.AF_INET, 
                    socket.SOCK_STREAM
                )
                ipv4_ips = [res[4][0] for res in ipv4_results]
                result["ipv4"].extend(ipv4_ips)
                logger.debug(f"🌐 Method 1 - IPv4 for {domain}: {ipv4_ips}")
            except socket.gaierror as e:
                logger.debug(f"Method 1 failed for {domain}: {e}")
            
            # Method 2: Try with different socket types
            try:
                ipv4_results_dgram = socket.getaddrinfo(
                    clean_domain, None, 
                    socket.AF_INET, 
                    socket.SOCK_DGRAM
                )
                ipv4_ips_dgram = [res[4][0] for res in ipv4_results_dgram]
                result["ipv4"].extend(ipv4_ips_dgram)
                logger.debug(f"🌐 Method 2 - IPv4 DGRAM for {domain}: {ipv4_ips_dgram}")
            except socket.gaierror as e:
                logger.debug(f"Method 2 failed for {domain}: {e}")
            
            # Method 3: Try gethostbyname (legacy but sometimes gets different results)
            try:
                legacy_ip = socket.gethostbyname(clean_domain)
                result["ipv4"].append(legacy_ip)
                logger.debug(f"🌐 Method 3 - Legacy IPv4 for {domain}: {legacy_ip}")
            except socket.gaierror as e:
                logger.debug(f"Method 3 failed for {domain}: {e}")
            
            # Method 4: Try gethostbyname_ex for additional IPs
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(clean_domain)
                result["ipv4"].extend(ipaddrlist)
                logger.debug(f"🌐 Method 4 - Extended IPv4 for {domain}: {ipaddrlist}")
            except socket.gaierror as e:
                logger.debug(f"Method 4 failed for {domain}: {e}")
        
            #  ENHANCED: Remove duplicates and sort
            result["ipv4"] = sorted(list(set(result["ipv4"])))
            
            # Method 5: IPv6 resolution (optional but comprehensive)
            try:
                ipv6_results = socket.getaddrinfo(
                    clean_domain, None, 
                    socket.AF_INET6, 
                    socket.SOCK_STREAM
                )
                ipv6_ips = [res[4][0] for res in ipv6_results]
                result["ipv6"] = sorted(list(set(ipv6_ips)))
                logger.debug(f"🌐 IPv6 for {domain}: {result['ipv6']}")
            except socket.gaierror as e:
                logger.debug(f"No IPv6 records for {domain}: {e}")
            
            total_ips = len(result["ipv4"]) + len(result["ipv6"])
            if total_ips > 0:
                logger.debug(f" Resolved {domain} to {total_ips} IPs (IPv4: {len(result['ipv4'])}, IPv6: {len(result['ipv6'])})")
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

    def _clean_expired_cache(self):
        """Clean expired cache entries"""
        try:
            current_time = now()
            expired_domains = []
            
            for domain, timestamp in self.ip_cache_timestamps.items():
                if (current_time - timestamp) > self.ip_cache_ttl:
                    expired_domains.append(domain)
            
            for domain in expired_domains:
                self.ip_cache.pop(domain, None)
                self.ip_cache_timestamps.pop(domain, None)
                logger.debug(f"🗑️ Removed expired cache for {domain}")
                
        except Exception as e:
            logger.warning(f"Error cleaning expired cache: {e}")

    # ========================================
    # FIREWALL INTEGRATION
    # ========================================

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

    def set_firewall_manager(self, firewall_manager):
        """Set firewall manager for auto-sync"""
        self.firewall_manager = firewall_manager
        logger.info("🔗 Firewall manager linked for auto-sync")
        
        #  ENHANCED: Perform initial firewall sync if startup completed
        if self.startup_sync_completed and self.auto_sync_firewall:
            self._sync_with_firewall_initial()

    def _sync_with_firewall_initial(self):
        """Initial firewall sync for whitelist-only mode"""
        try:
            if not self.firewall_manager:
                logger.debug("No firewall manager available for initial sync")
                return
            
            logger.info("🔄 Performing initial firewall sync...")
            
            #  ENHANCED: Get all current whitelisted IPs
            whitelisted_ips = self.get_all_whitelisted_ips()
            
            if not whitelisted_ips:
                logger.warning("No whitelisted IPs found for firewall sync")
                return
            
            #  ENHANCED: Setup whitelist-only firewall
            success = self.firewall_manager.setup_whitelist_firewall(whitelisted_ips)
            
            if success:
                self.stats["firewall_sync_count"] += 1
                logger.info(f" Initial firewall sync completed: {len(whitelisted_ips)} IPs")
            else:
                logger.error("❌ Initial firewall sync failed")
                
        except Exception as e:
            logger.error(f"Error in initial firewall sync: {e}")

    def _sync_with_firewall(self, old_domains: set, new_domains: set):
        """Enhanced firewall sync for runtime changes"""
        try:
            if not self.firewall_manager or not self.auto_sync_firewall:
                return
            
            #  ENHANCED: Calculate IP changes instead of domain changes
            old_ips = self.previous_resolved_ips
            
            #  ENHANCED: Resolve new domains to get current IPs
            if old_domains != new_domains:
                logger.info("🔄 Domain changes detected, resolving IPs...")
                self._resolve_all_domain_ips(force_refresh=True)
            
            new_ips = self.current_resolved_ips
            
            #  ENHANCED: Sync IP changes with firewall
            if old_ips != new_ips:
                logger.info(f"🔄 IP changes detected: {len(old_ips)} -> {len(new_ips)}")
                success = self.firewall_manager.sync_whitelist_changes(old_ips, new_ips)
                
                if success:
                    self.stats["firewall_sync_count"] += 1
                    logger.info(" Runtime firewall sync completed")
                else:
                    logger.warning("❌ Runtime firewall sync had errors")
            else:
                logger.debug("No IP changes detected, skipping firewall sync")
            
        except Exception as e:
            logger.error(f"Error syncing with firewall: {e}")

    # ========================================
    # SERVER COMMUNICATION
    # ========================================

    def update_whitelist_from_server(self, force_full_sync: bool = False) -> bool:
        """Enhanced whitelist update from server với better completion tracking"""
        if self.sync_in_progress:
            logger.debug("Sync already in progress, skipping")
            return False
        
        self.sync_in_progress = True
        start_time = now()
        
        try:
            #  FIX: Always do full sync if forced OR if we have no domains yet
            should_do_full_sync = (
                force_full_sync or 
                not self.startup_sync_completed or 
                len(self.domains) == 0 or
                self.last_updated is None
            )
            
            params = {}
            if not should_do_full_sync and self.last_updated:
                params['since'] = now_server_compatible(self.last_updated)
                logger.info(f"📡 Incremental sync from server since {now_server_compatible(self.last_updated)}")
            else:
                logger.info(f"📡 Full sync from server (force: {force_full_sync}, no domains: {len(self.domains) == 0})")

            logger.info(f"📡 Syncing whitelist from server: {self.server_url}")
            
            response = requests.get(
                self.server_url,
                params=params,
                timeout=(self.connect_timeout, self.read_timeout),
                headers={'User-Agent': 'FirewallController-Agent/1.0'}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('success', True):
                    domains_data = data.get('domains', [])
                    
                    #  FIX: Always validate response format
                    if not isinstance(domains_data, list):
                        logger.error(f"Invalid domains format: {type(domains_data)}")
                        return False
                    
                    logger.info(f"📥 Received {len(domains_data)} domains from server")
                    
                    #  FIX: Handle both full and incremental sync properly
                    old_domains = self.domains.copy()
                    
                    if should_do_full_sync:
                        # Full sync - replace all domains
                        logger.info("🔄 Full sync: replacing all domains")
                        self.domains.clear()
                    
                    #  FIX: Process each domain properly
                    new_domains_added = 0
                    for domain_data in domains_data:
                        try:
                            if isinstance(domain_data, dict):
                                domain_value = domain_data.get('value', '').strip().lower()
                            elif isinstance(domain_data, str):
                                domain_value = domain_data.strip().lower()
                            else:
                                logger.warning(f"Invalid domain data format: {domain_data}")
                                continue
                        
                            if domain_value and domain_value not in self.domains:
                                self.domains.add(domain_value)
                                new_domains_added += 1
                                logger.debug(f"➕ Added domain: {domain_value}")
                        
                        except Exception as e:
                            logger.warning(f"Error processing domain: {domain_data}, error: {e}")
                
                #  FIX: Update timestamps and state
                self.last_updated = now()
                self.stats["sync_count"] += 1
                self.stats["last_sync_time"] = self.last_updated
                self.stats["last_sync_duration"] = now() - start_time
                
                #  FIX: Mark startup sync as completed on any successful sync
                if not self.startup_sync_completed:
                    self.startup_sync_completed = True
                    logger.info(" Startup sync marked as completed")
                
                #  FIX: Log comprehensive results
                logger.info(f" Sync completed: {len(self.domains)} total domains")
                logger.info(f"   - New domains added: {new_domains_added}")
                logger.info(f"   - Sync type: {'full' if should_do_full_sync else 'incremental'}")
                logger.info(f"   - Duration: {now() - start_time:.2f}s")
                
                #  FIX: Save state immediately after successful sync
                self._save_whitelist_state()
                
                #  FIX: Sync with firewall if domains changed
                if old_domains != self.domains:
                    logger.info(f"🔄 Domain changes detected: {len(old_domains)} -> {len(self.domains)}")
                    self._sync_with_firewall(old_domains, self.domains)
                else:
                    logger.debug("No domain changes detected")
                
                return True
                
            else:
                error_msg = data.get('error', 'Unknown server error')
                logger.error(f"Server returned error: {error_msg}")
                return False
        except Exception as e:
            logger.error(f"Error updating whitelist: {e}")
            self.stats["sync_errors"] += 1
            return False
        finally:
            self.sync_in_progress = False

    # ========================================
    # STATE MANAGEMENT
    # ========================================

    def _save_whitelist_state(self):
        """Enhanced save whitelist state to file với proper JSON serialization"""
        state_file = "whitelist_state.json"
        try:
            #  FIX: Convert timestamp to readable string for JSON
            state = {
                "domains": list(self.domains),
                "last_updated": now_server_compatible(self.last_updated) if self.last_updated else None,
                "domain_count": len(self.domains),
                "current_resolved_ips": list(self.current_resolved_ips),
                "saved_at": now_server_compatible(),
                "version": "2.0"
            }
            
            #  FIX: Convert stats with timestamp objects to strings
            serializable_stats = {}
            for key, value in self.stats.items():
                if key == "last_sync_time" and value:
                    serializable_stats[key] = now_server_compatible(value)
                else:
                    serializable_stats[key] = value
            
            state["stats"] = serializable_stats
            
            with open(state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"💾 Saved whitelist state: {len(self.domains)} domains")
            
        except Exception as e:
            logger.error(f"Error saving whitelist state: {e}")

    def _load_whitelist_state(self):
        """Enhanced load whitelist state from file với better error handling"""
        state_file = "whitelist_state.json"
        try:
            if os.path.exists(state_file):
                with open(state_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    
                    if not content:
                        logger.warning("Whitelist state file is empty, starting fresh")
                        return
                    
                    try:
                        state = json.loads(content)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON in whitelist state file: {e}")
                        import shutil
                        backup_file = f"{state_file}.backup.{int(now())}"
                        shutil.move(state_file, backup_file)
                        logger.info(f"Corrupted state file backed up to {backup_file}")
                        return
            else:
                logger.debug("Whitelist state file not found, starting fresh")
                return
            
            # Load domains
            domains_data = state.get("domains", [])
            if isinstance(domains_data, list):
                self.domains = set(domain for domain in domains_data if isinstance(domain, str))
            else:
                logger.warning("Invalid domains format in state file")
                self.domains = set()
            
            # Load last_updated - try to parse as readable string first
            if state.get("last_updated"):
                try:
                    # For backward compatibility, try to parse as timestamp
                    last_updated_str = state["last_updated"]
                    if isinstance(last_updated_str, str):
                        # This is a readable string, we can't easily convert back to timestamp
                        # So we'll use current time minus a reasonable interval
                        self.last_updated = now() - 300  # 5 minutes ago
                    else:
                        self.last_updated = float(last_updated_str)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Invalid last_updated format: {e}")
                    self.last_updated = None
        
            # Load resolved IPs
            if state.get("current_resolved_ips"):
                resolved_ips_data = state["current_resolved_ips"]
                if isinstance(resolved_ips_data, list):
                    self.current_resolved_ips = set(ip for ip in resolved_ips_data if isinstance(ip, str))
            
            # Load stats
            if "stats" in state and isinstance(state["stats"], dict):
                for key, value in state["stats"].items():
                    if key == "last_sync_time" and isinstance(value, str):
                        # Skip parsing readable time strings
                        self.stats[key] = None
                    else:
                        self.stats[key] = value
            
            logger.info(f"📂 Loaded whitelist state: {len(self.domains)} domains")
            
        except Exception as e:
            logger.warning(f"Could not load whitelist state: {e}")
            self.domains = set()
            self.last_updated = None
            self.current_resolved_ips = set()

    def _save_ip_cache(self):
        """Enhanced save IP cache to file với JSON serialization fix"""
        cache_file = "ip_cache.json"
        try:
            #  FIX: Convert all timestamps to readable strings
            timestamp_data = {}
            for domain, timestamp in self.ip_cache_timestamps.items():
                timestamp_data[domain] = now_server_compatible(timestamp)
            
            #  FIX: Ensure cache data is JSON serializable
            serializable_cache = {}
            for domain, ip_data in self.ip_cache.items():
                if isinstance(ip_data, dict):
                    serializable_cache[domain] = {
                        "ipv4": list(ip_data.get("ipv4", [])),
                        "ipv6": list(ip_data.get("ipv6", []))
                    }
            
            cache_data = {
                "cache": serializable_cache,
                "timestamps": timestamp_data,
                "cache_ttl": self.ip_cache_ttl,
                "stats": {
                    "cache_hits": self.stats.get("cache_hit_count", 0),
                    "cache_misses": self.stats.get("cache_miss_count", 0)
                },
                "saved_at": now_server_compatible(),
                "version": "2.0"
            }
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"💾 Saved IP cache: {len(self.ip_cache)} entries")
            
        except Exception as e:
            logger.error(f"Error saving IP cache: {e}")

    def _load_ip_cache(self):
        """Enhanced load IP cache from file với better error handling"""
        cache_file = "ip_cache.json"
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    
                    #  FIX: Check for empty file
                    if not content:
                        logger.debug("IP cache file is empty, starting fresh")
                        return
                    
                    try:
                        cache_data = json.loads(content)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON in IP cache file: {e}")
                        #  FIX: Backup corrupted file
                        import shutil
                        backup_file = f"{cache_file}.backup.{int(now())}"
                        shutil.move(cache_file, backup_file)
                        logger.info(f"Corrupted cache file backed up to {backup_file}")
                        return
            else:
                logger.debug("IP cache file not found, starting fresh")
                return
                
            #  FIX: Load cache with validation
            cache_raw = cache_data.get("cache", {})
            if isinstance(cache_raw, dict):
                self.ip_cache = {}
                for domain, ip_data in cache_raw.items():
                    if isinstance(ip_data, dict):
                        self.ip_cache[domain] = {
                            "ipv4": list(ip_data.get("ipv4", [])),
                            "ipv6": list(ip_data.get("ipv6", []))
                        }
            
            #  FIX: Parse timestamps - since we saved as readable strings, we'll use current time
            timestamp_data = cache_data.get("timestamps", {})
            if isinstance(timestamp_data, dict):
                self.ip_cache_timestamps = {}
                for domain, timestamp_str in timestamp_data.items():
                    # Since we can't easily parse readable strings back to timestamps,
                    # we'll set them to current time minus cache TTL to make them expire
                    self.ip_cache_timestamps[domain] = now() - self.ip_cache_ttl - 1
            
            #  FIX: Clean expired entries on load
            self._clean_expired_cache()
            
            logger.debug(f"📂 Loaded IP cache: {len(self.ip_cache)} entries")
            
        except Exception as e:
            logger.warning(f"Could not load IP cache: {e}")
            self.ip_cache = {}
            self.ip_cache_timestamps = {}

    # ========================================
    # PERIODIC UPDATES
    # ========================================

    def start_periodic_updates(self):
        """Start background threads for periodic updates"""
        if self._running:
            logger.warning("Periodic updates already running")
            return
        
        self._running = True
        self._stop_event.clear()
        
        #  ENHANCED: Start whitelist update thread
        self._update_thread = threading.Thread(target=self._update_loop, daemon=True)
        self._update_thread.start()
        
        #  ENHANCED: Start IP refresh thread
        self._ip_refresh_thread = threading.Thread(target=self._ip_refresh_loop, daemon=True)
        self._ip_refresh_thread.start()
        
        logger.info("🔄 Periodic update threads started")

    def _update_loop(self):
        """Main update loop for periodic whitelist syncing"""
        consecutive_failures = 0
        
        while not self._stop_event.is_set():
            try:
                #  FIX: Force full sync periodically để ensure fresh data
                force_full = consecutive_failures > 2  # Force full sync after multiple failures
                
                if self.update_whitelist_from_server(force_full_sync=force_full):
                    if consecutive_failures > 0:
                        logger.info(f" Sync recovered after {consecutive_failures} failures")
                    consecutive_failures = 0
                    
                    #  FIX: Force IP resolution after successful sync
                    if len(self.domains) > 0:
                        logger.debug("🔄 Refreshing IP resolution after sync")
                        self._resolve_all_domain_ips(force_refresh=True)
                        
                else:
                    consecutive_failures += 1
                    logger.warning(f"❌ Sync failed (attempt {consecutive_failures}/{self.max_retries})")
            
                #  FIX: Adaptive retry interval
                sleep_interval = self.update_interval
                if consecutive_failures > 0:
                    sleep_interval = min(self.retry_interval * consecutive_failures, 300)  # Max 5 minutes
                    logger.info(f"⏳ Will retry in {sleep_interval}s due to failures")
            
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
                    
                    #  ENHANCED: Refresh IP resolution
                    self._resolve_all_domain_ips(force_refresh=True)
                    
                    #  ENHANCED: Check for changes and sync firewall if needed
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
        
        #  ENHANCED: Wait for threads to finish
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=5)
        
        if self._ip_refresh_thread and self._ip_refresh_thread.is_alive():
            self._ip_refresh_thread.join(timeout=5)
        
        #  ENHANCED: Save state before stopping
        self._save_whitelist_state()
        self._save_ip_cache()
        
        logger.info(" Periodic updates stopped and state saved")

    # ========================================
    # STATUS & MONITORING
    # ========================================

    def get_status(self) -> Dict:
        """Get comprehensive status information"""
        return {
            "domains_count": len(self.domains),
            "resolved_ips_count": len(self.current_resolved_ips),
            "cache_entries": len(self.ip_cache),
            "last_updated": now_server_compatible(self.last_updated) if self.last_updated else None,
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
            "current_time": now_server_compatible()
        }

    def get_domain_details(self, domain: str = None) -> Dict:
        """Get detailed information about domains and their IPs"""
        if domain:
            #  ENHANCED: Single domain details
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
                "cache_time": now_server_compatible(cache_time) if cache_time else None,
                "cache_age_seconds": (now() - cache_time) if cache_time else None
            }
        else:
            #  ENHANCED: All domains summary
            return {
                "total_domains": len(self.domains),
                "total_resolved_ips": len(self.current_resolved_ips),
                "cached_domains": len(self.ip_cache),
                "cache_hit_rate": f"{self.stats['cache_hit_count'] / max(self.stats['cache_hit_count'] + self.stats['cache_miss_count'], 1) * 100:.1f}%",
                "sample_domains": list(self.domains)[:10] if self.domains else []
            }

    def force_refresh(self) -> bool:
        """Force complete refresh from server"""
        logger.info("🔄 Forcing complete refresh...")
        
        try:
            #  FIX: Force full sync without 'since' parameter
            sync_success = self.update_whitelist_from_server(force_full_sync=True)
            
            if sync_success and len(self.domains) > 0:
                ip_success = self._resolve_all_domain_ips(force_refresh=True)
                
                if ip_success:
                    logger.info(" Force refresh completed: full")
                    return True
                else:
                    logger.warning("⚠️ Force refresh completed: partial (domains only)")
                    return False
            else:
                logger.error("❌ Force refresh failed")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error in force refresh: {e}")
            return False
