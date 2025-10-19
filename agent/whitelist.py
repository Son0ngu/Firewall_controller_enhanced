"""
Enhanced Whitelist Manager for Firewall Controller Agent
UTC ONLY - Clean, optimized implementation with dnspython and aiodns

Key improvements:
- LRU Cache with minimal lock contention
- Parallel DNS resolution with dnspython
- Immutable cache values
- High-performance async DNS lookups
- Fixed threading and lock issues
"""

import json
import os
import socket
import threading
import requests
import ipaddress
import asyncio
import concurrent.futures
import atexit
from collections import OrderedDict, namedtuple
from typing import Dict, Set, Optional, List, Tuple
from datetime import datetime, timezone
from urllib.parse import urlparse

# Time utilities - UTC ONLY
from time_utils import now, now_iso, sleep, is_cache_valid, cache_age

# High-performance DNS libraries (cleaned imports)
import dns.resolver
import aiodns

import logging
logger = logging.getLogger("whitelist")

# Immutable DNS record structures
DNSRecord = namedtuple('DNSRecord', ['ipv4', 'ipv6', 'cname', 'ttl', 'resolved_at'])
CacheValue = namedtuple('CacheValue', ['data', 'timestamp', 'ttl'])

class HighPerformanceLRUCache:
    """High-performance LRU cache with minimal lock contention"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        
        # Use OrderedDict for O(1) LRU operations
        self._cache: OrderedDict[str, CacheValue] = OrderedDict()
        self._lock = threading.RLock()
        
        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expired_cleanups': 0
        }
    
    def get(self, key: str, force_refresh: bool = False) -> Optional[DNSRecord]:
        """Get cache entry with minimal lock contention"""
        if force_refresh:
            self._stats['misses'] += 1
            return None
        
        # Fast path: check existence without lock first
        if key not in self._cache:
            self._stats['misses'] += 1
            return None
        
        # Critical section: minimal lock scope
        with self._lock:
            if key not in self._cache:  # Double-check
                self._stats['misses'] += 1
                return None
            
            cache_value = self._cache[key]
            self._cache.move_to_end(key)  # Mark as recently used
        
        # TTL validation outside lock
        if not is_cache_valid(cache_value.timestamp, cache_value.ttl):
            with self._lock:
                self._cache.pop(key, None)
            
            self._stats['misses'] += 1
            self._stats['expired_cleanups'] += 1
            return None
        
        self._stats['hits'] += 1
        return cache_value.data
    
    def set(self, key: str, value: DNSRecord, ttl: Optional[int] = None) -> bool:
        """Set cache entry with automatic LRU eviction"""
        if ttl is None:
            ttl = self.default_ttl
        
        cache_value = CacheValue(
            data=value,
            timestamp=now(),
            ttl=ttl
        )
        
        with self._lock:
            if key in self._cache:
                self._cache[key] = cache_value
                self._cache.move_to_end(key)
            else:
                # Check if eviction needed
                if len(self._cache) >= self.max_size:
                    oldest_key = next(iter(self._cache))
                    self._cache.pop(oldest_key)
                    self._stats['evictions'] += 1
                
                self._cache[key] = cache_value
        
        return True
    
    def bulk_cleanup_expired(self) -> int:
        """Bulk cleanup of expired entries"""
        expired_keys = []
        
        with self._lock:
            for key, cache_value in list(self._cache.items()):
                if not is_cache_valid(cache_value.timestamp, cache_value.ttl):
                    expired_keys.append(key)
        
        if expired_keys:
            with self._lock:
                for key in expired_keys:
                    self._cache.pop(key, None)
            
            self._stats['expired_cleanups'] += len(expired_keys)
            logger.debug(f"🧹 Bulk cleaned {len(expired_keys)} expired cache entries")
        
        return len(expired_keys)
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            cache_size = len(self._cache)
        
        total_requests = self._stats['hits'] + self._stats['misses']
        hit_rate = (self._stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self._stats,
            'total_requests': total_requests,
            'hit_rate': hit_rate,
            'cache_size': cache_size,
            'max_size': self.max_size,
            'default_ttl': self.default_ttl,
            'memory_efficiency': (cache_size / self.max_size * 100) if self.max_size > 0 else 0
        }
    
    def clear(self):
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
        logger.debug("🧹 LRU Cache cleared")


class OptimizedDNSResolver:
    """High-performance DNS resolver with dnspython and aiodns"""
    
    def __init__(self, max_workers: int = 20, timeout: float = 5.0):
        self.max_workers = max_workers
        self.timeout = timeout
        self._shutdown = False
        
        # Configure dnspython resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        # Use fast DNS servers
        self.resolver.nameservers = [
            '1.1.1.1',  # Cloudflare
            '8.8.8.8',  # Google
            '1.0.0.1',  # Cloudflare
            '8.8.4.4',  # Google
        ]
        
        # Thread pool for parallel resolution
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix='DNSResolver'
        )
        
        # Async DNS resolver
        self.aiodns_resolver = aiodns.DNSResolver()
        self.aiodns_resolver.timeout = timeout
        
        # Register cleanup on exit
        atexit.register(self.shutdown)
    
    def resolve_domain_sync(self, domain: str) -> DNSRecord:
        """Synchronous DNS resolution with dnspython"""
        if self._shutdown:
            return self._fallback_resolve(domain)
            
        ipv4_ips = []
        ipv6_ips = []
        cname = None
        min_ttl = 300
        
        try:
            # Resolve A records (IPv4)
            try:
                answers = self.resolver.resolve(domain, 'A')
                ipv4_ips = [str(rdata) for rdata in answers]
                min_ttl = min(min_ttl, answers.ttl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            
            # Resolve AAAA records (IPv6)
            try:
                answers = self.resolver.resolve(domain, 'AAAA')
                ipv6_ips = [str(rdata) for rdata in answers]
                min_ttl = min(min_ttl, answers.ttl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            
            # Resolve CNAME if no direct records
            if not ipv4_ips and not ipv6_ips:
                try:
                    answers = self.resolver.resolve(domain, 'CNAME')
                    if answers:
                        cname = str(answers[0])
                        # Recursively resolve CNAME target
                        cname_record = self.resolve_domain_sync(cname)
                        ipv4_ips = list(cname_record.ipv4)
                        ipv6_ips = list(cname_record.ipv6)
                        min_ttl = min(min_ttl, answers.ttl, cname_record.ttl)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass
        
        except Exception as e:
            logger.debug(f"DNS resolution error for {domain}: {e}")
            return self._fallback_resolve(domain)
        
        return DNSRecord(
            ipv4=tuple(ipv4_ips),
            ipv6=tuple(ipv6_ips),
            cname=cname,
            ttl=min_ttl,
            resolved_at=now()
        )
    
    async def resolve_domain_async(self, domain: str) -> DNSRecord:
        """Asynchronous DNS resolution with aiodns"""
        if self._shutdown:
            return await self._async_fallback_resolve(domain)
            
        ipv4_ips = []
        ipv6_ips = []
        cname = None
        min_ttl = 300
        
        try:
            # Parallel async resolution
            tasks = [
                self._safe_query_async(domain, 'A'),
                self._safe_query_async(domain, 'AAAA'),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process A records
            if not isinstance(results[0], Exception) and results[0]:
                ipv4_ips = [r.host for r in results[0]]
                min_ttl = min(min_ttl, results[0][0].ttl if results[0] else 300)
            
            # Process AAAA records
            if not isinstance(results[1], Exception) and results[1]:
                ipv6_ips = [r.host for r in results[1]]
                min_ttl = min(min_ttl, results[1][0].ttl if results[1] else 300)
            
            # Try CNAME if no direct records
            if not ipv4_ips and not ipv6_ips:
                cname_result = await self._safe_query_async(domain, 'CNAME')
                if not isinstance(cname_result, Exception) and cname_result:
                    cname = cname_result[0].cname
                    # Recursively resolve CNAME
                    cname_record = await self.resolve_domain_async(cname)
                    ipv4_ips = list(cname_record.ipv4)
                    ipv6_ips = list(cname_record.ipv6)
                    min_ttl = min(min_ttl, cname_record.ttl)
        
        except Exception as e:
            logger.debug(f"Async DNS resolution error for {domain}: {e}")
            return await self._async_fallback_resolve(domain)
        
        return DNSRecord(
            ipv4=tuple(ipv4_ips),
            ipv6=tuple(ipv6_ips),
            cname=cname,
            ttl=min_ttl,
            resolved_at=now()
        )
    
    async def _safe_query_async(self, domain: str, record_type: str):
        """Safe async DNS query with timeout"""
        try:
            return await asyncio.wait_for(
                self.aiodns_resolver.query(domain, record_type),
                timeout=self.timeout
            )
        except Exception:
            return None
    
    def resolve_multiple_parallel(self, domains: List[str]) -> Dict[str, DNSRecord]:
        """Resolve multiple domains in parallel using thread pool"""
        if not domains or self._shutdown:
            return {}
        
        logger.info(f" Parallel DNS resolution for {len(domains)} domains")
        start_time = now()
        
        # Submit all tasks to thread pool
        future_to_domain = {
            self.executor.submit(self.resolve_domain_sync, domain): domain
            for domain in domains
        }
        
        results = {}
        completed = 0
        
        # Collect results as they complete
        for future in concurrent.futures.as_completed(future_to_domain, timeout=self.timeout * 2):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results[domain] = result
                completed += 1
                
                if completed % 20 == 0:  # Log progress every 20 domains
                    logger.debug(f"DNS progress: {completed}/{len(domains)} domains resolved")
                    
            except Exception as e:
                logger.warning(f"DNS resolution failed for {domain}: {e}")
                results[domain] = self._fallback_resolve(domain)
        
        duration = now() - start_time
        logger.info(f" Parallel DNS resolution completed in {duration:.2f}s ({len(results)}/{len(domains)} domains)")
        
        return results
    
    async def resolve_multiple_async(self, domains: List[str]) -> Dict[str, DNSRecord]:
        """Resolve multiple domains asynchronously"""
        if not domains or self._shutdown:
            return {}
        
        logger.info(f" Async DNS resolution for {len(domains)} domains")
        start_time = now()
        
        # Create async tasks for all domains
        tasks = [self.resolve_domain_async(domain) for domain in domains]
        
        # Execute all tasks concurrently
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        results = {}
        for domain, result in zip(domains, results_list):
            if isinstance(result, Exception):
                logger.warning(f"Async DNS resolution failed for {domain}: {result}")
                results[domain] = self._fallback_resolve(domain)
            else:
                results[domain] = result
        
        duration = now() - start_time
        logger.info(f" Async DNS resolution completed in {duration:.2f}s ({len(results)}/{len(domains)} domains)")
        
        return results
    
    def _fallback_resolve(self, domain: str) -> DNSRecord:
        """Fallback to standard socket resolution"""
        if self._is_ip_address(domain):
            try:
                ip_obj = ipaddress.ip_address(domain)
                if ip_obj.version == 4:
                    return DNSRecord(ipv4=(domain,), ipv6=(), cname=None, ttl=300, resolved_at=now())
                else:
                    return DNSRecord(ipv4=(), ipv6=(domain,), cname=None, ttl=300, resolved_at=now())
            except:
                pass
        
        ipv4_ips = []
        ipv6_ips = []
        
        # IPv4 resolution
        try:
            ipv4_results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            ipv4_ips = list(set(res[4][0] for res in ipv4_results))
        except socket.gaierror:
            pass
        
        # IPv6 resolution
        try:
            ipv6_results = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            ipv6_ips = list(set(res[4][0] for res in ipv6_results))
        except socket.gaierror:
            pass
        
        return DNSRecord(
            ipv4=tuple(sorted(ipv4_ips)),
            ipv6=tuple(sorted(ipv6_ips)),
            cname=None,
            ttl=300,
            resolved_at=now()
        )
    
    async def _async_fallback_resolve(self, domain: str) -> DNSRecord:
        """Async fallback resolution"""
        if self._shutdown:
            return self._fallback_resolve(domain)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._fallback_resolve, domain)
    
    def _is_ip_address(self, address: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def shutdown(self):
        """Shutdown the thread pool"""
        if self._shutdown:
            return
            
        self._shutdown = True
        self.executor.shutdown(wait=True)
        logger.debug("DNS resolver thread pool shutdown")


class SyncMonitor:
    """Monitor sync operations for health tracking"""
    
    def __init__(self, max_history: int = 50):
        self.sync_history: List[Dict] = []
        self.max_history = max_history
        self._lock = threading.Lock()
    
    def record_sync(self, sync_type: str, success: bool, domains_count: int, 
                   duration: float, error: str = None, details: Dict = None):
        """Record a sync operation"""
        with self._lock:
            sync_record = {
                "timestamp": now_iso(),
                "type": sync_type,
                "success": success,
                "domains_count": domains_count,
                "duration": duration,
                "error": error,
                "details": details or {}
            }
            
            self.sync_history.append(sync_record)
            if len(self.sync_history) > self.max_history:
                self.sync_history.pop(0)
    
    def get_sync_health(self) -> Dict:
        """Get sync health status"""
        with self._lock:
            if not self.sync_history:
                return {
                    "status": "no_data",
                    "message": "No sync history available",
                    "success_rate": 0,
                    "total_syncs": 0
                }
            
            recent_syncs = self.sync_history[-10:]
            success_count = sum(1 for s in recent_syncs if s["success"])
            success_rate = success_count / len(recent_syncs) * 100
            
            if success_rate >= 80:
                status = "healthy"
            elif success_rate >= 50:
                status = "degraded"
            else:
                status = "unhealthy"
            
            return {
                "status": status,
                "success_rate": success_rate,
                "total_syncs": len(self.sync_history),
                "recent_syncs": len(recent_syncs),
                "last_sync": self.sync_history[-1] if self.sync_history else None,
                "avg_duration": sum(s["duration"] for s in recent_syncs) / len(recent_syncs),
                "error_rate": (len(recent_syncs) - success_count) / len(recent_syncs) * 100
            }
    
    def get_recent_errors(self, limit: int = 5) -> List[Dict]:
        """Get recent sync errors"""
        with self._lock:
            errors = [s for s in self.sync_history if not s["success"] and s["error"]]
            return errors[-limit:]


class WhitelistManager:
    """Enhanced Whitelist Manager with high-performance caching and DNS resolution"""
    
    def __init__(self, config: Dict):
        """Initialize whitelist manager with optimized configuration"""
        
        # Configuration loading
        whitelist_config = config.get("whitelist", {})
        server_config = config.get("server", {})
        
        # Basic settings
        self.update_interval = max(whitelist_config.get("update_interval", 300), 30)
        self.retry_interval = max(whitelist_config.get("retry_interval", 60), 10)
        self.max_retries = whitelist_config.get("max_retries", 3)
        self.timeout = whitelist_config.get("timeout", 30)
        
        # Server configuration with fallback support
        server_urls = server_config.get("urls", [])
        if not server_urls:
            primary_url = server_config.get("url", "https://firewall-controller.onrender.com")
            server_urls = [primary_url]
        
        self.server_urls = server_urls
        self.current_server_index = 0
        self.server_url = self._build_sync_url(server_urls[0])
        
        # Connection settings
        self.connect_timeout = server_config.get("connect_timeout", 10)
        self.read_timeout = server_config.get("read_timeout", 30)
        
        # Feature flags
        self.auto_sync_enabled = whitelist_config.get("auto_sync", True)
        self.sync_on_startup = whitelist_config.get("sync_on_startup", True)
        self.auto_sync_firewall = whitelist_config.get("auto_sync_firewall", True)
        self.resolve_ips_on_startup = whitelist_config.get("resolve_ips_on_startup", True)
        
        # High-performance cache and DNS
        cache_ttl = whitelist_config.get("ip_cache_ttl", 300)
        max_cache_entries = whitelist_config.get("max_cache_entries", 2000)
        dns_workers = whitelist_config.get("dns_workers", 20)
        dns_timeout = whitelist_config.get("dns_timeout", 5.0)
        
        # Initialize components
        self.cache_manager = HighPerformanceLRUCache(
            max_size=max_cache_entries,
            default_ttl=cache_ttl
        )
        
        self.dns_resolver = OptimizedDNSResolver(
            max_workers=dns_workers,
            timeout=dns_timeout
        )
        
        self.ip_refresh_interval = whitelist_config.get("ip_refresh_interval", 600)
        self._cache_cleanup_interval = 300
        self._last_cache_cleanup = now()
        
        # State management
        self.domains: Set[str] = set()
        self.current_resolved_ips: Set[str] = set()
        self.previous_resolved_ips: Set[str] = set()
        
        # Timestamps - all UTC
        self.last_updated: Optional[float] = None
        self.last_successful_sync: Optional[float] = None
        self.startup_sync_completed = False
        
        # Threading and synchronization - Fixed lock management
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None
        self._ip_refresh_thread: Optional[threading.Thread] = None
        self._cache_cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        self.sync_in_progress = threading.Lock()
        
        # Thread-safe statistics with lock
        self._stats_lock = threading.Lock()
        self.stats = {
            "sync_count": 0,
            "sync_errors": 0,
            "ip_resolution_count": 0,
            "ip_resolution_errors": 0,
            "firewall_sync_count": 0,
            "last_sync_time": None,
            "last_sync_duration": 0,
            "total_domains_processed": 0,
            "parallel_dns_calls": 0,
            "async_dns_calls": 0,
            "cache_stats": {}
        }
        
        # External components
        self.firewall_manager = None
        
        # Monitoring and statistics
        self.sync_monitor = SyncMonitor()
        
        # Register cleanup on exit
        atexit.register(self.stop_periodic_updates)
        
        # Initialization
        logger.info(" Initializing High-Performance WhitelistManager...")
        
        # Load persisted state
        self._load_state()
        
        # Perform startup sync if enabled
        if self.sync_on_startup:
            startup_success = self._perform_startup_sync()
            if startup_success and self.resolve_ips_on_startup and self.domains:
                self._resolve_all_ips_parallel(force_refresh=True)
        
        # Start background threads
        if self.auto_sync_enabled:
            self.start_periodic_updates()
        
        logger.info(f" High-Performance WhitelistManager initialized: {len(self.domains)} domains")
    
    def _build_sync_url(self, base_url: str) -> str:
        """Build sync endpoint URL"""
        base_url = base_url.rstrip('/')
        return f"{base_url}/api/whitelist/agent-sync"
    
    def _perform_startup_sync(self) -> bool:
        """Perform initial startup sync"""
        logger.info(" Performing startup sync...")
        
        success = self.update_whitelist_from_server(force_full_sync=True)
        if success:
            self.startup_sync_completed = True
            logger.info(f" Startup sync completed: {len(self.domains)} domains")
            return True
        else:
            logger.error(" Startup sync failed - will retry in background")
            return False
    
    def _update_stats(self, **kwargs):
        """Thread-safe stats update"""
        with self._stats_lock:
            self.stats.update(kwargs)
    
    def _increment_stat(self, key: str, amount: int = 1):
        """Thread-safe stats increment"""
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + amount
    
    # Core whitelist methods
    def is_allowed(self, domain: str) -> bool:
        """Check if domain is whitelisted"""
        if not domain:
            return False
        
        domain = domain.lower().strip()
        
        # Direct match
        if domain in self.domains:
            return True
        
        # Wildcard matching
        for whitelist_domain in self.domains:
            if whitelist_domain.startswith("*."):
                base_domain = whitelist_domain[2:]
                if domain == base_domain or domain.endswith("." + base_domain):
                    return True
        
        return False
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        if not ip:
            return False
        
        try:
            # Direct IP check in domains
            if ip in self.domains:
                return True
            
            # Check resolved IPs
            if ip in self.current_resolved_ips:
                return True
            
            # Check essential IPs
            if self._is_essential_ip(ip):
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking IP {ip}: {e}")
            return False
    
    def _is_essential_ip(self, ip: str) -> bool:
        """Check if IP is essential (DNS, localhost, etc.)"""
        essential_ips = {
            "127.0.0.1", "::1", "0.0.0.0",
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "208.67.222.222", "208.67.220.220",
            "9.9.9.9", "149.112.112.112"
        }
        
        if ip in essential_ips:
            return True
        
        # Check private networks
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False
    
    # High-performance IP resolution
    def _resolve_all_ips_parallel(self, force_refresh: bool = False) -> bool:
        """High-performance parallel IP resolution"""
        if not self.domains:
            logger.warning("No domains to resolve")
            return False
        
        # Periodic cache cleanup
        self._maybe_cleanup_cache()
        
        # Separate domains that need resolution
        domains_to_resolve = []
        cached_results = {}
        
        for domain in self.domains:
            clean_domain = domain.replace("*.", "")
            
            if force_refresh:
                domains_to_resolve.append(clean_domain)
            else:
                cached_record = self.cache_manager.get(clean_domain)
                if cached_record:
                    cached_results[clean_domain] = cached_record
                else:
                    domains_to_resolve.append(clean_domain)
        
        logger.info(f" IP Resolution: {len(cached_results)} cached, {len(domains_to_resolve)} to resolve")
        
        # Parallel resolution of uncached domains
        resolved_results = {}
        if domains_to_resolve:
            self._increment_stat("parallel_dns_calls")
            resolved_results = self.dns_resolver.resolve_multiple_parallel(domains_to_resolve)
            
            # Cache new results
            for domain, dns_record in resolved_results.items():
                if dns_record and (dns_record.ipv4 or dns_record.ipv6):
                    self.cache_manager.set(domain, dns_record, dns_record.ttl)
        
        # Combine cached and resolved results
        all_results = {**cached_results, **resolved_results}
        
        # Extract all IPs
        total_ips = set()
        success_count = 0
        
        for domain, dns_record in all_results.items():
            if dns_record and (dns_record.ipv4 or dns_record.ipv6):
                total_ips.update(dns_record.ipv4)
                total_ips.update(dns_record.ipv6)
                success_count += 1
        
        # Update tracking
        self.previous_resolved_ips = self.current_resolved_ips.copy()
        self.current_resolved_ips = total_ips
        
        # Thread-safe stats update
        self._increment_stat("ip_resolution_count", success_count)
        self._increment_stat("ip_resolution_errors", len(self.domains) - success_count)
        
        logger.info(f" Parallel IP resolution completed: {success_count}/{len(self.domains)} domains, {len(total_ips)} IPs")
        
        return len(total_ips) > 0
    
    async def _resolve_all_ips_async(self, force_refresh: bool = False) -> bool:
        """Async IP resolution using aiodns"""
        if not self.domains:
            logger.warning("No domains to resolve")
            return False
        
        self._maybe_cleanup_cache()
        
        domains_to_resolve = []
        cached_results = {}
        
        for domain in self.domains:
            clean_domain = domain.replace("*.", "")
            
            if force_refresh:
                domains_to_resolve.append(clean_domain)
            else:
                cached_record = self.cache_manager.get(clean_domain)
                if cached_record:
                    cached_results[clean_domain] = cached_record
                else:
                    domains_to_resolve.append(clean_domain)
        
        logger.info(f" Async IP Resolution: {len(cached_results)} cached, {len(domains_to_resolve)} to resolve")
        
        resolved_results = {}
        if domains_to_resolve:
            self._increment_stat("async_dns_calls")
            resolved_results = await self.dns_resolver.resolve_multiple_async(domains_to_resolve)
            
            for domain, dns_record in resolved_results.items():
                if dns_record and (dns_record.ipv4 or dns_record.ipv6):
                    self.cache_manager.set(domain, dns_record, dns_record.ttl)
        
        all_results = {**cached_results, **resolved_results}
        
        total_ips = set()
        success_count = 0
        
        for domain, dns_record in all_results.items():
            if dns_record and (dns_record.ipv4 or dns_record.ipv6):
                total_ips.update(dns_record.ipv4)
                total_ips.update(dns_record.ipv6)
                success_count += 1
        
        self.previous_resolved_ips = self.current_resolved_ips.copy()
        self.current_resolved_ips = total_ips
        
        # Thread-safe stats update
        self._increment_stat("ip_resolution_count", success_count)
        self._increment_stat("ip_resolution_errors", len(self.domains) - success_count)
        
        logger.info(f" Async IP resolution completed: {success_count}/{len(self.domains)} domains, {len(total_ips)} IPs")
        
        return len(total_ips) > 0
    
    def _maybe_cleanup_cache(self):
        """Periodic cache cleanup"""
        current_time = now()
        if current_time - self._last_cache_cleanup > self._cache_cleanup_interval:
            self.cache_manager.bulk_cleanup_expired()
            self._last_cache_cleanup = current_time
    
    # Backward compatibility
    def _resolve_all_ips(self, force_refresh: bool = False) -> bool:
        """Wrapper for backward compatibility - uses parallel resolution"""
        return self._resolve_all_ips_parallel(force_refresh)
    
    # ========================================
    # SERVER SYNCHRONIZATION (Fixed lock management)
    # ========================================
    
    def update_whitelist_from_server(self, force_full_sync: bool = False) -> bool:
        """Enhanced server sync with proper lock management"""
        
        # Fixed lock management - acquire first, then check
        acquired = self.sync_in_progress.acquire(blocking=False)
        if not acquired:
            logger.debug("Sync already in progress, skipping")
            return False
        
        sync_id = f"sync_{int(now())}"
        start_time = now()
        
        try:
            logger.info(f" [{sync_id}] Starting whitelist sync")
            
            # Determine sync type
            should_do_full_sync = (
                force_full_sync or
                not self.startup_sync_completed or
                len(self.domains) == 0 or
                self.last_updated is None or
                (now() - (self.last_updated or 0)) > 86400  # Force full sync after 24h
            )
            
            # Build request parameters
            params = {}
            if not should_do_full_sync and self.last_updated:
                params['since'] = self._timestamp_to_iso(self.last_updated)
                logger.info(f" [{sync_id}] Incremental sync since {params['since']}")
            else:
                logger.info(f" [{sync_id}] Full sync (forced={force_full_sync}, startup={not self.startup_sync_completed})")
            
            # Attempt sync with server fallback
            sync_result = self._sync_with_fallback(params)
            
            if not sync_result["success"]:
                raise Exception(sync_result["error"])
            
            # Process sync response
            old_domains = self.domains.copy()
            domains_data = sync_result["data"].get("domains", [])
            
            if not isinstance(domains_data, list):
                raise ValueError(f"Invalid domains format: {type(domains_data)}")
            
            logger.info(f" [{sync_id}] Received {len(domains_data)} domains from server")
            
            #  EXISTING: Logic xử lý domain changes
            new_domains_added = 0
            domains_removed = 0
            
            if should_do_full_sync:
                logger.info(f" [{sync_id}] Full sync: replacing all domains")
                self.domains.clear()
                
                # Process each domain for full sync
                for domain_data in domains_data:
                    try:
                        domain_value = self._extract_domain_value(domain_data)
                        if domain_value:
                            self.domains.add(domain_value)
                            new_domains_added += 1
                            logger.debug(f" [{sync_id}] Added: {domain_value}")
                    except Exception as e:
                        logger.warning(f"Error processing domain {domain_data}: {e}")
            else:
                #  EXISTING: Incremental sync logic
                logger.info(f" [{sync_id}] Incremental sync: comparing with current domains")
                
                # Get all server domains
                server_domains = set()
                for domain_data in domains_data:
                    try:
                        domain_value = self._extract_domain_value(domain_data)
                        if domain_value:
                            server_domains.add(domain_value)
                    except Exception as e:
                        logger.warning(f"Error processing domain {domain_data}: {e}")
                
                # Calculate changes
                domains_to_add = server_domains - self.domains
                domains_to_remove = self.domains - server_domains
                
                # Apply changes
                new_domains_added = len(domains_to_add)
                domains_removed = len(domains_to_remove)
                
                for domain in domains_to_add:
                    self.domains.add(domain)
                    logger.info(f" [{sync_id}] Added: {domain}")
                
                for domain in domains_to_remove:
                    self.domains.discard(domain)
                    logger.info(f"➖ [{sync_id}] Removed: {domain}")
                
                logger.info(f" [{sync_id}] Incremental changes: +{new_domains_added}, -{domains_removed}")
        
            #  FIX: Cập nhật timestamps và trạng thái thành công
            current_timestamp = now()
            self.last_updated = current_timestamp
            self.last_successful_sync = current_timestamp
            
            #  FIX: Cập nhật stats thành công
            duration = current_timestamp - start_time
            self._increment_stat("sync_count")
            self._update_stats(
                last_sync_time=current_timestamp,
                last_sync_duration=duration,
                total_domains_processed=len(self.domains)
            )
            
            #  FIX: Record sync thành công
            self.sync_monitor.record_sync(
                sync_type="full" if should_do_full_sync else "incremental",
                success=True,  # ← QUAN TRỌNG: Mark as success
                domains_count=len(self.domains),
                duration=duration,
                details={
                    "domains_added": new_domains_added,
                    "domains_removed": domains_removed,
                    "total_domains": len(self.domains)
                }
            )
            
            #  FIX: Sync với firewall nếu có thay đổi
            if old_domains != self.domains:
                logger.info(f" Domain changes detected, syncing with firewall...")
                self._sync_with_firewall(old_domains, self.domains)
            
            #  FIX: Save state sau khi sync thành công
            self._save_state()
            
            #  FIX: Log thành công và return True
            logger.info(f" [{sync_id}] Sync completed successfully")
            logger.info(f"   • Total domains: {len(self.domains)}")
            logger.info(f"   • New domains: {new_domains_added}")
            logger.info(f"   • Removed domains: {domains_removed}")
            logger.info(f"   • Duration: {duration:.2f}s")
            logger.info(f"   • Type: {'full' if should_do_full_sync else 'incremental'}")
            
            return True  # ← QUAN TRỌNG: Return success
            
        except Exception as e:
            duration = now() - start_time
            error_msg = str(e)
            
            self._increment_stat("sync_errors")
            
            # Record failed sync
            self.sync_monitor.record_sync(
                sync_type="full" if force_full_sync else "incremental",
                success=False,
                domains_count=len(self.domains),
                duration=duration,
                error=error_msg
            )
            
            logger.error(f" [{sync_id}] Sync failed after {duration:.2f}s: {error_msg}")
            return False
            
        finally:
            # Only release if we actually acquired the lock
            self.sync_in_progress.release()
    
    def _sync_with_fallback(self, params: Dict) -> Dict:
        """Attempt sync with server fallback"""
        last_error = None
        
        # Try current server first
        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    self.server_url,
                    params=params,
                    timeout=(self.connect_timeout, self.read_timeout),
                    headers={'User-Agent': 'FirewallController-Agent/2.1-HighPerf'}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('success', True):
                        return {"success": True, "data": data}
                    else:
                        raise Exception(data.get('error', 'Server returned error'))
                else:
                    raise Exception(f"HTTP {response.status_code}: {response.text}")
                    
            except Exception as e:
                last_error = e
                logger.warning(f"Sync attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    sleep(min(self.retry_interval * (attempt + 1), 300))
        
        # Try fallback servers
        if len(self.server_urls) > 1:
            logger.info("Trying fallback servers...")
            for i, fallback_url in enumerate(self.server_urls[1:], 1):
                try:
                    fallback_sync_url = self._build_sync_url(fallback_url)
                    logger.info(f"Attempting fallback server {i}: {fallback_url}")
                    
                    response = requests.get(
                        fallback_sync_url,
                        params=params,
                        timeout=(self.connect_timeout, self.read_timeout),
                        headers={'User-Agent': 'FirewallController-Agent/2.1-HighPerf'}
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('success', True):
                            # Switch to this server for future requests
                            self.server_url = fallback_sync_url
                            self.current_server_index = i
                            logger.info(f" Switched to fallback server: {fallback_url}")
                            return {"success": True, "data": data}
                    
                except Exception as e:
                    logger.warning(f"Fallback server {i} failed: {e}")
                    last_error = e
        
        return {"success": False, "error": str(last_error)}
    
    def _extract_domain_value(self, domain_data) -> Optional[str]:
        """Extract domain value from server response"""
        if isinstance(domain_data, dict):
            return domain_data.get('value', '').strip().lower()
        elif isinstance(domain_data, str):
            return domain_data.strip().lower()
        else:
            logger.warning(f"Invalid domain data format: {domain_data}")
            return None
    
    def _timestamp_to_iso(self, timestamp: float) -> str:
        """Convert UTC timestamp to ISO string"""
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # ========================================
    # FIREWALL INTEGRATION (optimized calls)
    # ========================================
    
    def set_firewall_manager(self, firewall_manager):
        """Set firewall manager for auto-sync"""
        self.firewall_manager = firewall_manager
        logger.info("🔗 Firewall manager linked")
        
        # Perform initial sync if ready
        if self.startup_sync_completed and self.auto_sync_firewall:
            self._sync_with_firewall_initial()
    
    def _sync_with_firewall_initial(self):
        """Initial firewall sync"""
        try:
            if not self.firewall_manager:
                return
            
            logger.info(" Performing initial firewall sync...")
            
            # Get current whitelisted IPs
            whitelisted_ips = self.get_all_whitelisted_ips()
            
            if not whitelisted_ips:
                logger.warning("No whitelisted IPs for firewall sync")
                return
            
            # Setup whitelist firewall
            success = self.firewall_manager.setup_whitelist_firewall(whitelisted_ips)
            
            if success:
                self._increment_stat("firewall_sync_count")
                logger.info(f" Initial firewall sync completed: {len(whitelisted_ips)} IPs")
            else:
                logger.error(" Initial firewall sync failed")
                
        except Exception as e:
            logger.error(f"Error in initial firewall sync: {e}")
    
    def _sync_with_firewall(self, old_domains: Set[str], new_domains: Set[str]):
        """Sync firewall rules with domain changes"""
        try:
            if not self.firewall_manager or not self.auto_sync_firewall:
                return
            
            # Resolve IPs if domains changed
            if old_domains != new_domains:
                logger.info(" Domain changes detected, resolving IPs...")
                self._resolve_all_ips_parallel(force_refresh=True)
            
            old_ips = self.previous_resolved_ips
            new_ips = self.current_resolved_ips
            
            # Update firewall if IPs changed
            if old_ips != new_ips:
                logger.info(f" IP changes detected: {len(old_ips)} → {len(new_ips)}")
                success = self.firewall_manager.sync_whitelist_changes(old_ips, new_ips)
                
                if success:
                    self._increment_stat("firewall_sync_count")
                    logger.info(" Firewall sync completed")
                else:
                    logger.warning(" Firewall sync had errors")
            else:
                logger.debug("No IP changes, skipping firewall sync")
                
        except Exception as e:
            logger.error(f"Error syncing with firewall: {e}")
    
    def get_all_whitelisted_ips(self, force_refresh: bool = False) -> Set[str]:
        """Get all whitelisted IP addresses"""
        try:
            if force_refresh or not self.current_resolved_ips:
                self._resolve_all_ips_parallel(force_refresh=True)
            
            return self.current_resolved_ips.copy()
            
        except Exception as e:
            logger.error(f"Error getting whitelisted IPs: {e}")
            return set()
    
    # ========================================
    # STATE MANAGEMENT (enhanced with cache stats)
    # ========================================
    
    def _save_state(self):
        """Save current state to file"""
        try:
            # Update cache stats before saving
            with self._stats_lock:
                self.stats["cache_stats"] = self.cache_manager.get_stats()
                state_stats = self.stats.copy()
            
            state = {
                "domains": sorted(list(self.domains)),
                "last_updated": self.last_updated,
                "last_successful_sync": self.last_successful_sync,
                "startup_sync_completed": self.startup_sync_completed,
                "current_resolved_ips": sorted(list(self.current_resolved_ips)),
                "stats": state_stats,
                "server_url": self.server_url,
                "current_server_index": self.current_server_index,
                "saved_at": now_iso(),
                "version": "2.1-HighPerf"
            }
            
            with open("whitelist_state.json", 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=2, ensure_ascii=False)
            
            logger.debug(f" State saved: {len(self.domains)} domains")
            
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def _load_state(self):
        """Load state from file"""
        try:
            if not os.path.exists("whitelist_state.json"):
                logger.debug("No state file found, starting fresh")
                return
            
            with open("whitelist_state.json", 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logger.warning("Empty state file, starting fresh")
                    return
                
                state = json.loads(content)
        
            # Load domains
            domains_data = state.get("domains", [])
            if isinstance(domains_data, list):
                self.domains = set(d for d in domains_data if isinstance(d, str))
        
            # Load timestamps properly
            current_time = now()
        
            if state.get("last_updated"):
                saved_timestamp = state.get("last_updated")
            
                # Only adjust if timestamp is in the future (clock skew)
                if saved_timestamp > current_time:
                    logger.warning(f"Saved timestamp is in future, adjusting")
                    self.last_updated = current_time - 60  # 1 minute ago
                else:
                    # Use actual saved timestamp for proper incremental sync
                    self.last_updated = saved_timestamp
                    logger.debug(f"Loaded last_updated: {self._timestamp_to_iso(self.last_updated)}")
        
            if state.get("last_successful_sync"):
                self.last_successful_sync = state.get("last_successful_sync")
        
            # Load other state
            self.startup_sync_completed = state.get("startup_sync_completed", False)
        
            # Load resolved IPs
            resolved_ips_data = state.get("current_resolved_ips", [])
            if isinstance(resolved_ips_data, list):
                self.current_resolved_ips = set(ip for ip in resolved_ips_data if isinstance(ip, str))
        
            # Load statistics
            if "stats" in state and isinstance(state["stats"], dict):
                with self._stats_lock:
                    self.stats.update(state["stats"])
        
            # Load server configuration
            if state.get("server_url"):
                self.server_url = state["server_url"]
            if state.get("current_server_index") is not None:
                self.current_server_index = state["current_server_index"]
        
            logger.info(f" State loaded: {len(self.domains)} domains, last_updated={self._timestamp_to_iso(self.last_updated) if self.last_updated else 'None'}")
        
        except Exception as e:
            logger.warning(f"Error loading state: {e}")
            # Reset to safe defaults
            self.domains = set()
            self.last_updated = None
            self.current_resolved_ips = set()
            self.startup_sync_completed = False
    
    # ========================================
    # PERIODIC UPDATES (with dedicated cache cleanup thread)
    # ========================================
    
    def start_periodic_updates(self):
        """Start background update threads"""
        if self._running:
            logger.warning("Periodic updates already running")
            return
        
        self._running = True
        self._stop_event.clear()
        
        # Start main sync thread
        self._update_thread = threading.Thread(
            target=self._update_loop,
            name="WhitelistSync",
            daemon=True
        )
        self._update_thread.start()
        
        # Start IP refresh thread
        self._ip_refresh_thread = threading.Thread(
            target=self._ip_refresh_loop,
            name="IPRefresh", 
            daemon=True
        )
        self._ip_refresh_thread.start()
        
        # Start dedicated cache cleanup thread
        self._cache_cleanup_thread = threading.Thread(
            target=self._cache_cleanup_loop,
            name="CacheCleanup",
            daemon=True
        )
        self._cache_cleanup_thread.start()
        
        logger.info(" High-performance periodic update threads started")
    
    def _update_loop(self):
        """Main sync loop with adaptive retry"""
        consecutive_failures = 0
        
        while not self._stop_event.is_set():
            try:
                # Force full sync periodically or after multiple failures
                force_full = consecutive_failures >= 3
                
                success = self.update_whitelist_from_server(force_full_sync=force_full)
                
                if success:
                    if consecutive_failures > 0:
                        logger.info(f"🎉 Sync recovered after {consecutive_failures} failures")
                    consecutive_failures = 0
                    
                    # Refresh IPs after successful sync using parallel resolution
                    if self.domains:
                        self._resolve_all_ips_parallel(force_refresh=False)
                else:
                    consecutive_failures += 1
                    logger.warning(f" Sync failed (attempt {consecutive_failures})")
                
                # Adaptive sleep interval
                if consecutive_failures == 0:
                    sleep_interval = self.update_interval
                else:
                    # Exponential backoff with cap
                    sleep_interval = min(self.retry_interval * (2 ** (consecutive_failures - 1)), 300)
                    logger.info(f"⏳ Will retry in {sleep_interval}s due to failures")
                
                if self._stop_event.wait(sleep_interval):
                    break
                    
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Error in sync loop: {e}")
                if self._stop_event.wait(self.retry_interval):
                    break
        
        logger.debug("Sync loop stopped")
    
    def _ip_refresh_loop(self):
        """Background IP refresh loop with parallel resolution"""
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(self.ip_refresh_interval):
                    break
                
                if self.domains:
                    logger.debug(" Performing periodic parallel IP refresh...")
                    old_ips = self.current_resolved_ips.copy()
                    
                    # Refresh IPs using parallel resolution
                    self._resolve_all_ips_parallel(force_refresh=True)
                    
                    # Check for changes and sync firewall
                    if old_ips != self.current_resolved_ips:
                        logger.info(f"📍 IP changes during refresh: {len(old_ips)} → {len(self.current_resolved_ips)}")
                        if self.firewall_manager and self.auto_sync_firewall:
                            try:
                                self.firewall_manager.sync_whitelist_changes(old_ips, self.current_resolved_ips)
                            except Exception as e:
                                logger.error(f"Error syncing firewall during IP refresh: {e}")
                    else:
                        logger.debug("No IP changes during refresh")
                
            except Exception as e:
                logger.error(f"Error in IP refresh loop: {e}")
                if self._stop_event.wait(60):  # Wait 1 minute on error
                    break
        
        logger.debug("IP refresh loop stopped")
    
    def _cache_cleanup_loop(self):
        """Dedicated cache cleanup loop"""
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(self._cache_cleanup_interval):
                    break
                
                cleaned = self.cache_manager.bulk_cleanup_expired()
                if cleaned > 0:
                    logger.debug(f"🧹 Periodic cache cleanup: {cleaned} expired entries removed")
                
            except Exception as e:
                logger.error(f"Error in cache cleanup loop: {e}")
                if self._stop_event.wait(60):  # Wait 1 minute on error
                    break
        
        logger.debug("Cache cleanup loop stopped")
    
    def stop_periodic_updates(self):
        """Stop all background threads"""
        if not self._running:
            return
        
        logger.info(" Stopping periodic updates...")
        self._stop_event.set()
        self._running = False
        
        # Wait for threads to finish
        threads_to_join = [
            (self._update_thread, "Sync thread"),
            (self._ip_refresh_thread, "IP refresh thread"),
            (self._cache_cleanup_thread, "Cache cleanup thread")
        ]
        
        for thread, name in threads_to_join:
            if thread and thread.is_alive():
                thread.join(timeout=5)
                if thread.is_alive():
                    logger.warning(f"{name} did not shutdown cleanly")
        
        # Shutdown DNS resolver
        self.dns_resolver.shutdown()
        
        # Save final state
        self._save_state()
        
        logger.info(" High-performance periodic updates stopped")
    
    # ========================================
    # MONITORING AND STATUS (enhanced with cache and DNS stats)
    # ========================================
    
    def get_status(self) -> Dict:
        """Get comprehensive status information"""
        cache_stats = self.cache_manager.get_stats()
        sync_health = self.sync_monitor.get_sync_health()
        
        # Thread-safe stats copy
        with self._stats_lock:
            stats_copy = self.stats.copy()
        
        # Check if sync is in progress (non-blocking check)
        sync_in_progress_check = not self.sync_in_progress.acquire(blocking=False)
        if not sync_in_progress_check:
            self.sync_in_progress.release()
        
        return {
            "domains_count": len(self.domains),
            "resolved_ips_count": len(self.current_resolved_ips),
            "last_updated": self._timestamp_to_iso(self.last_updated) if self.last_updated else None,
            "last_successful_sync": self._timestamp_to_iso(self.last_successful_sync) if self.last_successful_sync else None,
            "startup_sync_completed": self.startup_sync_completed,
            "auto_sync_enabled": self.auto_sync_enabled,
            "sync_in_progress": sync_in_progress_check,
            "firewall_linked": self.firewall_manager is not None,
            "current_server": self.server_url,
            "server_index": self.current_server_index,
            "total_servers": len(self.server_urls),
            "threads_running": self._running,
            "stats": stats_copy,
            "cache_stats": cache_stats,
            "sync_health": sync_health,
            "dns_available": True,  # Since we removed DNS_AVAILABLE variable
            "performance_mode": "high_performance_lru_parallel_dns_fixed",
            "current_time": now_iso()
        }
    
    def get_sync_health(self) -> Dict:
        """Get sync health information - delegates to SyncMonitor"""
        return self.sync_monitor.get_sync_health()
    
    def get_recent_errors(self, limit: int = 5) -> List[Dict]:
        """Get recent sync errors - delegates to SyncMonitor"""
        return self.sync_monitor.get_recent_errors(limit)
    
    def force_refresh(self) -> bool:
        """Force complete refresh from server"""
        logger.info(" Forcing complete refresh...")
        
        try:
            # Force full sync
            sync_success = self.update_whitelist_from_server(force_full_sync=True)
            
            if sync_success and self.domains:
                # Force parallel IP refresh
                ip_success = self._resolve_all_ips_parallel(force_refresh=True)
                
                if ip_success:
                    logger.info(" Force refresh completed successfully")
                    return True
                else:
                    logger.warning(" Force refresh: domains synced but IP resolution failed")
                    return True  # Still consider success if domains synced
            else:
                logger.error(" Force refresh failed - sync unsuccessful")
                return False
                
        except Exception as e:
            logger.error(f" Error during force refresh: {e}")
            return False
    
    def get_domain_details(self, domain: str = None) -> Dict:
        """Get detailed domain information with DNS record details"""
        if domain:
            domain = domain.lower().strip()
            if domain not in self.domains:
                return {"error": "Domain not in whitelist"}
            
            # Get cached DNS record
            clean_domain = domain.replace("*.", "")
            dns_record = self.cache_manager.get(clean_domain)
            
            if dns_record:
                return {
                    "domain": domain,
                    "in_whitelist": True,
                    "ipv4_addresses": list(dns_record.ipv4),
                    "ipv6_addresses": list(dns_record.ipv6),
                    "cname": dns_record.cname,
                    "total_ips": len(dns_record.ipv4) + len(dns_record.ipv6),
                    "cache_age": cache_age(dns_record.resolved_at),
                    "ttl": dns_record.ttl,
                    "cache_valid": True
                }
            else:
                return {
                    "domain": domain,
                    "in_whitelist": True,
                    "ipv4_addresses": [],
                    "ipv6_addresses": [],
                    "cname": None,
                    "total_ips": 0,
                    "cache_age": -1,
                    "ttl": 0,
                    "cache_valid": False
                }
        else:
            # Summary of all domains
            cache_stats = self.cache_manager.get_stats()
            with self._stats_lock:
                parallel_dns_calls = self.stats.get("parallel_dns_calls", 0)
                async_dns_calls = self.stats.get("async_dns_calls", 0)
            
            return {
                "total_domains": len(self.domains),
                "total_resolved_ips": len(self.current_resolved_ips),
                "cached_domains": cache_stats["cache_size"],
                "cache_hit_rate": cache_stats["hit_rate"],
                "cache_memory_efficiency": cache_stats["memory_efficiency"],
                "parallel_dns_calls": parallel_dns_calls,
                "async_dns_calls": async_dns_calls,
                "last_updated": self._timestamp_to_iso(self.last_updated) if self.last_updated else None,
                "last_successful_sync": self._timestamp_to_iso(self.last_successful_sync) if self.last_successful_sync else None,
                "startup_sync_completed": self.startup_sync_completed,
                "auto_sync_enabled": self.auto_sync_enabled,
                "current_server": self.server_url,
                "server_index": self.current_server_index,
                "total_servers": len(self.server_urls),
                "performance_mode": "high_performance_lru_parallel_dns_fixed",
                "current_time": now_iso(),
                "dns_available": True  
            }