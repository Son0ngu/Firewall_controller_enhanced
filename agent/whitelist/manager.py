import logging
import threading
from typing import Callable, Dict, List, Optional, Set

from shared.time_utils import now, now_iso, now_server_compatible, sleep, cache_age
from shared.server_urls import collect_server_urls
from shared.whitelist_values import canonicalize_whitelist_entry
from cache.lru_cache import LRUCache
from network import OptimizedDNSResolver

from .state import WhitelistState
from .sync import WhitelistSyncer  

logger = logging.getLogger("whitelist.manager")


class WhitelistManager:
    def __init__(self, config: Dict):

        self.config = config
        self.whitelist_config = config.get("whitelist", {})
        self.server_config = config.get("server", {})
        
        self._state = WhitelistState()
        
        # Initialize syncer with proper parameters
        server_urls = self._get_server_urls()
        agent_id = config.get("agent_id", "unknown")
        self._sync = WhitelistSyncer(
            server_urls=server_urls,
            agent_id=agent_id,
            config=config,  # Pass full config for JWT auth
            connect_timeout=self.server_config.get("connect_timeout", 10),
            read_timeout=self.server_config.get("read_timeout", 30),
            max_retries=self.whitelist_config.get("max_retries", 3)
        )
        
        # Firewall integration
        self._firewall_manager = None
        
        # Callbacks for sync completion
        self._on_sync_callbacks: List[Callable[[], None]] = []
        
        # Threading
        self._lock = threading.RLock()
        self._sync_thread: Optional[threading.Thread] = None
        self._dns_refresh_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Settings
        self._sync_interval = self.whitelist_config.get(
            "update_interval",
            self.whitelist_config.get("sync_interval", 60),
        )
        self._cache_ttl = self.whitelist_config.get("cache_ttl", 300)
        
        # DNS Cache & Resolver
        self.dns_cache = LRUCache(max_size=2000, default_ttl=self._cache_ttl)
        # Reduce max_workers to 5 for better stability on weak machines
        self.resolver = OptimizedDNSResolver(max_workers=5, timeout=5.0)
        
        # Statistics
        self._stats = {
            "total_checks": 0,
            "allowed": 0,
            "blocked": 0,
            "sync_count": 0,
            "last_sync": None,
            "errors": 0
        }
        
        logger.info("WhitelistManager initialized")
    
    def on_sync_complete(self, callback: Callable[[], None]) -> None:
        """Register callback to be called when sync completes."""
        if callback not in self._on_sync_callbacks:
            self._on_sync_callbacks.append(callback)
    
    def _notify_sync_complete(self) -> None:
        """Notify all registered callbacks that sync is complete."""
        for callback in self._on_sync_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Error in sync callback: {e}")
    
    def _get_server_urls(self) -> List[str]:
        """Resolve server URLs via the shared resolver.

        Empty list means "no URL configured" — caller should treat sync as
        offline-skipped instead of contacting localhost. See
        agent/shared/server_urls.py.
        """
        return collect_server_urls(self.config, allow_dev_default=False)
    
    def set_firewall_manager(self, firewall_manager) -> None:
        """Set firewall manager for rule updates."""
        self._firewall_manager = firewall_manager
        logger.info("Firewall manager linked to whitelist")
    
    def start_sync(self) -> None:
        if self._running:
            logger.warning("Sync already running")
            return
        
        self._running = True
        self._sync_thread = threading.Thread(
            target=self._sync_loop,
            daemon=True,
            name="WhitelistSync"
        )
        self._sync_thread.start()
        
        # Start DNS refresh thread
        self._dns_refresh_thread = threading.Thread(
            target=self._refresh_dns_loop,
            daemon=True,
            name="DNSRefresh"
        )
        self._dns_refresh_thread.start()

        logger.info(f"Whitelist sync started (interval: {self._sync_interval}s)")
    
    def stop_sync(self) -> None:
        self._running = False
        if self._sync_thread:
            self._sync_thread.join(timeout=5)
        if self._dns_refresh_thread:
            self._dns_refresh_thread.join(timeout=5)
        logger.info("Whitelist sync stopped")
    
    def stop_periodic_updates(self) -> None:
        self.stop_sync()
    
    def _sync_loop(self) -> None:
        logger.info("Starting initial whitelist sync...")
        
        # Initial sync
        self.sync_now()
        
        while self._running:
            logger.debug(f"Next sync in {self._sync_interval} seconds...")
            for _ in range(int(self._sync_interval)):
                if not self._running:
                    break
                sleep(1)
            
            if self._running:
                logger.info(f"Periodic whitelist sync (interval: {self._sync_interval}s)")
                self.sync_now()
    
    def _refresh_dns_loop(self) -> None:
        """Background loop to refresh expiring DNS records."""
        logger.info("Starting DNS refresh loop...")
        
        while self._running:
            try:
                # Check every 10 seconds
                for _ in range(10): 
                    if not self._running:
                        return
                    sleep(1)
                
                # Get keys expiring in the next 60 seconds
                expiring_domains = self.dns_cache.get_expiring_keys(threshold_seconds=60.0)
                
                if expiring_domains:
                    logger.debug(f"Refreshing {len(expiring_domains)} expiring domains...")
                    updated = False
                    
                    for domain in expiring_domains:
                        if not self._running:
                            break
                            
                        # Resolve
                        try:
                            record = self.resolver.resolve_domain_sync(domain)
                            # Create a set of IPs
                            ips = set(record.ipv4)
                            if ips:
                                self.dns_cache.set(domain, ips, ttl=self._cache_ttl)
                                updated = True
                        except Exception as e:
                            logger.debug(f"Failed to refresh {domain}: {e}")
                    
                    if updated and self._running:
                        logger.info("DNS Cache updated via background refresh, triggering firewall update")
                        self._update_firewall_rules()
                        
            except Exception as e:
                logger.error(f"Error in DNS refresh loop: {e}")
                sleep(5)

    def sync_now(self) -> bool:
        try:
            agent_id = self.config.get("agent_id", "unknown")
            
            # Build sync parameters
            params = {
                "agent_id": agent_id,
                "global_version": self._state._version if self._state._version else None,
                "group_version": self._state._group_version if self._state._group_version else None,
                "group_id": self._state._group_id if self._state._group_id else None,
                "policy_mode": self._state._policy_mode if self._state._policy_mode else "none",
                "timestamp": now_iso()
            }
            
            logger.info(f"Syncing whitelist from server (agent_id: {agent_id})...")
            
            # Sync with server
            result = self._sync.sync_with_server(params)
            
            if result.get("success"):
                data = result.get("data", {})
                
                # Log server response
                domains_count = len(data.get("domains", []))
                logger.info(f"Received {domains_count} entries from server")
                
                # Debug: Log first few entries
                if domains_count > 0:
                    sample = data.get("domains", [])[:3]
                    logger.debug(f"Sample entries: {sample}")
                
                # Update state
                updated = self._state.update(data)
                
                with self._lock:
                    self._stats["sync_count"] += 1
                    self._stats["last_sync"] = now()
                
                if updated:
                    logger.info("Whitelist state updated with new data")
                    
                    # Update firewall rules if available
                    if self._firewall_manager:
                        logger.info("Updating firewall rules...")
                        self._update_firewall_rules()
                    else:
                        logger.debug("No firewall manager linked, skipping firewall update")
                else:
                    logger.debug("No changes in whitelist data (already up to date)")
                
                # Notify callbacks (even if no changes, so GUI can refresh)
                self._notify_sync_complete()
                
                return True
            else:
                # Skip noisy error stats + warning when the sync was
                # short-circuited because the user hasn't configured a
                # Server URL yet (first-run offline mode).
                if result.get("offline"):
                    logger.debug("Whitelist sync skipped: %s", result.get("error"))
                    return False
                with self._lock:
                    self._stats["errors"] += 1
                error_msg = result.get('error', 'Unknown error')
                logger.warning(f"Whitelist sync failed: {error_msg}")
                return False
            
        except Exception as e:
            with self._lock:
                self._stats["errors"] += 1
            logger.error(f"Sync error: {e}", exc_info=True)
            return False
    
    def is_allowed(self, domain: str, ip: Optional[str] = None) -> bool:
        """Check if domain/IP is allowed."""
        with self._lock:
            self._stats["total_checks"] += 1
            
            # Check domain
            if domain and self._state.is_domain_allowed(domain):
                self._stats["allowed"] += 1
                return True
            
            # Check IP
            if ip and self._state.is_ip_allowed(ip):
                self._stats["allowed"] += 1
                return True
            
            self._stats["blocked"] += 1
            return False
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is allowed (delegate to state)."""
        return self._state.is_ip_allowed(ip)

    def remove_ip(self, ip: str) -> bool:
        """Remove IP from whitelist state."""
        success = self._state.remove_ip(ip)
        if success:
             self._update_firewall_rules()
        return success
    
    def _update_firewall_rules(self) -> None:
        """Update firewall rules based on whitelist."""
        if not self._firewall_manager:
            logger.debug("No firewall manager linked, skipping firewall update")
            return
        
        try:
            # Get all whitelisted domains and IPs
            domains = self._state.get_all_domains()
            ips = self._state.get_all_ips()

            # Only exact hostnames are resolvable to firewall IP rules.
            # Wildcard patterns are kept for hostname matching, not DNS.
            all_domains = set()
            for domain in domains:
                entry_type, normalized = canonicalize_whitelist_entry(
                    "domain",
                    domain,
                )
                if entry_type == "domain" and normalized:
                    all_domains.add(normalized)
            
            # CRITICAL: Always whitelist the server URLs
            server_urls = self._get_server_urls()
            for url in server_urls:
                entry_type, normalized = canonicalize_whitelist_entry("url", url)
                if entry_type == "domain" and normalized:
                    all_domains.add(normalized)
                    logger.debug(f"Added server hostname to whitelist: {normalized}")

            # RESOLVE DOMAINS LOCALLY VIA CACHE
            resolved_ips = set()
            domains_to_resolve = set()
            
            for domain in all_domains:
                cached_ips = self.dns_cache.get(domain)
                if cached_ips:
                    resolved_ips.update(cached_ips)
                else:
                    domains_to_resolve.add(domain)
            
            # Resolve missing
            if domains_to_resolve:
                logger.info(f"Resolving {len(domains_to_resolve)} new domains...")
                try:
                    results = self.resolver.resolve_multiple_parallel(list(domains_to_resolve))
                    
                    for domain, record in results.items():
                        domain_ips = set(record.ipv4)
                        if domain_ips:
                            resolved_ips.update(domain_ips)
                            self.dns_cache.set(domain, domain_ips, ttl=self._cache_ttl)
                except Exception as e:
                    logger.error(f"Error resolving domains: {e}")
            
            # Combine all IPs
            final_ips = ips.union(resolved_ips)

            logger.info(f"Updating firewall with {len(all_domains)} domains (resolved to {len(resolved_ips)} IPs) and {len(ips)} static IPs")
            
            # Update firewall - PASS RESOLVED IPS ONLY to avoid double resolution
            if hasattr(self._firewall_manager, 'update_whitelist'):
                # Pass empty domains set, and all IPs
                success = self._firewall_manager.update_whitelist(set(), final_ips)
                if success:
                    logger.info("Firewall rules updated successfully")
                else:
                    logger.warning("Firewall update returned failure")
            else:
                logger.warning("Firewall manager doesn't support update_whitelist method")
            
        except Exception as e:
            logger.error(f"Failed to update firewall rules: {e}")
    
    def get_stats(self) -> Dict:
        with self._lock:
            state_stats = self._state.get_stats()
            
            return {
                **state_stats,
                "total_checks": self._stats["total_checks"],
                "allowed": self._stats["allowed"],
                "blocked": self._stats["blocked"],
                "sync_count": self._stats["sync_count"],
                "last_sync": now_server_compatible(self._stats["last_sync"]) if self._stats["last_sync"] else None,
                "errors": self._stats["errors"],
                "sync_interval": self._sync_interval,
                "running": self._running
            }
    
    def get_cache_info(self) -> Dict:
        with self._lock:
            last_sync = self._stats.get("last_sync")
            
            return {
                "ttl": self._cache_ttl,
                "age": cache_age(last_sync) if last_sync else None,
                "valid": last_sync and cache_age(last_sync) < self._cache_ttl,
                "last_sync": now_server_compatible(last_sync) if last_sync else None
            }
    
    def force_refresh(self) -> bool:
        """Force immediate refresh of whitelist."""
        logger.info("Forcing whitelist refresh...")
        return self.sync_now()
    
    def cleanup(self) -> None:
        self.stop_sync()
        self._state.clear()
        # Shutdown DNS resolver thread pool so its worker threads do not
        # outlive the agent process. Otherwise the ThreadPoolExecutor created
        # in OptimizedDNSResolver.__init__ relies solely on atexit, which can
        # delay or block clean process shutdown.
        resolver = getattr(self, "resolver", None)
        if resolver is not None:
            try:
                resolver.shutdown()
            except Exception as e:
                logger.warning(f"DNS resolver shutdown failed: {e}")
            self.resolver = None
        logger.info("WhitelistManager cleaned up")
