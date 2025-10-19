"""
Enhanced Whitelist Manager for Firewall Controller Agent
UTC ONLY - Clean, optimized implementation with dnspython and aiodns

Key improvements:
- LRU Cache with minimal lock contention
- Parallel and async DNS resolution (wildcard-aware)
- Wildcard includes expansion from server metadata
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

from time_utils import now, now_iso, sleep, is_cache_valid, cache_age
import dns.resolver
import aiodns
import logging

logger = logging.getLogger("whitelist")

DNSRecord = namedtuple("DNSRecord", ["ipv4", "ipv6", "cname", "ttl", "resolved_at"])
CacheValue = namedtuple("CacheValue", ["data", "timestamp", "ttl"])


class HighPerformanceLRUCache:
    """High-performance LRU cache with minimal lock contention"""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheValue] = OrderedDict()
        self._lock = threading.RLock()
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "expired_cleanups": 0,
        }

    def get(self, key: str, force_refresh: bool = False) -> Optional[DNSRecord]:
        """Get cache entry with minimal lock contention"""
        if force_refresh:
            self._stats["misses"] += 1
            return None

        if key not in self._cache:
            self._stats["misses"] += 1
            return None

        with self._lock:
            if key not in self._cache:
                self._stats["misses"] += 1
                return None

            cache_value = self._cache[key]
            self._cache.move_to_end(key)

        if not is_cache_valid(cache_value.timestamp, cache_value.ttl):
            with self._lock:
                self._cache.pop(key, None)

            self._stats["misses"] += 1
            self._stats["expired_cleanups"] += 1
            return None

        self._stats["hits"] += 1
        return cache_value.data

    def set(
        self,
        key: str,
        value: DNSRecord,
        ttl: Optional[int] = None,
        store_time: Optional[float] = None,
    ) -> bool:
        """Set cache entry with automatic LRU eviction"""
        if ttl is None:
            ttl = self.default_ttl

        cache_value = CacheValue(
            data=value,
            timestamp=store_time if store_time is not None else now(),
            ttl=ttl,
        )

        with self._lock:
            if key in self._cache:
                self._cache[key] = cache_value
                self._cache.move_to_end(key)
            else:
                if len(self._cache) >= self.max_size:
                    oldest_key = next(iter(self._cache))
                    self._cache.pop(oldest_key)
                    self._stats["evictions"] += 1

                self._cache[key] = cache_value

        return True

    def bulk_cleanup_expired(self) -> int:
        """Bulk cleanup of expired entries"""
        expired_keys: List[str] = []

        with self._lock:
            for key, cache_value in list(self._cache.items()):
                if not is_cache_valid(cache_value.timestamp, cache_value.ttl):
                    expired_keys.append(key)

        if expired_keys:
            with self._lock:
                for key in expired_keys:
                    self._cache.pop(key, None)

            self._stats["expired_cleanups"] += len(expired_keys)
            logger.debug("🧹 Bulk cleaned %d expired cache entries", len(expired_keys))

        return len(expired_keys)

    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self._lock:
            cache_size = len(self._cache)

        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            **self._stats,
            "total_requests": total_requests,
            "hit_rate": hit_rate,
            "cache_size": cache_size,
            "max_size": self.max_size,
            "default_ttl": self.default_ttl,
            "memory_efficiency": (cache_size / self.max_size * 100) if self.max_size > 0 else 0,
        }

    def clear(self) -> None:
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

        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        self.resolver.nameservers = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]

        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="DNSResolver",
        )

        self.aiodns_resolver = aiodns.DNSResolver()
        self.aiodns_resolver.timeout = timeout

        atexit.register(self.shutdown)

    def resolve_domain_sync(self, domain: str) -> DNSRecord:
        """Synchronous DNS resolution with dnspython"""
        if self._shutdown:
            return self._fallback_resolve(domain)

        ipv4_ips: List[str] = []
        ipv6_ips: List[str] = []
        cname = None
        min_ttl = 300

        try:
            try:
                answers = self.resolver.resolve(domain, "A")
                ipv4_ips = [str(rdata) for rdata in answers]
                min_ttl = min(min_ttl, answers.ttl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass

            try:
                answers = self.resolver.resolve(domain, "AAAA")
                ipv6_ips = [str(rdata) for rdata in answers]
                min_ttl = min(min_ttl, answers.ttl)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass

            if not ipv4_ips and not ipv6_ips:
                try:
                    answers = self.resolver.resolve(domain, "CNAME")
                    if answers:
                        cname = str(answers[0])
                        cname_record = self.resolve_domain_sync(cname)
                        ipv4_ips = list(cname_record.ipv4)
                        ipv6_ips = list(cname_record.ipv6)
                        min_ttl = min(min_ttl, answers.ttl, cname_record.ttl)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    pass

        except Exception as exc:
            logger.debug("DNS resolution error for %s: %s", domain, exc)
            return self._fallback_resolve(domain)

        return DNSRecord(
            ipv4=tuple(sorted(set(ipv4_ips))),
            ipv6=tuple(sorted(set(ipv6_ips))),
            cname=cname,
            ttl=min_ttl,
            resolved_at=now(),
        )

    async def resolve_domain_async(self, domain: str) -> DNSRecord:
        """Asynchronous DNS resolution with aiodns"""
        if self._shutdown:
            return await self._async_fallback_resolve(domain)

        ipv4_ips: List[str] = []
        ipv6_ips: List[str] = []
        cname = None
        min_ttl = 300

        try:
            tasks = [
                self._safe_query_async(domain, "A"),
                self._safe_query_async(domain, "AAAA"),
            ]

            results = await asyncio.gather(*tasks, return_exceptions=True)

            if not isinstance(results[0], Exception) and results[0]:
                ipv4_ips = [record.host for record in results[0]]
                min_ttl = min(min_ttl, results[0][0].ttl if results[0] else 300)

            if not isinstance(results[1], Exception) and results[1]:
                ipv6_ips = [record.host for record in results[1]]
                min_ttl = min(min_ttl, results[1][0].ttl if results[1] else 300)

            if not ipv4_ips and not ipv6_ips:
                cname_result = await self._safe_query_async(domain, "CNAME")
                if not isinstance(cname_result, Exception) and cname_result:
                    cname = cname_result[0].cname
                    cname_record = await self.resolve_domain_async(cname)
                    ipv4_ips = list(cname_record.ipv4)
                    ipv6_ips = list(cname_record.ipv6)
                    min_ttl = min(min_ttl, cname_record.ttl)

        except Exception as exc:
            logger.debug("Async DNS resolution error for %s: %s", domain, exc)
            return await self._async_fallback_resolve(domain)

        return DNSRecord(
            ipv4=tuple(sorted(set(ipv4_ips))),
            ipv6=tuple(sorted(set(ipv6_ips))),
            cname=cname,
            ttl=min_ttl,
            resolved_at=now(),
        )

    async def _safe_query_async(self, domain: str, record_type: str):
        try:
            return await asyncio.wait_for(
                self.aiodns_resolver.query(domain, record_type),
                timeout=self.timeout,
            )
        except Exception:
            return None

    def resolve_multiple_parallel(self, domains: List[str]) -> Dict[str, DNSRecord]:
        """Resolve multiple domains in parallel using thread pool"""
        if not domains or self._shutdown:
            return {}

        logger.info(" Parallel DNS resolution for %d domains", len(domains))
        start_time = now()

        future_to_domain = {
            self.executor.submit(self.resolve_domain_sync, domain): domain for domain in domains
        }

        results: Dict[str, DNSRecord] = {}
        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results[domain] = result
            except Exception as exc:
                logger.warning("DNS resolution failed for %s: %s", domain, exc)
                results[domain] = self._fallback_resolve(domain)

        duration = now() - start_time
        logger.info(
            " Parallel DNS resolution completed in %.2fs (%d/%d domains)",
            duration,
            len(results),
            len(domains),
        )
        return results

    async def resolve_multiple_async(self, domains: List[str]) -> Dict[str, DNSRecord]:
        """Resolve multiple domains asynchronously"""
        if not domains or self._shutdown:
            return {}

        logger.info(" Async DNS resolution for %d domains", len(domains))
        start_time = now()

        tasks = [self.resolve_domain_async(domain) for domain in domains]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: Dict[str, DNSRecord] = {}
        for domain, result in zip(domains, results_list):
            if isinstance(result, Exception):
                logger.warning("Async DNS resolution failed for %s: %s", domain, result)
                results[domain] = self._fallback_resolve(domain)
            else:
                results[domain] = result

        duration = now() - start_time
        logger.info(
            " Async DNS resolution completed in %.2fs (%d/%d domains)",
            duration,
            len(results),
            len(domains),
        )

        return results

    def _fallback_resolve(self, domain: str) -> DNSRecord:
        """Fallback to standard socket resolution"""
        if self._is_ip_address(domain):
            try:
                ip_obj = ipaddress.ip_address(domain)
                if ip_obj.version == 4:
                    return DNSRecord(
                        ipv4=(domain,),
                        ipv6=(),
                        cname=None,
                        ttl=300,
                        resolved_at=now(),
                    )
                return DNSRecord(
                    ipv4=(),
                    ipv6=(domain,),
                    cname=None,
                    ttl=300,
                    resolved_at=now(),
                )
            except ValueError:
                pass

        ipv4_ips: Set[str] = set()
        ipv6_ips: Set[str] = set()

        try:
            ipv4_results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            ipv4_ips = {res[4][0] for res in ipv4_results}
        except socket.gaierror:
            pass

        try:
            ipv6_results = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            ipv6_ips = {res[4][0] for res in ipv6_results}
        except socket.gaierror:
            pass

        return DNSRecord(
            ipv4=tuple(sorted(ipv4_ips)),
            ipv6=tuple(sorted(ipv6_ips)),
            cname=None,
            ttl=300,
            resolved_at=now(),
        )

    async def _async_fallback_resolve(self, domain: str) -> DNSRecord:
        if self._shutdown:
            return self._fallback_resolve(domain)
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, self._fallback_resolve, domain)

    def _is_ip_address(self, address: str) -> bool:
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    def shutdown(self) -> None:
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

    def record_sync(
        self,
        sync_type: str,
        success: bool,
        domains_count: int,
        duration: float,
        error: str = None,
        details: Dict = None,
    ):
        with self._lock:
            sync_record = {
                "timestamp": now_iso(),
                "type": sync_type,
                "success": success,
                "domains_count": domains_count,
                "duration": duration,
                "error": error,
                "details": details or {},
            }

            self.sync_history.append(sync_record)
            if len(self.sync_history) > self.max_history:
                self.sync_history.pop(0)

    def get_sync_health(self) -> Dict:
        with self._lock:
            if not self.sync_history:
                return {
                    "status": "no_data",
                    "message": "No sync history available",
                    "success_rate": 0,
                    "total_syncs": 0,
                }

            recent_syncs = self.sync_history[-10:]
            success_count = sum(1 for sync in recent_syncs if sync["success"])
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
                "last_sync": self.sync_history[-1],
                "avg_duration": (
                    sum(sync["duration"] for sync in recent_syncs) / len(recent_syncs)
                    if recent_syncs
                    else 0
                ),
                "error_rate": (len(recent_syncs) - success_count) / len(recent_syncs) * 100,
            }

    def get_recent_errors(self, limit: int = 5) -> List[Dict]:
        with self._lock:
            errors = [
                sync for sync in self.sync_history if not sync["success"] and sync["error"]
            ]
            return errors[-limit:]


class WhitelistManager:
    """Enhanced Whitelist Manager with high-performance caching and DNS resolution"""

    def __init__(self, config: Dict):
        whitelist_config = config.get("whitelist", {})
        server_config = config.get("server", {})

        self.update_interval = max(whitelist_config.get("update_interval", 300), 30)
        self.retry_interval = max(whitelist_config.get("retry_interval", 60), 10)
        self.max_retries = whitelist_config.get("max_retries", 3)
        self.timeout = whitelist_config.get("timeout", 30)

        server_urls = server_config.get("urls", [])
        if not server_urls:
            primary_url = server_config.get(
                "url", "https://firewall-controller.onrender.com"
            )
            server_urls = [primary_url]

        self.server_urls = server_urls
        self.current_server_index = 0
        self.server_url = self._build_sync_url(server_urls[0])

        self.connect_timeout = server_config.get("connect_timeout", 10)
        self.read_timeout = server_config.get("read_timeout", 30)

        self.auto_sync_enabled = whitelist_config.get("auto_sync", True)
        self.sync_on_startup = whitelist_config.get("sync_on_startup", True)
        self.auto_sync_firewall = whitelist_config.get("auto_sync_firewall", True)
        self.resolve_ips_on_startup = whitelist_config.get("resolve_ips_on_startup", True)

        cache_ttl = whitelist_config.get("ip_cache_ttl", 300)
        max_cache_entries = whitelist_config.get("max_cache_entries", 2000)
        dns_workers = whitelist_config.get("dns_workers", 20)
        dns_timeout = whitelist_config.get("dns_timeout", 5.0)

        self.cache_manager = HighPerformanceLRUCache(
            max_size=max_cache_entries,
            default_ttl=cache_ttl,
        )

        self.dns_resolver = OptimizedDNSResolver(
            max_workers=dns_workers,
            timeout=dns_timeout,
        )

        self.ip_refresh_interval = whitelist_config.get("ip_refresh_interval", 600)
        self._cache_cleanup_interval = 300
        self._last_cache_cleanup = now()

        self.domains: Set[str] = set()
        self.domain_metadata: Dict[str, Dict] = {}
        self._last_domain_ip_map: Dict[str, Set[str]] = {}
        self.current_resolved_ips: Set[str] = set()
        self.previous_resolved_ips: Set[str] = set()

        self.last_updated: Optional[float] = None
        self.last_successful_sync: Optional[float] = None
        self.startup_sync_completed = False

        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None
        self._ip_refresh_thread: Optional[threading.Thread] = None
        self._cache_cleanup_thread: Optional[threading.Thread] = None
        self._running = False
        self.sync_in_progress = threading.Lock()

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
            "cache_stats": {},
        }

        self.firewall_manager = None
        self.sync_monitor = SyncMonitor()

        atexit.register(self.stop_periodic_updates)

        logger.info(" Initializing High-Performance WhitelistManager...")

        self._load_state()

        if self.sync_on_startup:
            startup_success = self._perform_startup_sync()
            if startup_success and self.resolve_ips_on_startup and self.domains:
                self._resolve_all_ips_parallel(force_refresh=True)

        if self.auto_sync_enabled:
            self.start_periodic_updates()

        logger.info(
            " High-Performance WhitelistManager initialized: %d domains", len(self.domains)
        )

    # ------------------------------------------------------------------
    # Domain metadata helpers
    # ------------------------------------------------------------------

    def _normalize_domain(self, domain: str) -> str:
        return (domain or "").strip().lower()

    def _build_domain_metadata(self, domain_data) -> Dict:
        includes = self._extract_includes(domain_data)
        metadata = {
            "type": "domain",
            "category": "uncategorized",
            "priority": "normal",
            "includes": includes,
        }
        if isinstance(domain_data, dict):
            metadata["type"] = domain_data.get("type", "domain")
            metadata["category"] = domain_data.get("category", "uncategorized")
            metadata["priority"] = domain_data.get("priority", "normal")
            if domain_data.get("added_date"):
                metadata["added_date"] = domain_data.get("added_date")
        return metadata

    def _extract_includes(self, domain_data) -> List[str]:
        if isinstance(domain_data, dict):
            includes = domain_data.get("includes", [])
            if isinstance(includes, (list, tuple, set)):
                normalized = []
                for item in includes:
                    if isinstance(item, str):
                        cleaned = item.strip().lower()
                        if cleaned:
                            normalized.append(cleaned)
                return sorted(set(normalized))
        return []

    def _get_domain_metadata(self, domain: str) -> Dict:
        return self.domain_metadata.get(domain, {})

    def _get_resolution_targets(self, domain: str) -> List[str]:
        normalized = self._normalize_domain(domain)
        metadata = self._get_domain_metadata(normalized)
        includes = metadata.get("includes", [])

        targets: List[str] = []
        seen: Set[str] = set()

        def _add(target: str):
            if target and target not in seen:
                seen.add(target)
                targets.append(target)

        _add(normalized)
        if normalized.startswith("*."):
            _add(normalized[2:])

        for include in includes:
            _add(self._normalize_domain(include))

        logger.debug(
            "Resolution targets for %s: %s (includes=%d)",
            normalized,
            targets,
            len(includes),
        )
        return targets

    # ------------------------------------------------------------------
    # Core whitelist logic
    # ------------------------------------------------------------------

    def _build_sync_url(self, base_url: str) -> str:
        base_url = base_url.rstrip("/")
        return f"{base_url}/api/whitelist/agent-sync"

    def _perform_startup_sync(self) -> bool:
        logger.info(" Performing startup sync...")
        success = self.update_whitelist_from_server(force_full_sync=True)
        if success:
            self.startup_sync_completed = True
            logger.info(" Startup sync completed: %d domains", len(self.domains))
            return True
        logger.error(" Startup sync failed - will retry in background")
        return False

    def _update_stats(self, **kwargs) -> None:
        with self._stats_lock:
            self.stats.update(kwargs)

    def _increment_stat(self, key: str, amount: int = 1) -> None:
        with self._stats_lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    def is_allowed(self, domain: str) -> bool:
        if not domain:
            return False

        domain = self._normalize_domain(domain)

        if domain in self.domains:
            return True

        for whitelist_domain in self.domains:
            if whitelist_domain.startswith("*."):
                base_domain = whitelist_domain[2:]
                if domain == base_domain or domain.endswith("." + base_domain):
                    return True

        return False

    def is_ip_allowed(self, ip: str) -> bool:
        if not ip:
            return False

        try:
            if ip in self.domains:
                return True

            if ip in self.current_resolved_ips:
                return True

            if self._is_essential_ip(ip):
                return True

            return False

        except Exception as exc:
            logger.warning("Error checking IP %s: %s", ip, exc)
            return False

    def _is_essential_ip(self, ip: str) -> bool:
        essential_ips = {
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "208.67.222.222",
            "208.67.220.220",
            "9.9.9.9",
            "149.112.112.112",
        }

        if ip in essential_ips:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Wildcard-aware DNS resolution
    # ------------------------------------------------------------------

    def _collect_resolution_plan(self) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        domain_target_map: Dict[str, List[str]] = {}
        alias_to_resolvable: Dict[str, str] = {}

        for domain in self.domains:
            targets = self._get_resolution_targets(domain)
            if not targets:
                continue

            domain_target_map[domain] = targets

            for target in targets:
                resolvable = target[2:] if target.startswith("*.") else target
                if resolvable:
                    alias_to_resolvable[target] = resolvable

        return domain_target_map, alias_to_resolvable

    def _resolve_all_ips_parallel(self, force_refresh: bool = False) -> bool:
        if not self.domains:
            logger.warning("No domains to resolve")
            return False

        self._maybe_cleanup_cache()

        domain_target_map, alias_to_resolvable = self._collect_resolution_plan()

        if not alias_to_resolvable:
            logger.warning("No resolvable targets found for whitelist domains")
            return False

        unique_resolvables = set(alias_to_resolvable.values())
        cached_records: Dict[str, DNSRecord] = {}
        targets_to_resolve: Set[str] = set()

        for resolvable in unique_resolvables:
            if force_refresh:
                targets_to_resolve.add(resolvable)
                continue

            cached_record = self.cache_manager.get(resolvable)
            if cached_record:
                cached_records[resolvable] = cached_record
            else:
                targets_to_resolve.add(resolvable)

        cached_count = len(unique_resolvables) - len(targets_to_resolve)
        logger.info(
            " IP Resolution: %d cached targets, %d to resolve (unique: %d)",
            cached_count,
            len(targets_to_resolve),
            len(unique_resolvables),
        )

        fresh_results: Dict[str, DNSRecord] = {}
        if targets_to_resolve:
            self._increment_stat("parallel_dns_calls")
            fresh_results = self.dns_resolver.resolve_multiple_parallel(
                list(targets_to_resolve)
            )
            for resolvable, record in fresh_results.items():
                if record and (record.ipv4 or record.ipv6):
                    self.cache_manager.set(
                        resolvable,
                        record,
                        record.ttl,
                        store_time=record.resolved_at,
                    )

        all_records = {**cached_records, **fresh_results}

        for alias, resolvable in alias_to_resolvable.items():
            record = all_records.get(resolvable)
            if record and alias != resolvable:
                self.cache_manager.set(
                    alias,
                    record,
                    record.ttl,
                    store_time=record.resolved_at,
                )

        total_ips: Set[str] = set()
        success_count = 0
        self._last_domain_ip_map = {}

        for domain, targets in domain_target_map.items():
            domain_ips: Set[str] = set()

            for target in targets:
                resolvable = alias_to_resolvable.get(target)
                record = None
                if resolvable:
                    record = all_records.get(resolvable)
                if not record:
                    record = self.cache_manager.get(target)
                if not record and target.startswith("*."):
                    record = self.cache_manager.get(target[2:])

                if record:
                    domain_ips.update(record.ipv4)
                    domain_ips.update(record.ipv6)

            if domain_ips:
                success_count += 1
                total_ips.update(domain_ips)

            self._last_domain_ip_map[domain] = domain_ips

        self.previous_resolved_ips = self.current_resolved_ips.copy()
        self.current_resolved_ips = total_ips

        self._increment_stat("ip_resolution_count", success_count)
        self._increment_stat(
            "ip_resolution_errors",
            len(self.domains) - success_count,
        )

        logger.info(
            " Parallel IP resolution completed: %d/%d domains, %d IPs",
            success_count,
            len(self.domains),
            len(total_ips),
        )

        return len(total_ips) > 0

    async def _resolve_all_ips_async(self, force_refresh: bool = False) -> bool:
        if not self.domains:
            logger.warning("No domains to resolve")
            return False

        self._maybe_cleanup_cache()

        domain_target_map, alias_to_resolvable = self._collect_resolution_plan()

        if not alias_to_resolvable:
            logger.warning("No resolvable targets found for whitelist domains")
            return False

        unique_resolvables = set(alias_to_resolvable.values())
        cached_records: Dict[str, DNSRecord] = {}
        targets_to_resolve: Set[str] = set()

        for resolvable in unique_resolvables:
            if force_refresh:
                targets_to_resolve.add(resolvable)
                continue

            cached_record = self.cache_manager.get(resolvable)
            if cached_record:
                cached_records[resolvable] = cached_record
            else:
                targets_to_resolve.add(resolvable)

        cached_count = len(unique_resolvables) - len(targets_to_resolve)
        logger.info(
            " Async IP Resolution: %d cached targets, %d to resolve (unique: %d)",
            cached_count,
            len(targets_to_resolve),
            len(unique_resolvables),
        )

        fresh_results: Dict[str, DNSRecord] = {}
        if targets_to_resolve:
            self._increment_stat("async_dns_calls")
            fresh_results = await self.dns_resolver.resolve_multiple_async(
                list(targets_to_resolve)
            )
            for resolvable, record in fresh_results.items():
                if record and (record.ipv4 or record.ipv6):
                    self.cache_manager.set(
                        resolvable,
                        record,
                        record.ttl,
                        store_time=record.resolved_at,
                    )

        all_records = {**cached_records, **fresh_results}

        for alias, resolvable in alias_to_resolvable.items():
            record = all_records.get(resolvable)
            if record and alias != resolvable:
                self.cache_manager.set(
                    alias,
                    record,
                    record.ttl,
                    store_time=record.resolved_at,
                )

        total_ips: Set[str] = set()
        success_count = 0
        self._last_domain_ip_map = {}

        for domain, targets in domain_target_map.items():
            domain_ips: Set[str] = set()

            for target in targets:
                resolvable = alias_to_resolvable.get(target)
                record = None
                if resolvable:
                    record = all_records.get(resolvable)
                if not record:
                    record = self.cache_manager.get(target)
                if not record and target.startswith("*."):
                    record = self.cache_manager.get(target[2:])
                if record:
                    domain_ips.update(record.ipv4)
                    domain_ips.update(record.ipv6)

            if domain_ips:
                success_count += 1
                total_ips.update(domain_ips)

            self._last_domain_ip_map[domain] = domain_ips

        self.previous_resolved_ips = self.current_resolved_ips.copy()
        self.current_resolved_ips = total_ips

        self._increment_stat("ip_resolution_count", success_count)
        self._increment_stat(
            "ip_resolution_errors",
            len(self.domains) - success_count,
        )

        logger.info(
            " Async IP resolution completed: %d/%d domains, %d IPs",
            success_count,
            len(self.domains),
            len(total_ips),
        )

        return len(total_ips) > 0

    def _maybe_cleanup_cache(self) -> None:
        current_time = now()
        if current_time - self._last_cache_cleanup > self._cache_cleanup_interval:
            self.cache_manager.bulk_cleanup_expired()
            self._last_cache_cleanup = current_time

    def _resolve_all_ips(self, force_refresh: bool = False) -> bool:
        return self._resolve_all_ips_parallel(force_refresh)

    # ------------------------------------------------------------------
    # Server synchronization
    # ------------------------------------------------------------------

    def update_whitelist_from_server(self, force_full_sync: bool = False) -> bool:
        acquired = self.sync_in_progress.acquire(blocking=False)
        if not acquired:
            logger.debug("Sync already in progress, skipping")
            return False

        sync_id = f"sync_{int(now())}"
        start_time = now()

        try:
            logger.info(" [%s] Starting whitelist sync", sync_id)

            should_do_full_sync = (
                force_full_sync
                or not self.startup_sync_completed
                or len(self.domains) == 0
                or self.last_updated is None
                or (now() - (self.last_updated or 0)) > 86400
            )

            params: Dict[str, str] = {}
            if not should_do_full_sync and self.last_updated:
                params["since"] = self._timestamp_to_iso(self.last_updated)
                logger.info(" [%s] Incremental sync since %s", sync_id, params["since"])
            else:
                logger.info(
                    " [%s] Full sync (forced=%s, startup=%s)",
                    sync_id,
                    force_full_sync,
                    not self.startup_sync_completed,
                )

            sync_result = self._sync_with_fallback(params)

            if not sync_result["success"]:
                raise Exception(sync_result["error"])

            domains_data = sync_result["data"].get("domains", [])
            if not isinstance(domains_data, list):
                raise ValueError(f"Invalid domains format: {type(domains_data)}")

            old_domains = self.domains.copy()
            old_metadata = self.domain_metadata.copy()

            incoming_domains: Set[str] = set()
            incoming_metadata: Dict[str, Dict] = {}

            for domain_data in domains_data:
                value = self._extract_domain_value(domain_data)
                if not value:
                    continue
                normalized = self._normalize_domain(value)
                incoming_domains.add(normalized)
                incoming_metadata[normalized] = self._build_domain_metadata(domain_data)

            domains_added = incoming_domains - old_domains
            domains_removed = old_domains - incoming_domains

            self.domains = incoming_domains
            self.domain_metadata = incoming_metadata

            current_timestamp = now()
            self.last_updated = current_timestamp
            self.last_successful_sync = current_timestamp

            duration = current_timestamp - start_time
            self._increment_stat("sync_count")
            self._update_stats(
                last_sync_time=current_timestamp,
                last_sync_duration=duration,
                total_domains_processed=len(self.domains),
            )

            self.sync_monitor.record_sync(
                sync_type="full" if should_do_full_sync else "incremental",
                success=True,
                domains_count=len(self.domains),
                duration=duration,
                details={
                    "domains_added": len(domains_added),
                    "domains_removed": len(domains_removed),
                    "total_domains": len(self.domains),
                },
            )

            if old_domains != self.domains:
                logger.info(" Domain changes detected, syncing with firewall...")
                self._sync_with_firewall(old_domains, self.domains)

            self._save_state()

            logger.info(" [%s] Sync completed successfully", sync_id)
            logger.info("   • Total domains: %d", len(self.domains))
            logger.info("   • New domains: %d", len(domains_added))
            logger.info("   • Removed domains: %d", len(domains_removed))
            logger.info("   • Duration: %.2fs", duration)
            logger.info("   • Type: %s", "full" if should_do_full_sync else "incremental")

            return True

        except Exception as exc:
            duration = now() - start_time
            error_msg = str(exc)

            self._increment_stat("sync_errors")
            self.sync_monitor.record_sync(
                sync_type="full" if force_full_sync else "incremental",
                success=False,
                domains_count=len(self.domains),
                duration=duration,
                error=error_msg,
            )

            logger.error(" [%s] Sync failed after %.2fs: %s", sync_id, duration, error_msg)
            return False

        finally:
            self.sync_in_progress.release()

    def _sync_with_fallback(self, params: Dict) -> Dict:
        last_error = None

        for attempt in range(self.max_retries):
            try:
                response = requests.get(
                    self.server_url,
                    params=params,
                    timeout=(self.connect_timeout, self.read_timeout),
                    headers={"User-Agent": "FirewallController-Agent/2.1-HighPerf"},
                )

                if response.status_code == 200:
                    data = response.json()
                    if data.get("success", True):
                        return {"success": True, "data": data}
                    raise Exception(data.get("error", "Server returned error"))

                raise Exception(f"HTTP {response.status_code}: {response.text}")

            except Exception as exc:
                last_error = exc
                logger.warning("Sync attempt %d failed: %s", attempt + 1, exc)
                if attempt < self.max_retries - 1:
                    sleep(min(self.retry_interval * (attempt + 1), 300))

        if len(self.server_urls) > 1:
            logger.info("Trying fallback servers...")
            for index, fallback_url in enumerate(self.server_urls[1:], 1):
                try:
                    fallback_sync_url = self._build_sync_url(fallback_url)
                    logger.info("Attempting fallback server %d: %s", index, fallback_url)

                    response = requests.get(
                        fallback_sync_url,
                        params=params,
                        timeout=(self.connect_timeout, self.read_timeout),
                        headers={"User-Agent": "FirewallController-Agent/2.1-HighPerf"},
                    )

                    if response.status_code == 200:
                        data = response.json()
                        if data.get("success", True):
                            self.server_url = fallback_sync_url
                            self.current_server_index = index
                            logger.info(" Switched to fallback server: %s", fallback_url)
                            return {"success": True, "data": data}

                except Exception as exc:
                    logger.warning("Fallback server %d failed: %s", index, exc)
                    last_error = exc

        return {"success": False, "error": str(last_error)}

    def _extract_domain_value(self, domain_data) -> Optional[str]:
        if isinstance(domain_data, dict):
            return self._normalize_domain(domain_data.get("value", ""))
        if isinstance(domain_data, str):
            return self._normalize_domain(domain_data)
        logger.warning("Invalid domain data format: %s", domain_data)
        return None

    def _timestamp_to_iso(self, timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")

    # ------------------------------------------------------------------
    # Firewall integration
    # ------------------------------------------------------------------

    def set_firewall_manager(self, firewall_manager):
        self.firewall_manager = firewall_manager
        logger.info("🔗 Firewall manager linked")

        if self.startup_sync_completed and self.auto_sync_firewall:
            self._sync_with_firewall_initial()

    def _sync_with_firewall_initial(self) -> None:
        try:
            if not self.firewall_manager:
                return

            logger.info(" Performing initial firewall sync...")

            whitelisted_ips = self.get_all_whitelisted_ips()

            if not whitelisted_ips:
                logger.warning("No whitelisted IPs for firewall sync")
                return

            success = self.firewall_manager.setup_whitelist_firewall(whitelisted_ips)

            if success:
                self._increment_stat("firewall_sync_count")
                logger.info(" Initial firewall sync completed: %d IPs", len(whitelisted_ips))
            else:
                logger.error(" Initial firewall sync failed")

        except Exception as exc:
            logger.error("Error in initial firewall sync: %s", exc)

    def _sync_with_firewall(self, old_domains: Set[str], new_domains: Set[str]) -> None:
        try:
            if not self.firewall_manager or not self.auto_sync_firewall:
                return

            if old_domains != new_domains:
                logger.info(" Domain changes detected, resolving IPs...")
                self._resolve_all_ips_parallel(force_refresh=True)

            old_ips = self.previous_resolved_ips
            new_ips = self.current_resolved_ips

            if old_ips != new_ips:
                logger.info(" IP changes detected: %d → %d", len(old_ips), len(new_ips))
                success = self.firewall_manager.sync_whitelist_changes(old_ips, new_ips)

                if success:
                    self._increment_stat("firewall_sync_count")
                    logger.info(" Firewall sync completed")
                else:
                    logger.warning(" Firewall sync had errors")
            else:
                logger.debug("No IP changes, skipping firewall sync")

        except Exception as exc:
            logger.error("Error syncing with firewall: %s", exc)

    def get_all_whitelisted_ips(self, force_refresh: bool = False) -> Set[str]:
        try:
            if force_refresh or not self.current_resolved_ips:
                self._resolve_all_ips_parallel(force_refresh=True)

            return self.current_resolved_ips.copy()

        except Exception as exc:
            logger.error("Error getting whitelisted IPs: %s", exc)
            return set()

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _serialize_domain_metadata(self) -> Dict[str, Dict]:
        serialized: Dict[str, Dict] = {}
        for domain, metadata in self.domain_metadata.items():
            includes = metadata.get("includes", [])
            serialized[domain] = {
                "type": metadata.get("type", "domain"),
                "category": metadata.get("category", "uncategorized"),
                "priority": metadata.get("priority", "normal"),
                "includes": includes,
                "added_date": metadata.get("added_date"),
            }
        return serialized

    def _load_domain_metadata(self, stored_metadata) -> None:
        if not isinstance(stored_metadata, dict):
            return

        normalized_metadata: Dict[str, Dict] = {}
        for domain, metadata in stored_metadata.items():
            normalized_domain = self._normalize_domain(domain)
            if not normalized_domain:
                continue

            includes = []
            if isinstance(metadata, dict):
                raw_includes = metadata.get("includes", [])
                if isinstance(raw_includes, (list, tuple, set)):
                    includes = [
                        self._normalize_domain(item)
                        for item in raw_includes
                        if isinstance(item, str) and self._normalize_domain(item)
                    ]

                normalized_metadata[normalized_domain] = {
                    "type": metadata.get("type", "domain"),
                    "category": metadata.get("category", "uncategorized"),
                    "priority": metadata.get("priority", "normal"),
                    "includes": sorted(set(includes)),
                    "added_date": metadata.get("added_date"),
                }
        self.domain_metadata = normalized_metadata
        self.domains = set(normalized_metadata.keys())

    def _save_state(self) -> None:
        try:
            with self._stats_lock:
                self.stats["cache_stats"] = self.cache_manager.get_stats()
                state_stats = self.stats.copy()

            state = {
                "domains": sorted(list(self.domains)),
                "domain_metadata": self._serialize_domain_metadata(),
                "last_updated": self.last_updated,
                "last_successful_sync": self.last_successful_sync,
                "startup_sync_completed": self.startup_sync_completed,
                "current_resolved_ips": sorted(list(self.current_resolved_ips)),
                "stats": state_stats,
                "server_url": self.server_url,
                "current_server_index": self.current_server_index,
                "saved_at": now_iso(),
                "version": "2.1-HighPerf",
            }

            with open("whitelist_state.json", "w", encoding="utf-8") as state_file:
                json.dump(state, state_file, indent=2, ensure_ascii=False)

            logger.debug(" State saved: %d domains", len(self.domains))

        except Exception as exc:
            logger.error("Error saving state: %s", exc)

    def _load_state(self) -> None:
        try:
            if not os.path.exists("whitelist_state.json"):
                logger.debug("No state file found, starting fresh")
                return

            with open("whitelist_state.json", "r", encoding="utf-8") as state_file:
                content = state_file.read().strip()
                if not content:
                    logger.warning("Empty state file, starting fresh")
                    return

                state = json.loads(content)

            stored_metadata = state.get("domain_metadata")
            if stored_metadata:
                self._load_domain_metadata(stored_metadata)
            else:
                domains_data = state.get("domains", [])
                if isinstance(domains_data, list):
                    self.domains = {
                        self._normalize_domain(domain)
                        for domain in domains_data
                        if isinstance(domain, str)
                    }
                    self.domain_metadata = {domain: {} for domain in self.domains}

            current_time = now()

            if state.get("last_updated"):
                saved_timestamp = state.get("last_updated")
                if saved_timestamp > current_time:
                    logger.warning("Saved timestamp is in future, adjusting")
                    self.last_updated = current_time - 60
                else:
                    self.last_updated = saved_timestamp
                    logger.debug(
                        "Loaded last_updated: %s",
                        self._timestamp_to_iso(self.last_updated),
                    )

            if state.get("last_successful_sync"):
                self.last_successful_sync = state.get("last_successful_sync")

            self.startup_sync_completed = state.get("startup_sync_completed", False)

            resolved_ips_data = state.get("current_resolved_ips", [])
            if isinstance(resolved_ips_data, list):
                self.current_resolved_ips = {
                    ip for ip in resolved_ips_data if isinstance(ip, str)
                }

            if "stats" in state and isinstance(state["stats"], dict):
                with self._stats_lock:
                    self.stats.update(state["stats"])

            if state.get("server_url"):
                self.server_url = state["server_url"]
            if state.get("current_server_index") is not None:
                self.current_server_index = state["current_server_index"]

            logger.info(
                " State loaded: %d domains, last_updated=%s",
                len(self.domains),
                self._timestamp_to_iso(self.last_updated)
                if self.last_updated
                else "None",
            )

        except Exception as exc:
            logger.warning("Error loading state: %s", exc)
            self.domains = set()
            self.domain_metadata = {}
            self.last_updated = None
            self.current_resolved_ips = set()
            self.startup_sync_completed = False

    # ------------------------------------------------------------------
    # Periodic updates
    # ------------------------------------------------------------------

    def start_periodic_updates(self) -> None:
        if self._running:
            logger.warning("Periodic updates already running")
            return

        self._running = True
        self._stop_event.clear()

        self._update_thread = threading.Thread(
            target=self._update_loop,
            name="WhitelistSync",
            daemon=True,
        )
        self._update_thread.start()

        self._ip_refresh_thread = threading.Thread(
            target=self._ip_refresh_loop,
            name="IPRefresh",
            daemon=True,
        )
        self._ip_refresh_thread.start()

        self._cache_cleanup_thread = threading.Thread(
            target=self._cache_cleanup_loop,
            name="CacheCleanup",
            daemon=True,
        )
        self._cache_cleanup_thread.start()

        logger.info(" High-performance periodic update threads started")

    def _update_loop(self) -> None:
        consecutive_failures = 0

        while not self._stop_event.is_set():
            try:
                force_full = consecutive_failures >= 3
                success = self.update_whitelist_from_server(force_full_sync=force_full)

                if success:
                    if consecutive_failures > 0:
                        logger.info(
                            "🎉 Sync recovered after %d failures", consecutive_failures
                        )
                    consecutive_failures = 0

                    if self.domains:
                        self._resolve_all_ips_parallel(force_refresh=False)
                else:
                    consecutive_failures += 1
                    logger.warning(" Sync failed (attempt %d)", consecutive_failures)

                if consecutive_failures == 0:
                    sleep_interval = self.update_interval
                else:
                    sleep_interval = min(
                        self.retry_interval * (2 ** (consecutive_failures - 1)),
                        300,
                    )
                    logger.info("⏳ Will retry in %ds due to failures", sleep_interval)

                if self._stop_event.wait(sleep_interval):
                    break

            except Exception as exc:
                consecutive_failures += 1
                logger.error("Error in sync loop: %s", exc)
                if self._stop_event.wait(self.retry_interval):
                    break

        logger.debug("Sync loop stopped")

    def _ip_refresh_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(self.ip_refresh_interval):
                    break

                if self.domains:
                    logger.debug(" Performing periodic parallel IP refresh...")
                    old_ips = self.current_resolved_ips.copy()

                    self._resolve_all_ips_parallel(force_refresh=True)

                    if old_ips != self.current_resolved_ips:
                        logger.info(
                            "📍 IP changes during refresh: %d → %d",
                            len(old_ips),
                            len(self.current_resolved_ips),
                        )
                        if self.firewall_manager and self.auto_sync_firewall:
                            try:
                                self.firewall_manager.sync_whitelist_changes(
                                    old_ips,
                                    self.current_resolved_ips,
                                )
                            except Exception as exc:
                                logger.error(
                                    "Error syncing firewall during IP refresh: %s", exc
                                )
                    else:
                        logger.debug("No IP changes during refresh")

            except Exception as exc:
                logger.error("Error in IP refresh loop: %s", exc)
                if self._stop_event.wait(60):
                    break

        logger.debug("IP refresh loop stopped")

    def _cache_cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                if self._stop_event.wait(self._cache_cleanup_interval):
                    break

                cleaned = self.cache_manager.bulk_cleanup_expired()
                if cleaned > 0:
                    logger.debug(
                        "🧹 Periodic cache cleanup: %d expired entries removed", cleaned
                    )

            except Exception as exc:
                logger.error("Error in cache cleanup loop: %s", exc)
                if self._stop_event.wait(60):
                    break

        logger.debug("Cache cleanup loop stopped")

    def stop_periodic_updates(self) -> None:
        if not self._running:
            return

        logger.info(" Stopping periodic updates...")
        self._stop_event.set()
        self._running = False

        threads_to_join = [
            (self._update_thread, "Sync thread"),
            (self._ip_refresh_thread, "IP refresh thread"),
            (self._cache_cleanup_thread, "Cache cleanup thread"),
        ]

        for thread, name in threads_to_join:
            if thread and thread.is_alive():
                thread.join(timeout=5)
                if thread.is_alive():
                    logger.warning("%s did not shutdown cleanly", name)

        self.dns_resolver.shutdown()
        self._save_state()

        logger.info(" High-performance periodic updates stopped")

    # ------------------------------------------------------------------
    # Monitoring and status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict:
        cache_stats = self.cache_manager.get_stats()
        sync_health = self.sync_monitor.get_sync_health()

        with self._stats_lock:
            stats_copy = self.stats.copy()

        sync_in_progress_check = not self.sync_in_progress.acquire(blocking=False)
        if not sync_in_progress_check:
            self.sync_in_progress.release()

        return {
            "domains_count": len(self.domains),
            "resolved_ips_count": len(self.current_resolved_ips),
            "last_updated": self._timestamp_to_iso(self.last_updated)
            if self.last_updated
            else None,
            "last_successful_sync": self._timestamp_to_iso(self.last_successful_sync)
            if self.last_successful_sync
            else None,
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
            "dns_available": True,
            "performance_mode": "high_performance_lru_parallel_dns_fixed",
            "current_time": now_iso(),
        }

    def get_sync_health(self) -> Dict:
        return self.sync_monitor.get_sync_health()

    def get_recent_errors(self, limit: int = 5) -> List[Dict]:
        return self.sync_monitor.get_recent_errors(limit)

    def force_refresh(self) -> bool:
        logger.info(" Forcing complete refresh...")

        try:
            sync_success = self.update_whitelist_from_server(force_full_sync=True)

            if sync_success and self.domains:
                ip_success = self._resolve_all_ips_parallel(force_refresh=True)

                if ip_success:
                    logger.info(" Force refresh completed successfully")
                    return True

                logger.warning(" Force refresh: domains synced but IP resolution failed")
                return True

            logger.error(" Force refresh failed - sync unsuccessful")
            return False

        except Exception as exc:
            logger.error(" Error during force refresh: %s", exc)
            return False

    # ------------------------------------------------------------------
    # Domain details API
    # ------------------------------------------------------------------

    def get_domain_details(self, domain: str = None) -> Dict:
        if domain:
            domain = self._normalize_domain(domain)
            if domain not in self.domains:
                wildcard_variant = f"*.{domain}" if not domain.startswith("*.") else domain
                if wildcard_variant in self.domains:
                    domain = wildcard_variant
                else:
                    return {"error": "Domain not in whitelist"}

            metadata = self._get_domain_metadata(domain)
            targets = self._get_resolution_targets(domain)

            target_details: List[Dict] = []
            aggregated_ipv4: Set[str] = set()
            aggregated_ipv6: Set[str] = set()
            cnames: Set[str] = set()
            ttl_values: List[int] = []
            cache_ages: List[float] = []

            for target in targets:
                record = self.cache_manager.get(target)
                if not record and target.startswith("*."):
                    record = self.cache_manager.get(target[2:])
                if record:
                    aggregated_ipv4.update(record.ipv4)
                    aggregated_ipv6.update(record.ipv6)
                    if record.cname:
                        cnames.add(record.cname)
                    ttl_values.append(record.ttl)
                    age = cache_age(record.resolved_at)
                    cache_ages.append(age)
                    target_details.append(
                        {
                            "target": target,
                            "resolved_target": target[2:]
                            if target.startswith("*.")
                            else target,
                            "ipv4_addresses": list(record.ipv4),
                            "ipv6_addresses": list(record.ipv6),
                            "cname": record.cname,
                            "ttl": record.ttl,
                            "cache_age": age,
                            "resolved_at": record.resolved_at,
                        }
                    )

            if target_details:
                return {
                    "domain": domain,
                    "in_whitelist": True,
                    "includes": metadata.get("includes", []),
                    "ipv4_addresses": sorted(aggregated_ipv4),
                    "ipv6_addresses": sorted(aggregated_ipv6),
                    "cname": next(iter(cnames)) if cnames else None,
                    "cnames": sorted(cnames),
                    "total_ips": len(aggregated_ipv4) + len(aggregated_ipv6),
                    "cache_age": min(cache_ages) if cache_ages else -1,
                    "ttl": min(ttl_values) if ttl_values else 0,
                    "cache_valid": True,
                    "targets": target_details,
                }
            else:
                return {
                    "domain": domain,
                    "in_whitelist": True,
                    "includes": metadata.get("includes", []),
                    "ipv4_addresses": [],
                    "ipv6_addresses": [],
                    "cname": None,
                    "cnames": [],
                    "total_ips": 0,
                    "cache_age": -1,
                    "ttl": 0,
                    "cache_valid": False,
                    "targets": [],
                }

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
            "last_updated": self._timestamp_to_iso(self.last_updated)
            if self.last_updated
            else None,
            "last_successful_sync": self._timestamp_to_iso(self.last_successful_sync)
            if self.last_successful_sync
            else None,
            "startup_sync_completed": self.startup_sync_completed,
            "auto_sync_enabled": self.auto_sync_enabled,
            "current_server": self.server_url,
            "server_index": self.current_server_index,
            "total_servers": len(self.server_urls),
            "performance_mode": "high_performance_lru_parallel_dns_fixed",
            "current_time": now_iso(),
            "dns_available": True,
        }