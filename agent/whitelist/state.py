import hashlib
import json
import logging
import threading
from typing import Any, Dict, Optional, Set

from shared.time_utils import now,now_server_compatible
from shared.whitelist_values import canonicalize_whitelist_entry, normalize_whitelist_host

logger = logging.getLogger("whitelist.state")


class WhitelistState:
    def __init__(self):

        self._lock = threading.RLock()
        self._domains: Set[str] = set()
        self._patterns: Set[str] = set()
        self._ips: Set[str] = set()
        self._last_updated: Optional[float] = None
        self._version: str = ""
        self._group_version: str = ""
        self._group_id: str = ""
        self._policy_mode: str = "none"
        self._checksum: str = ""
        self._metadata: Dict[str, Any] = {}
    
    def _parse_entries(self, data: Dict):
        """Parse domains/ips from server response into sets."""
        new_domains = set()
        new_patterns = set()
        new_ips = set()

        for item in data.get("domains", []):
            if isinstance(item, str):
                value = item
                entry_type = "domain"
            elif isinstance(item, dict):
                value = item.get("value", "")
                if not value:
                    value = item.get("domain", "")
                entry_type = item.get("type", "domain").lower()
            else:
                continue

            entry_type, value = canonicalize_whitelist_entry(entry_type, value)
            if not entry_type or not value:
                continue

            if entry_type == "ip":
                new_ips.add(value)
            elif entry_type == "pattern":
                new_patterns.add(value)
            else:
                new_domains.add(value)

        for ip in data.get("ips", []):
            if isinstance(ip, str):
                entry_type, ip_value = canonicalize_whitelist_entry("ip", ip)
                if entry_type == "ip" and ip_value:
                    new_ips.add(ip_value)
            elif isinstance(ip, dict):
                entry_type, ip_value = canonicalize_whitelist_entry(
                    "ip",
                    ip.get("value", ip.get("ip", "")),
                )
                if entry_type == "ip" and ip_value:
                    new_ips.add(ip_value)

        return new_domains, new_patterns, new_ips

    def update(self, data: Dict) -> bool:

        with self._lock:
            try:
                up_to_date = data.get("up_to_date", False)

                # Detect group change - if agent moved to a different group,
                # force full sync even if server says up_to_date
                new_group_id = str(data.get("group_id", ""))
                group_changed = (self._group_id and new_group_id
                                 and new_group_id != self._group_id)
                if group_changed:
                    logger.info(f"Group changed: {self._group_id} -> {new_group_id}, forcing full sync")

                # Server says we're already up to date - no changes needed
                if up_to_date and not group_changed:
                    logger.debug("Server says up_to_date, no changes")
                    return False

                new_domains, new_patterns, new_ips = self._parse_entries(data)

                logger.debug(f"Parsed from server: {len(new_domains)} domains, "
                           f"{len(new_patterns)} patterns, {len(new_ips)} IPs")

                # Full sync: REPLACE entire state
                if (not group_changed
                    and new_domains == self._domains
                    and new_patterns == self._patterns
                    and new_ips == self._ips):
                    logger.debug("No changes in whitelist data")
                    self._version = str(data.get("global_version", data.get("version", self._version)))
                    self._group_version = str(data.get("group_version", self._group_version))
                    self._group_id = new_group_id
                    return False

                self._domains = new_domains
                self._patterns = new_patterns
                self._ips = new_ips

                # Update metadata
                self._last_updated = now()
                self._version = str(data.get("global_version", data.get("version", "")))
                self._group_version = str(data.get("group_version", ""))
                self._group_id = new_group_id
                self._policy_mode = data.get("policy_mode", "none")
                self._checksum = self._calculate_checksum()
                self._metadata = data.get("metadata", {})

                logger.info(
                    f"Whitelist updated: {len(self._domains)} domains, "
                    f"{len(self._patterns)} patterns, {len(self._ips)} IPs "
                    f"[v{self._version}/g{self._group_version}]"
                )
                return True

            except Exception as e:
                logger.error(f"Failed to update whitelist state: {e}", exc_info=True)
                return False
    
    def _calculate_checksum(self) -> str:
        """Calculate checksum of current state."""
        data = json.dumps({
            "domains": sorted(self._domains),
            "patterns": sorted(self._patterns),
            "ips": sorted(self._ips)
        }, sort_keys=True)
        return hashlib.md5(data.encode()).hexdigest()
    
    def is_domain_allowed(self, domain: str) -> bool:

        with self._lock:
            domain = normalize_whitelist_host(domain)
            if not domain:
                return False
            
            # Direct match
            if domain in self._domains:
                return True
            
            # Pattern match
            import fnmatch
            for pattern in self._patterns:
                if fnmatch.fnmatch(domain, pattern):
                    return True
            
            # Subdomain match
            parts = domain.split(".")
            for i in range(len(parts)):
                parent = ".".join(parts[i:])
                if parent in self._domains:
                    return True
            
            return False
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if IP is in whitelist."""
        with self._lock:
            return ip in self._ips
    
    def get_stats(self) -> Dict:
        """Get whitelist statistics."""
        with self._lock:
            return {
                "domains_count": len(self._domains),
                "patterns_count": len(self._patterns),
                "ips_count": len(self._ips),
                "last_updated": now_server_compatible(self._last_updated) if self._last_updated else None,
                "version": self._version,
                "checksum": self._checksum
            }
    
    def get_all_domains(self) -> Set[str]:
        with self._lock:
            return self._domains.copy()
    
    def get_all_patterns(self) -> Set[str]:
        with self._lock:
            return self._patterns.copy()
    
    def get_all_ips(self) -> Set[str]:
        with self._lock:
            return self._ips.copy()

    def remove_ip(self, ip: str) -> bool:
        """Remove an IP from the state safely."""
        with self._lock:
            if ip in self._ips:
                self._ips.remove(ip)
                return True
            return False
    
    def clear(self) -> None:
        with self._lock:
            self._domains.clear()
            self._patterns.clear()
            self._ips.clear()
            self._last_updated = None
            self._version = ""
            self._checksum = ""
            self._metadata.clear()
