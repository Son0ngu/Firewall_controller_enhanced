import logging
import platform
import socket
from typing import Dict, Optional

import netifaces

from shared.time_utils import now, now_iso, now_server_compatible, is_cache_valid, cache_age

logger = logging.getLogger("utils.ip_detector")


class IPDetector:

    def __init__(self):
        self._cached_local_ip: Optional[str] = None
        self._cached_admin_status: Optional[bool] = None
        self._last_ip_check: float = 0
        self._ip_cache_ttl: int = 300  # 5 minutes
    
    def get_local_ip(self, force_refresh: bool = False) -> str:
        """Get local IP address with caching."""
        current_time = now()
        
        # Use cache validation
        if (not force_refresh and
            self._cached_local_ip and
            is_cache_valid(self._last_ip_check, self._ip_cache_ttl)):
            
            age = cache_age(self._last_ip_check)
            logger.debug(f"IP cache hit: {self._cached_local_ip} (age: {age:.1f}s)")
            return self._cached_local_ip
        
        # Log cache miss reason
        if force_refresh:
            logger.debug("IP cache miss: force refresh requested")
        elif not self._cached_local_ip:
            logger.debug("IP cache miss: no cached value")
        else:
            age = cache_age(self._last_ip_check)
            logger.debug(f"IP cache miss: expired (age: {age:.1f}s > {self._ip_cache_ttl}s)")
        
        # Method 1: Use the OS default IPv4 gateway/interface. This avoids
        # hardcoding any public resolver just to discover our local address.
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)
            if default_gateway:
                _gateway_ip, interface = default_gateway[:2]
                addresses = netifaces.ifaddresses(interface)
                for addr in addresses.get(netifaces.AF_INET, []):
                    local_ip = addr.get("addr")
                    if local_ip and not local_ip.startswith(("127.", "169.254.")):
                        self._cached_local_ip = local_ip
                        self._last_ip_check = current_time
                        logger.debug(
                            f"Detected local IP (default interface): "
                            f"{local_ip} at {now_iso()}"
                        )
                        return local_ip
        except Exception as e:
            logger.debug(f"Default interface detection failed: {e}")

        # Method 2: Hostname resolution
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            if local_ip and local_ip != "127.0.0.1":
                self._cached_local_ip = local_ip
                self._last_ip_check = current_time
                logger.debug(f"Detected local IP (hostname): {local_ip} at {now_iso()}")
                return local_ip
        except Exception as e:
            logger.debug(f"Hostname IP detection failed: {e}")
        
        # Method 3: Network interfaces with netifaces
        try:
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr['addr']
                        # Skip loopback and link-local addresses
                        if not ip.startswith(('127.', '169.254.')):
                            self._cached_local_ip = ip
                            self._last_ip_check = current_time
                            logger.debug(f"Detected local IP (interface scan): {ip} at {now_iso()}")
                            return ip
        except Exception as e:
            logger.debug(f"Interface scan IP detection failed: {e}")
        
        # Fallback
        logger.warning("Could not detect local IP, using localhost")
        self._cached_local_ip = "127.0.0.1"
        self._last_ip_check = current_time
        return "127.0.0.1"
    
    def get_admin_status(self, force_refresh: bool = False) -> bool:
        if not force_refresh and self._cached_admin_status is not None:
            return self._cached_admin_status
        
        try:
            if platform.system() == "Windows":
                import ctypes
                admin_status = bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                import os
                admin_status = os.geteuid() == 0
            
            self._cached_admin_status = admin_status
            logger.debug(f"Admin privileges: {admin_status}")
            return admin_status
            
        except Exception as e:
            logger.warning(f"Could not check admin privileges: {e}")
            self._cached_admin_status = False
            return False
    
    def get_cache_debug_info(self) -> Dict:
        return {
            "cached_ip": self._cached_local_ip,
            "last_check_timestamp": self._last_ip_check,
            "last_check_iso": now_server_compatible(self._last_ip_check) if self._last_ip_check > 0 else "never",
            "cache_age": cache_age(self._last_ip_check) if self._last_ip_check > 0 else -1,
            "ttl": self._ip_cache_ttl,
            "cache_valid": is_cache_valid(self._last_ip_check, self._ip_cache_ttl)
        }


# Global IP detector instance
_ip_detector = IPDetector()


def get_local_ip(force_refresh: bool = False) -> str:
    return _ip_detector.get_local_ip(force_refresh)


def check_admin_privileges(force_refresh: bool = False) -> bool:
    return _ip_detector.get_admin_status(force_refresh)


def get_ip_detector() -> IPDetector:
    return _ip_detector
