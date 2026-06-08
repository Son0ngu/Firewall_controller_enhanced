import logging
import threading
from typing import Callable, Dict, List

logger = logging.getLogger("controllers.whitelist_controller")


class WhitelistController:

    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        
        # Callbacks for UI updates
        self._on_data_changed: List[Callable[[List[Dict]], None]] = []
        self._on_error: List[Callable[[str], None]] = []
        self._on_success: List[Callable[[str], None]] = []
        
        # Local IP list (for UI display - actual whitelist is managed by WhitelistManager)
        self._local_ips: Dict[str, Dict] = {}
        self._lock_data = threading.RLock()
        
        # Reference to Agent's whitelist manager
        self._whitelist_manager = None
        
        logger.info("WhitelistController initialized")
    
    def set_whitelist_manager(self, manager) -> None:
   
        self._whitelist_manager = manager
        
        # Register callback to be notified when sync completes (periodic sync)
        if hasattr(manager, 'on_sync_complete'):
            manager.on_sync_complete(self._on_manager_sync_complete)
        
        # First sync from current manager state (cached data)
        self._sync_from_manager()
        
        # Then trigger immediate server sync in background
        # This ensures fresh data is loaded from server right away
        self._trigger_server_sync()
        
        logger.info("WhitelistController connected to WhitelistManager")
    
    def _on_manager_sync_complete(self) -> None:
        """Called when WhitelistManager completes a sync (including periodic syncs)."""
        logger.info("Manager sync complete, updating GUI...")
        self._sync_from_manager()
    
    def _trigger_server_sync(self) -> None:
        """Trigger immediate sync with server in background."""
        if not self._whitelist_manager:
            return
            
        def do_sync():
            try:
                logger.info("Triggering immediate whitelist sync from server...")
                if hasattr(self._whitelist_manager, 'sync_now'):
                    success = self._whitelist_manager.sync_now()
                    if success:
                        # Sync complete, update UI with fresh data
                        self._sync_from_manager()
                        logger.info("Immediate whitelist sync completed")
                    else:
                        logger.warning("Immediate whitelist sync failed")
            except Exception as e:
                logger.error(f"Error in immediate sync: {e}")
        
        # Run in background thread to not block UI
        threading.Thread(target=do_sync, daemon=True, name="ImmediateWhitelistSync").start()
    
    def _sync_from_manager(self) -> None:
        """Sync local list from WhitelistManager (domains + IPs)."""
        if not self._whitelist_manager:
            return
        
        try:
            if hasattr(self._whitelist_manager, '_state'):
                state = self._whitelist_manager._state
                
                with self._lock_data:
                    # Clear ALL existing server entries (case-insensitive check)
                    self._local_ips = {k: v for k, v in self._local_ips.items() 
                                      if v.get("source", "").lower() != "server"}
                    
                    # Get domains from manager's state
                    domains = state.get_all_domains()
                    for domain in domains:
                        key = f"domain:{domain}"
                        self._local_ips[key] = {
                            "ip": domain,
                            "type": "Domain",
                            "status": "Active",
                            "source": "Server",
                        }
                    
                    # Get patterns (wildcards) from manager's state
                    patterns = state.get_all_patterns()
                    for pattern in patterns:
                        key = f"pattern:{pattern}"
                        self._local_ips[key] = {
                            "ip": pattern,
                            "type": "Pattern",
                            "status": "Active",
                            "source": "Server",
                        }
                    
                    # Get IPs from manager's state
                    ips = state.get_all_ips()
                    for ip in ips:
                        key = f"ip:{ip}"
                        self._local_ips[key] = {
                            "ip": ip,
                            "type": "IP",
                            "status": "Active",
                            "source": "Server",
                        }
                
                total = len(domains) + len(patterns) + len(ips)
                logger.info(f"Synced from manager: {len(domains)} domains, {len(patterns)} patterns, {len(ips)} IPs")
                self._notify_data_changed()
                
        except Exception as e:
            logger.error(f"Failed to sync from manager: {e}")
    
    # ========== Callbacks Registration ==========
    
    def on_data_changed(self, callback: Callable[[List[Dict]], None]) -> None:
        """Register callback for data changes."""
        if callback not in self._on_data_changed:
            self._on_data_changed.append(callback)
    
    def on_error(self, callback: Callable[[str], None]) -> None:
        """Register callback for errors."""
        if callback not in self._on_error:
            self._on_error.append(callback)
    
    def on_success(self, callback: Callable[[str], None]) -> None:
        """Register callback for success messages."""
        if callback not in self._on_success:
            self._on_success.append(callback)
    
    def _notify_data_changed(self) -> None:
        """Notify all data changed listeners."""
        data = self.get_all_ips()
        for callback in self._on_data_changed:
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Error in data changed callback: {e}")
    
    def _notify_error(self, message: str) -> None:
        """Notify all error listeners."""
        for callback in self._on_error:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Error in error callback: {e}")
    
    def _notify_success(self, message: str) -> None:
        """Notify all success listeners."""
        for callback in self._on_success:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Error in success callback: {e}")
    
    def remove_ip(self, ip: str) -> bool:
        normalized_ip = ip.strip()
        local_key = normalized_ip
        if local_key not in self._local_ips:
            candidate_key = f"ip:{normalized_ip}"
            if candidate_key in self._local_ips:
                local_key = candidate_key
            else:
                self._notify_error(f"IP not found: {normalized_ip}")
                return False
        
        with self._lock_data:
            if local_key not in self._local_ips:
                self._notify_error(f"IP not found: {normalized_ip}")
                return False
        
        def remove_worker():
            try:
                # Remove from local list
                with self._lock_data:
                    if local_key in self._local_ips:
                        del self._local_ips[local_key]
                
                # If WhitelistManager supports removing IPs, call it
                if self._whitelist_manager:
                    if hasattr(self._whitelist_manager, 'remove_ip'):
                        self._whitelist_manager.remove_ip(
                            normalized_ip[3:] if normalized_ip.startswith("ip:") else normalized_ip
                        )
                    elif hasattr(self._whitelist_manager, '_state'):
                        # Fallback (though manager should have remove_ip now)
                        if hasattr(self._whitelist_manager._state, 'remove_ip'):
                             self._whitelist_manager._state.remove_ip(
                                 normalized_ip[3:] if normalized_ip.startswith("ip:") else normalized_ip
                             )
                        else: 
                             self._whitelist_manager._state._ips.discard(
                                 normalized_ip[3:] if normalized_ip.startswith("ip:") else normalized_ip
                             )
                
                self._notify_data_changed()
                self._notify_success(f"IP removed: {normalized_ip}")
                logger.info(f"IP removed from whitelist: {normalized_ip}")
                
            except Exception as e:
                self._notify_error(f"Failed to remove IP: {e}")
                logger.error(f"Failed to remove IP {normalized_ip}: {e}")
        
        # Run in thread
        thread = threading.Thread(target=remove_worker, daemon=True)
        thread.start()
        return True
    
    def get_all_ips(self) -> List[Dict]:
     
        with self._lock_data:
            return list(self._local_ips.values())
    
    def refresh(self) -> None:
        """Refresh whitelist data from manager."""
        def refresh_worker():
            try:
                # Force sync with server
                if self._whitelist_manager:
                    if hasattr(self._whitelist_manager, 'force_refresh'):
                        self._whitelist_manager.force_refresh()
                    elif hasattr(self._whitelist_manager, 'sync_now'):
                        self._whitelist_manager.sync_now()
                
                # Sync local list
                self._sync_from_manager()
                
                self._notify_success("Whitelist refreshed")
                logger.info("Whitelist refreshed")
                
            except Exception as e:
                self._notify_error(f"Refresh failed: {e}")
                logger.error(f"Whitelist refresh failed: {e}")
        
        thread = threading.Thread(target=refresh_worker, daemon=True)
        thread.start()
    
    def get_stats(self) -> Dict:
        """Get whitelist statistics."""
        with self._lock_data:
            # Count by type
            domains = sum(1 for ip in self._local_ips.values() if ip.get("type") == "Domain")
            patterns = sum(1 for ip in self._local_ips.values() if ip.get("type") == "Pattern")
            ips = sum(1 for ip in self._local_ips.values() if ip.get("type") == "IP")
            
            stats = {
                "total_ips": len(self._local_ips),
                "active": sum(1 for ip in self._local_ips.values() if ip.get("status") == "Active"),
                "pending": sum(1 for ip in self._local_ips.values() if ip.get("status") == "Pending"),
                "local": sum(1 for ip in self._local_ips.values() if ip.get("source") == "Local"),
                "server": sum(1 for ip in self._local_ips.values() if ip.get("source") == "Server"),
                "manager_domains": domains,
                "manager_ips": ips + patterns,
            }
        
        # Get stats from manager if available
        if self._whitelist_manager:
            if hasattr(self._whitelist_manager, 'get_stats'):
                manager_stats = self._whitelist_manager.get_stats()
                stats.update({
                    "sync_count": manager_stats.get("sync_count", 0),
                })
        
        return stats


# Convenience function
def get_whitelist_controller() -> WhitelistController:
    """Get WhitelistController singleton instance."""
    return WhitelistController()
