import atexit
import logging
import platform
import random
import threading
from typing import Dict, Optional

import psutil
import requests

from shared.time_utils import now, now_iso, sleep
from shared.os_info import get_os_details
from shared.server_urls import collect_server_urls
from core.token_manager import get_auth_headers

logger = logging.getLogger("services.heartbeat")


class HeartbeatSender:
    
    def __init__(self, config: Dict):
        self.config = config
        self.heartbeat_config = config.get("heartbeat", {})
        self.server_config = config.get("server", {})
        
        # Settings
        self.enabled = self.heartbeat_config.get("enabled", True)
        self.interval = self.heartbeat_config.get("interval", 20)
        self.timeout = self.heartbeat_config.get("timeout", 10)
        # ``retry_interval`` is the *base* for exponential backoff (was a
        # fixed sleep before). When the server is down we previously hammered
        # it every 5 s; now we double the sleep up to ``max_retry_interval``,
        # with full jitter to break herd effects across agents that came up
        # at the same time. On the next success we reset to the base.
        self.retry_interval = self.heartbeat_config.get("retry_interval", 5)
        self.max_retry_interval = self.heartbeat_config.get("max_retry_interval", 300)
        self.max_failures = self.heartbeat_config.get("max_failures", 3)
        
        # Credentials
        self.agent_id: Optional[str] = None
        self.agent_token: Optional[str] = None
        self.server_urls = self._get_server_urls()
        
        # State
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._consecutive_failures = 0
        self._last_successful_heartbeat: Optional[float] = None
        # See LogSender for the same pattern: daemon thread + atexit safety
        # net to wake the loop on hard exit so the interpreter doesn't
        # block on an in-flight ``requests.post`` for the full timeout.
        self._atexit_registered = False

        # Callback when server requests force sync (policy or whitelist changed)
        self.on_force_sync = None  # Set by caller: fn() -> None
        # Whitelist version getter - set by caller to report current versions in heartbeat
        self.get_whitelist_versions = None  # Set by caller: fn() -> dict
    
    def _get_server_urls(self) -> list:
        """Use the shared resolver — empty list means offline (no fallback to localhost)."""
        return collect_server_urls(self.config, allow_dev_default=False)
    
    def set_agent_credentials(self, agent_id: str, token: str) -> None:
        self.agent_id = agent_id
        self.agent_token = token
    
    def start(self) -> None:
        if not self.enabled:
            logger.info("Heartbeat sender disabled")
            return
        
        auth_headers = get_auth_headers(self.config)
        if not self.agent_id or (not self.agent_token and not auth_headers):
            logger.warning("Cannot start heartbeat - missing agent credentials")
            return
        
        if self._running:
            logger.warning("Heartbeat sender already running")
            return
        
        self._running = True
        self._thread = threading.Thread(
            target=self._heartbeat_loop,
            daemon=True,
            name="HeartbeatSender"
        )
        self._thread.start()
        if not self._atexit_registered:
            atexit.register(self._atexit_stop)
            self._atexit_registered = True
        logger.info(f"Heartbeat sender started (interval: {self.interval}s)")

    def stop(self) -> None:
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Heartbeat sender stopped")

    def _atexit_stop(self) -> None:
        """Signal the loop to exit at interpreter shutdown.

        Heartbeats are idempotent (the server tolerates one being
        missed/duplicated), so we don't try to flush. We only flip the
        ``_running`` flag so the interruptible sleep inside
        ``_heartbeat_loop`` returns within ~1 s instead of blocking on the
        next ``requests.post`` timeout.
        """
        if self._running:
            self._running = False
    
    def _heartbeat_loop(self) -> None:
        while self._running:
            try:
                success = self._send_heartbeat()

                if success:
                    self._consecutive_failures = 0
                    self._last_successful_heartbeat = now()
                    sleep_time = self.interval
                else:
                    self._consecutive_failures += 1
                    if self._consecutive_failures >= self.max_failures:
                        logger.error(
                            f"Too many consecutive heartbeat failures "
                            f"({self._consecutive_failures})"
                        )
                    sleep_time = self._backoff_seconds()

                # Interruptible sleep
                for _ in range(int(sleep_time)):
                    if not self._running:
                        break
                    sleep(1)

            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                sleep(self._backoff_seconds())

    def _backoff_seconds(self) -> float:
        """Capped exponential backoff with full jitter.

        Formula: ``random_uniform(0, min(cap, base * 2**n))`` where ``n`` is
        the consecutive-failure count. This is AWS Architecture Blog's "full
        jitter" recipe — it spreads retries across the whole window so a
        fleet of agents coming back up doesn't thunder on the server. Reset
        to the base happens implicitly by zeroing ``_consecutive_failures``
        on the next success.
        """
        attempt = max(0, self._consecutive_failures - 1)
        cap = max(1, int(self.max_retry_interval))
        exp = min(cap, int(self.retry_interval) * (2 ** attempt))
        return random.uniform(0, exp)
    
    def _send_heartbeat(self) -> bool:
        # Offline mode: no server URL configured. Skip silently — counting
        # this as a failure would spam max_failures and drown the logs.
        if not self.server_urls:
            return True

        metrics = self._collect_metrics()
        os_details = get_os_details()
        
        heartbeat_data = {
            "agent_id": self.agent_id,
            "token": self.agent_token,
            "device_id": self.config.get("device_id"),
            "timestamp": now_iso(),
            "metrics": metrics,
            "status": "active",
            "platform": os_details["platform"],
            "os_info": f"{os_details['name']} {os_details['version']}",
            "agent_version": "1.0.0"
        }

        # Include whitelist versions so server can detect changes
        if self.get_whitelist_versions:
            try:
                versions = self.get_whitelist_versions()
                if versions:
                    heartbeat_data.update(versions)
            except Exception:
                pass
        
        for server_url in self.server_urls:
            try:
                url = f"{server_url.rstrip('/')}/api/agents/heartbeat"
                
                # Build headers with JWT authentication
                headers = {'Content-Type': 'application/json'}
                auth_headers = get_auth_headers(self.config)
                headers.update(auth_headers)
                
                response = requests.post(
                    url,
                    json=heartbeat_data,
                    timeout=self.timeout,
                    headers=headers
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get("success"):
                        logger.debug(f"Heartbeat sent successfully to {server_url}")
                        # Check force_sync flag from server (agent policy changed)
                        resp_data = data.get("data", data)
                        if resp_data.get("force_sync") and self.on_force_sync:
                            logger.info(f"Server requests force sync (policy: {resp_data.get('policy_mode', '?')})")
                            try:
                                self.on_force_sync()
                            except Exception as fs_err:
                                logger.warning(f"Force sync callback failed: {fs_err}")
                        return True
                    else:
                        logger.warning(
                            f"Server rejected heartbeat: {data.get('error', 'Unknown')}"
                        )
                else:
                    logger.warning(f"Heartbeat failed: HTTP {response.status_code}")
                    
            except requests.exceptions.ConnectTimeout:
                logger.debug(f"Connection timeout to {server_url}")
            except requests.exceptions.ConnectionError:
                logger.debug(f"Connection error to {server_url}")
            except Exception as e:
                logger.warning(f"Error sending heartbeat to {server_url}: {e}")
        
        return False
    
    def _collect_metrics(self) -> Dict:
        """Collect system metrics"""
        metrics = {
            "memory_percent": 0,
            "disk_percent": 0,
            "uptime_seconds": 0,
            "timestamp": now_iso()
        }
        
        try:
            mem = psutil.virtual_memory()
            metrics["memory_percent"] = round(mem.percent, 2)
        except Exception:
            pass
        
        try:
            disk_path = "C:\\" if platform.system() == "Windows" else "/"
            disk = psutil.disk_usage(disk_path)
            metrics["disk_percent"] = round(disk.percent, 2)
        except Exception:
            pass
        
        try:
            metrics["uptime_seconds"] = int(now() - psutil.boot_time())
        except Exception:
            pass
        
        return metrics
    
    def get_status(self) -> Dict:
        """Get heartbeat sender status."""
        return {
            "enabled": self.enabled,
            "running": self._running,
            "agent_id": self.agent_id,
            "consecutive_failures": self._consecutive_failures,
            "last_successful_heartbeat": self._last_successful_heartbeat,
            "interval": self.interval,
            "timestamp": now_iso()
        }
