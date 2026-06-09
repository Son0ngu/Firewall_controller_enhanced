import atexit
import json
import logging
import queue
import random
import socket
import threading
import uuid
from typing import Any, Dict, List, Optional

import requests

from shared.time_utils import now, now_iso, sleep
from shared.server_urls import collect_server_urls
from core.token_manager import get_auth_headers

logger = logging.getLogger("logging.sender")


class LogSender:
    
    def __init__(self, config: Dict):

        self.config = config 
        
        # Server configuration
        self.server_urls = self._get_server_urls(config)
        
        # Queue configuration
        self.max_queue_size = config.get("max_queue_size", 1000)
        self.batch_size = config.get("batch_size", 100)
        self.send_interval = config.get("send_interval", 2)
        
        self.log_queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        self.running = False
        self._sender_thread: Optional[threading.Thread] = None
        
        self.agent_id = config.get("agent_id") or self._generate_agent_id()
        
        self.last_send_time = now()
        self._send_lock = threading.Lock()

        # Backoff state. ``_consecutive_send_failures`` drives an exponential
        # backoff with full jitter so a downed server doesn't get hammered
        # every ``send_interval`` (was: ~every 2 s). Reset to zero on the
        # next successful batch.
        self._consecutive_send_failures = 0
        self._logs_sent = 0
        self._next_send_allowed_at: float = now()
        self.max_retry_interval = config.get("max_retry_interval", 300)

        # atexit guard. The sender thread is a daemon so the process can
        # exit cleanly, but daemon threads are *killed* mid-call when the
        # interpreter shuts down. atexit handlers run *before* daemon
        # threads are torn down, so registering one here lets us flush the
        # in-memory queue even if lifecycle.cleanup() didn't run (hard
        # crash, SIGTERM from a service manager, etc.).
        self._atexit_registered = False

        logger.info(f"LogSender initialized with agent_id: {self.agent_id}")
        if self.server_urls:
            logger.info(f"Will send logs to: {', '.join(self.server_urls)}")
        else:
            logger.warning("LogSender starting in OFFLINE mode (no server URL configured)")

    def _get_server_urls(self, config: Dict) -> List[str]:
        """Use the shared resolver — empty list means offline (no localhost fallback)."""
        return collect_server_urls(config, allow_dev_default=False)
    
    def start(self) -> None:
        if self.running:
            return

        self.running = True
        self._sender_thread = threading.Thread(
            target=self._sender_loop,
            daemon=True,
            name="LogSender"
        )
        self._sender_thread.start()
        # Register once. atexit handlers run in LIFO order before daemon
        # threads are killed, so this is the last-chance flush.
        if not self._atexit_registered:
            atexit.register(self._atexit_flush)
            self._atexit_registered = True
        logger.info("Log sender started")

    def _atexit_flush(self) -> None:
        """Safety-net flush on interpreter shutdown.

        Idempotent with ``stop()``: if cleanup already ran (``self.running``
        is False and the queue is empty) this is a no-op. Otherwise we
        attempt one last batch send so structured logs (especially the
        ``agent_shutdown`` lifecycle event) reach the server.
        """
        try:
            if self.running:
                self.running = False
            if not self.log_queue.empty():
                logger.debug("atexit: flushing %d pending log(s)", self.log_queue.qsize())
                self._flush_queue()
        except Exception as e:  # noqa: BLE001 — atexit must never raise
            # We're past the point where the normal logger may still work
            # (handlers can be torn down before atexit runs). Use stderr
            # as a best-effort.
            try:
                import sys
                print(f"LogSender atexit flush failed: {e}", file=sys.stderr)
            except Exception:
                pass
    
    def stop(self) -> None:
        """Stop sender and flush remaining logs."""
        if not self.running:
            return
        
        self.running = False
        
        if self._sender_thread:
            try:
                self._flush_queue()
            except Exception as e:
                logger.error(f"Error flushing logs: {e}")
            
            self._sender_thread.join(timeout=5)
        
        logger.info("Log sender stopped")
    
    def queue_log(self, log_data: Dict) -> bool:
        try:
            serialized_log = self._serialize_log(log_data.copy())
            
            if "agent_id" not in serialized_log:
                serialized_log["agent_id"] = self.agent_id
            
            if "timestamp" not in serialized_log:
                serialized_log["timestamp"] = now_iso()
            
            self.log_queue.put_nowait(serialized_log)
            return True
            
        except queue.Full:
            logger.warning("Log queue is full, dropping log")
            return False
        except Exception as e:
            logger.error(f"Error queueing log: {e}")
            return False
    
    def _serialize_log(self, log_data: Dict) -> Dict:
        """Serialize log data for JSON transmission."""
        serialized = {}
        
        for key, value in log_data.items():
            if hasattr(value, 'isoformat'):
                serialized[key] = value.isoformat()
            elif isinstance(value, dict):
                serialized[key] = self._serialize_log(value)
            elif isinstance(value, list):
                serialized[key] = [
                    item.isoformat() if hasattr(item, 'isoformat')
                    else (self._serialize_log(item) if isinstance(item, dict) else item)
                    for item in value
                ]
            elif value is None:
                serialized[key] = "unknown"
            else:
                serialized[key] = value
        
        # Check if this is a lifecycle event (startup/shutdown)
        is_lifecycle = serialized.get("is_lifecycle_event", False)
        
        # Ensure essential fields
        essential_fields = {
            "timestamp": now_iso(),
            "agent_id": self.agent_id,
            "level": "INFO",
            "action": "UNKNOWN",
            "message": "Log entry"
        }
        
        # Network-related fields - only set defaults for non-lifecycle events
        if not is_lifecycle:
            network_fields = {
                "domain": "unknown",
                "destination": "unknown",
                "source_ip": "unknown",
                "dest_ip": "unknown",
                "protocol": "unknown",
                "port": "unknown"
            }
            essential_fields.update(network_fields)
        
        for field, default in essential_fields.items():
            if field not in serialized or not serialized[field]:
                serialized[field] = default
        
        return serialized
    
    def _sender_loop(self) -> None:
        """Main sender loop."""
        while self.running:
            try:
                current_time = now()
                queue_size = self.log_queue.qsize()

                should_send = (
                    queue_size >= self.batch_size or
                    (queue_size > 0 and (current_time - self.last_send_time) >= self.send_interval)
                )

                # Backoff gate: if a previous batch failed we delay the next
                # attempt. ``_next_send_allowed_at`` is bumped by
                # ``_send_batch`` on failure; ``should_send`` would otherwise
                # fire on every send_interval and hammer the server.
                if should_send and current_time >= self._next_send_allowed_at:
                    self._send_logs()
                    self.last_send_time = current_time

                sleep(1)

            except Exception as e:
                logger.error(f"Error in sender loop: {e}")
                sleep(5)

    def _record_send_failure(self) -> None:
        """Advance backoff after a failed batch.

        Full-jitter exponential backoff capped at ``max_retry_interval``,
        same recipe as HeartbeatSender. Implementation note: we set an
        absolute wall-clock deadline rather than sleeping inside this call
        so the sender loop stays responsive to ``stop()`` and to new
        high-priority logs that bypass the gate on the next iteration.
        """
        self._consecutive_send_failures += 1
        attempt = max(0, self._consecutive_send_failures - 1)
        base = max(1, int(self.send_interval))
        cap = max(base, int(self.max_retry_interval))
        exp = min(cap, base * (2 ** attempt))
        delay = random.uniform(0, exp)
        self._next_send_allowed_at = now() + delay
        logger.debug(
            f"Log send backoff: next attempt in {delay:.1f}s "
            f"(consecutive failures={self._consecutive_send_failures})"
        )

    def _record_send_success(self) -> None:
        """Reset backoff on a successful batch."""
        if self._consecutive_send_failures:
            logger.info(
                f"Log send recovered after {self._consecutive_send_failures} failure(s)"
            )
        self._consecutive_send_failures = 0
        self._next_send_allowed_at = now()
    
    def _flush_queue(self) -> None:
        logs = []
        try:
            while not self.log_queue.empty():
                logs.append(self.log_queue.get_nowait())
                self.log_queue.task_done()
        except queue.Empty:
            pass
        
        if logs:
            self._send_batch(logs)
    
    def _send_logs(self) -> None:
        logs = []
        batch_size = min(self.batch_size, self.log_queue.qsize())
        
        for _ in range(batch_size):
            try:
                log = self.log_queue.get_nowait()
                logs.append(log)
                self.log_queue.task_done()
            except queue.Empty:
                break
        
        if logs:
            self._send_batch(logs)
    
    def _send_batch(self, logs: List[Dict]) -> bool:
        if not self.server_urls:
            # Offline mode: drop the batch silently. The caller already
            # logged the OFFLINE state once at startup.
            logger.debug("Skipping log batch — agent in OFFLINE mode")
            return False
        
        serialized_logs = []
        for log in logs:
            try:
                clean_log = self._ensure_serializable(log)
                serialized_logs.append(clean_log)
            except Exception as e:
                logger.error(f"Failed to serialize log: {e}")
                serialized_logs.append({
                    "message": f"Serialization failed: {e}",
                    "level": "error",
                    "timestamp": now_iso(),
                    "agent_id": self.agent_id
                })
        
        try:
            url = f"{self.server_urls[0].rstrip('/')}/api/logs"
            payload = {"logs": serialized_logs}
            
            # Build headers with JWT authentication
            headers = {"Content-Type": "application/json"}
            auth_headers = get_auth_headers(self.config)
            headers.update(auth_headers)
            
            response = requests.post(
                url=url,
                json=payload,
                headers=headers,
                timeout=15
            )
            
            if response.status_code in (200, 201, 202):
                logger.info(f"Sent {len(serialized_logs)} logs to server")
                self._record_send_success()
                self._logs_sent += len(serialized_logs)
                return True
            elif response.status_code == 401:
                logger.warning("Log send authentication failed - token may be expired")
                self._record_send_failure()
                return False
            else:
                logger.error(f"Failed to send logs: HTTP {response.status_code}")
                self._record_send_failure()
                return False

        except requests.exceptions.Timeout:
            logger.error("Timeout sending logs")
            self._record_send_failure()
            return False
        except requests.exceptions.ConnectionError:
            logger.error("Connection error sending logs")
            self._record_send_failure()
            return False
        except Exception as e:
            logger.error(f"Error sending logs: {e}")
            self._record_send_failure()
            return False
    
    def _ensure_serializable(self, obj: Any) -> Any:
        """Ensure object is JSON serializable."""
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {k: self._ensure_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._ensure_serializable(item) for item in obj]
        elif isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        else:
            return str(obj)
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent identifier."""
        import platform
        
        hostname = socket.gethostname()
        system_info = platform.system() + platform.release()
        mac = ':'.join([
            f'{(uuid.getnode() >> elements) & 0xff:02x}'
            for elements in range(0, 12, 2)
        ][::-1])
        
        return f"{hostname}-{mac}"
    
    def get_status(self) -> Dict:
        """Get sender status."""
        return {
            "running": self.running,
            "agent_id": self.agent_id,
            "queue_size": self.log_queue.qsize(),
            "logs_sent": self._logs_sent,
            "max_queue_size": self.max_queue_size,
            "batch_size": self.batch_size,
            "send_interval": self.send_interval,
            "last_send_time": self.last_send_time,
            "server_urls": self.server_urls,
            "status_timestamp": now_iso()
        }