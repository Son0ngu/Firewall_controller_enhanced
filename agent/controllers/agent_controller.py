import logging
import threading
import queue
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("controllers.agent_controller")


class AgentStatus(Enum):
    """Agent status enum."""
    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    # Agent is running but some non-critical components failed to come up
    # (e.g. log_sender / heartbeat / whitelist_sync - usually offline mode).
    DEGRADED = auto()
    STOPPING = auto()
    ERROR = auto()


@dataclass
class AgentEvent:
    """Event data from agent to GUI."""
    event_type: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


class AgentSignals:

    def __init__(self):
        self._callbacks: Dict[str, List[Callable]] = {
            'status_changed': [],
            'packet_captured': [],
            'log_received': [],
            'error_occurred': [],
            'stats_updated': [],
            'whitelist_synced': [],
        }
        self._event_queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
    
    def connect(self, signal_name: str, callback: Callable) -> bool:
        """Connect a callback to a signal."""
        with self._lock:
            if signal_name in self._callbacks:
                self._callbacks[signal_name].append(callback)
                return True
            return False
    
    def disconnect(self, signal_name: str, callback: Callable) -> bool:
        """Disconnect a callback from a signal."""
        with self._lock:
            if signal_name in self._callbacks and callback in self._callbacks[signal_name]:
                self._callbacks[signal_name].remove(callback)
                return True
            return False
    
    def emit(self, signal_name: str, data: Any = None):
        """
        Queue an event to be processed by GUI thread.
        This is thread-safe and won't block.
        """
        event = AgentEvent(
            event_type=signal_name,
            data=data if data else {},
            timestamp=self._get_timestamp()
        )
        self._event_queue.put(event)
    
    # Drain interval. Must be small enough that buffered events feel instant
    # (under one display frame at 60Hz = ~16ms; 50ms is the snappy threshold
    # the human eye still perceives as "immediate"). The previous 500ms made
    # the UI jank as events piled up then released in bursts.
    #
    # These constants remain on AgentSignals so QtSignalBridge can mirror the
    # same values when it sets up its QTimer. Don't change one without the
    # other.
    DRAIN_INTERVAL_MS = 50
    # Soft cap so a flood of events (e.g. packet bursts) can't block the GUI
    # thread by draining the entire queue in one shot. Remaining events get
    # processed on the next tick.
    MAX_EVENTS_PER_TICK = 100

    # process_events(root) and the Tk-style ``root.after(...)`` reschedule
    # used to live here. They are gone. The Qt frontend drains the queue
    # via ``agent.gui_qt.signal_bridge.QtSignalBridge`` (QTimer-backed); no
    # other consumer existed. If a non-Qt frontend ever needs to drain
    # events, build it on top of ``_event_queue.get`` directly rather than
    # reviving the Tk path.

    def _dispatch_event(self, event: AgentEvent):
        """Dispatch event to registered callbacks."""
        with self._lock:
            callbacks = self._callbacks.get(event.event_type, []).copy()
        
        for callback in callbacks:
            try:
                callback(event.data)
            except Exception as e:
                logger.error(f"Error in callback for {event.event_type}: {e}")
    
    def _get_timestamp(self) -> float:
        """Get current timestamp."""
        try:
            from shared.time_utils import now
            return now()
        except ImportError:
            import time
            return time.time()


class AgentController:
    """Controller wrapping the agent worker thread + Qt-facing signals.

    Singleton via ``__new__`` because the GUI, lifecycle, and several
    standalone scripts all assume "the controller" rather than passing one
    around. That contract is fine for production but hostile to tests —
    use :meth:`reset_for_test` between test cases when isolation matters.
    Long-term migration is towards constructor injection (an ``AgentRuntime``
    instance the GUI receives), but that's a much bigger surgery.
    """

    _instance: Optional['AgentController'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @classmethod
    def reset_for_test(cls) -> None:
        """Drop the singleton so the next constructor returns a fresh one.

        Production code never calls this. Tests use it instead of monkey-
        patching ``_instance`` and ``_initialized`` from outside. Pair with
        :meth:`DeviceIdentityProvider.reset` if the test also mocked device
        identity.
        """
        if cls._instance is not None:
            try:
                cls._instance.stop_agent()  # type: ignore[attr-defined]
            except Exception:
                pass
        cls._instance = None
    
    def __init__(self, runtime=None):
        # ``runtime`` is an optional injected :class:`agent.core.AgentRuntime`.
        # Production code instantiates ``AgentController()`` with no args and
        # picks up the singleton via lazy import (avoids circular import at
        # module-load time). Tests can pass a fresh runtime via
        # ``make_runtime()`` to avoid touching the process singleton.
        if self._initialized:
            # Honour late-bound runtime if the singleton was already
            # initialised once but a test re-uses it with an injected one.
            if runtime is not None:
                self._runtime = runtime
            return

        self._initialized = True

        # Resolve the agent runtime. Lazy import keeps controllers loadable
        # in headless contexts where agent.core isn't fully wired yet.
        if runtime is None:
            from core.agent import get_agent
            runtime = get_agent()
        self._runtime = runtime

        # Signals for GUI communication
        self.signals = AgentSignals()

        # Agent state
        self._status = AgentStatus.STOPPED
        self._agent = None
        self._config = None
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Statistics
        self._stats_lock = threading.Lock()
        self._stats = {
            'packets_captured': 0,
            'domains_detected': 0,
            'blocked_count': 0,
            'allowed_count': 0,
            'uptime_seconds': 0,
        }

        # Monotonically increasing id so each worker thread knows whether it
        # is still the "current" one. Used to prevent an outgoing worker (in
        # its cleanup `finally` block) from clobbering the status of a newer
        # worker the user has already started. Bumped on every start_agent().
        self._worker_id = 0

        # Tk legacy field removed. Qt callers wire QtSignalBridge against
        # ``self.signals`` directly; no per-instance "root" handle to track.

        logger.info("AgentController initialized")
    
    @property
    def status(self) -> AgentStatus:
        return self._status
    
    @property
    def is_running(self) -> bool:
        # DEGRADED still counts as "running" - the agent is alive, just with
        # some optional components disabled. Callers that want strict OK status
        # should compare to AgentStatus.RUNNING directly.
        return self._status in (AgentStatus.RUNNING, AgentStatus.DEGRADED)
    
    @property
    def stats(self) -> Dict:
        return self._stats.copy()
    
    # ``set_root(root)`` removed. Qt frontends construct
    # ``QtSignalBridge(self.signals)`` instead; the previous Tk hook had no
    # remaining callers. Don't reintroduce: a controller that knows about a
    # specific UI toolkit is the exact entanglement this refactor was
    # designed to remove.

    def start_agent(self) -> bool:
        """
        Start agent in background thread.
        Returns immediately, status updates via signals.
        """
        if self._status in [AgentStatus.RUNNING, AgentStatus.DEGRADED, AgentStatus.STARTING]:
            logger.warning("Agent already running or starting")
            return False

        # Reject Start while a previous Stop is still tearing down. Two
        # workers sharing the `Agent` singleton would race on firewall /
        # whitelist state and the old worker's `finally` block would later
        # overwrite our RUNNING status with STOPPED - looking to the user
        # like "Start doesn't work".
        if self._status == AgentStatus.STOPPING:
            logger.warning("Agent is still stopping - wait for cleanup to finish")
            self.signals.emit('error_occurred', {
                'error': 'Agent is stopping - wait a few seconds before clicking Start again',
                'message': 'Previous session is still cleaning up',
            })
            return False

        # Best-effort wait: if a previous worker is still alive (e.g. user
        # clicked Start very quickly after Stop completed signalling), join
        # it briefly so we don't have two threads racing the Agent singleton.
        if self._worker_thread and self._worker_thread.is_alive():
            logger.info("Waiting for previous worker thread to finish...")
            self._worker_thread.join(timeout=5)
            if self._worker_thread.is_alive():
                logger.warning("Previous worker did not exit in 5s; refusing Start")
                self.signals.emit('error_occurred', {
                    'error': 'Previous agent session is still active. Try again in a few seconds.',
                    'message': 'Worker did not finish',
                })
                return False

        # Bump worker generation BEFORE spawning so the outgoing worker (if
        # any leaks past the join above) sees a mismatch and won't update
        # status from its `finally` block.
        self._worker_id += 1
        my_id = self._worker_id

        self._status = AgentStatus.STARTING
        self.signals.emit('status_changed', {'status': 'starting'})

        # Reset stop event so the new worker's main loop doesn't bail.
        self._stop_event.clear()

        # Start worker thread
        self._worker_thread = threading.Thread(
            target=self._agent_worker,
            args=(my_id,),
            daemon=True,
            name=f"AgentWorker-{my_id}",
        )
        self._worker_thread.start()

        logger.info(f"Agent worker thread #{my_id} started")
        return True
    
    def stop_agent(self) -> bool:

        if self._status not in [AgentStatus.RUNNING, AgentStatus.DEGRADED, AgentStatus.STARTING]:
            logger.warning("Agent not running")
            return False
        
        self._status = AgentStatus.STOPPING
        self.signals.emit('status_changed', {'status': 'stopping'})
        
        # Signal worker to stop
        self._stop_event.set()
        
        # Stop agent components
        if self._agent:
            self._agent.stop()
        
        logger.info("Agent stop requested")
        return True
    
    def _agent_worker(self, worker_id: int = 0):
        """Run the agent. `worker_id` is the generation counter recorded at
        spawn time - used to detect when a newer worker has superseded us
        (so our `finally` block doesn't clobber the new worker's status)."""

        def is_current() -> bool:
            return worker_id == self._worker_id

        try:
            logger.info(f"Agent worker #{worker_id} starting...")

            # Import agent components
            from config import reload_config
            from core import initialize_components, cleanup
            from shared.time_utils import sleep, uptime_string
            from utils import check_admin_privileges

            # Use the runtime that was injected (or auto-resolved) at
            # construction time. We no longer reach for ``get_agent()``
            # here — the controller already holds a reference; preserving
            # that referential identity is what makes DI-style tests work.
            self._agent = self._runtime
            
            # Load configuration
            logger.info("Reloading configuration from disk...")
            self._config = reload_config()
            
            # Ensure device ID
            from core import AGENT_DEVICE_ID
            self._config["device_id"] = AGENT_DEVICE_ID
            
            # The agent supports a single mode (whitelist_only). Force it and
            # toggle `enabled` based on admin privileges so users running
            # without elevation don't fail when applying firewall rules.
            admin_status = check_admin_privileges()
            self._config.setdefault("firewall", {})
            self._config["firewall"]["mode"] = "whitelist_only"
            self._config["firewall"]["enabled"] = bool(admin_status)
            if admin_status:
                logger.info("Admin privileges detected - firewall enforcement enabled")
            else:
                logger.warning(
                    "No admin privileges - firewall enforcement disabled. "
                    "Relaunch SAINT as administrator to apply rules."
                )
            
            # Initialize components
            logger.info("Initializing components...")
            # Pass the controller's runtime down explicitly so a test
            # using ``AgentController(runtime=my_runtime)`` doesn't have
            # its component handles attached to the singleton.
            #
            # Gắn callback hook lên runtime trước khi lifecycle chạy. Lifecycle
            # sẽ gọi callback này ngay sau Step 2.5 (whitelist sync xong), giúp
            # GUI nhận manager sớm thay vì phải đợi đủ 7 step. Callback hiện
            # tại chỉ wire WhitelistController; mọi exception trong callback
            # đã được lifecycle bọc try/except nên không phá flow init.
            self._runtime._on_whitelist_ready_callback = self._on_whitelist_ready
            init_result = initialize_components(self._config, runtime=self._runtime)
            if init_result.has_failure():
                failed = [c.name for c in init_result.components if c.status == 'failed']
                raise RuntimeError(
                    f"Component initialization failed: {', '.join(failed) or 'unknown'}"
                )

            # Connect WhitelistController to agent's WhitelistManager
            if self._agent.whitelist:
                from .whitelist_controller import WhitelistController
                whitelist_ctrl = WhitelistController()
                whitelist_ctrl.set_whitelist_manager(self._agent.whitelist)
                logger.info("WhitelistController connected to WhitelistManager")

                # Check if initial sync was successful
                stats = self._agent.whitelist.get_stats()
                if stats.get('sync_count', 0) > 0:
                    self.signals.emit('whitelist_synced', {'success': True})
                    logger.info("Initial whitelist sync completed successfully")

            # If a newer worker has started behind us (race condition the
            # generation guard catches), bail before touching shared state.
            if not is_current():
                logger.info(f"Worker #{worker_id} superseded before main loop; exiting")
                return

            # Mark as running (or degraded if non-critical components failed)
            issues = [
                {'name': c.name, 'status': c.status, 'detail': c.detail}
                for c in init_result.issues
            ]
            if init_result.overall == 'degraded':
                self._status = AgentStatus.DEGRADED
                self.signals.emit('status_changed', {
                    'status': 'degraded',
                    'message': (
                        f"Agent running in degraded mode - {len(issues)} component(s) "
                        "failed to initialize. Check Server configuration."
                    ),
                    'issues': issues,
                })
            else:
                self._status = AgentStatus.RUNNING
                self.signals.emit('status_changed', {
                    'status': 'running',
                    'message': 'Agent started successfully',
                    'issues': issues,
                })

            # Notify that agent is ready for server operations
            self.signals.emit('whitelist_synced', {'agent_ready': True})

            logger.info(f"Agent worker #{worker_id} running - entering main loop")

            # Main loop
            loop_count = 0
            last_emitted: Dict = {}
            # `is_current()` joins the exit condition so a superseded worker
            # bails immediately instead of continuing to emit stats updates.
            while (not self._stop_event.is_set()
                   and self._agent.running
                   and is_current()):
                sleep(1)
                loop_count += 1

                # Update stats every second
                self._update_stats()

                # Emit each tick - but only if values actually changed, so the
                # GUI thread doesn't relayout 8 cards when nothing moved.
                with self._stats_lock:
                    stats_snapshot = self._stats.copy()

                # Augment with the slowly-changing flags the dashboard used to
                # pull via get_agent_info() every second. Bundling them here
                # lets the dashboard be fully signal-driven.
                stats_snapshot['is_registered'] = (
                    self._agent.is_registered() if self._agent else False
                )
                stats_snapshot['firewall_enabled'] = bool(
                    self._config and self._config.get('firewall', {}).get('enabled', False)
                ) if self._config else False

                if stats_snapshot != last_emitted:
                    self.signals.emit('stats_updated', stats_snapshot)
                    last_emitted = stats_snapshot

                if loop_count % 30 == 0:
                    logger.debug(f"Agent loop #{loop_count}, uptime: {uptime_string()}")
            
            logger.info("Agent worker loop ended")
            
        except Exception as e:
            logger.error(f"Agent worker #{worker_id} error: {e}", exc_info=True)
            # Only update controller state if we're still the current worker
            # (a newer worker would already own ERROR/RUNNING transitions).
            if is_current():
                self._status = AgentStatus.ERROR
                self.signals.emit('error_occurred', {
                    'error': str(e),
                    'message': 'Agent encountered an error'
                })

        finally:
            # Cleanup runs unconditionally - we always want to release this
            # worker's firewall rules / sockets even if a newer worker has
            # already taken over the controller status. (The two workers
            # share the Agent singleton, so this could clobber state owned
            # by the newer worker; the start_agent() join above is the
            # primary defence - this is just a belt-and-braces release.)
            try:
                from core import cleanup
                cleanup(self._config, runtime=self._runtime)
            except Exception as e:
                logger.error(f"Cleanup error in worker #{worker_id}: {e}")

            # Only the *current* worker is allowed to publish STOPPED.
            # Without this guard, a slow cleanup from an old worker would
            # overwrite the RUNNING status of the new worker the user just
            # started - looking like "Start doesn't work".
            if is_current():
                self._status = AgentStatus.STOPPED
                self.signals.emit('status_changed', {
                    'status': 'stopped',
                    'message': 'Agent stopped'
                })

            logger.info(f"Agent worker #{worker_id} finished")

    def _on_whitelist_ready(self, manager) -> None:
        """Called by lifecycle right after Step 2.5 (initial whitelist sync).

        Wires the GUI's WhitelistController to the freshly-synced manager
        so the IP Whitelist tab populates in ~10–20s instead of waiting for
        all 7 lifecycle steps to finish (~1–3 minutes).

        Idempotent: WhitelistController is a singleton, and
        ``set_whitelist_manager`` rebinds + re-syncs cleanly if called again
        from the fallback block at the end of ``_agent_worker``.
        """
        try:
            from .whitelist_controller import WhitelistController
            WhitelistController().set_whitelist_manager(manager)
            logger.info(
                "WhitelistController wired early (via lifecycle callback)"
            )
        except Exception as e:
            logger.warning(
                f"Early WhitelistController wire failed: {e}; "
                "will retry from _agent_worker post-init fallback"
            )

    def _update_stats(self):
        """Update internal statistics."""
        try:
            from shared.time_utils import uptime
            
            with self._stats_lock:
                self._stats['uptime_seconds'] = int(uptime())
                
                # Get stats from components if available
                if self._agent:
                    # Whitelist stats
                    if self._agent.whitelist and hasattr(self._agent.whitelist, '_state'):
                        whitelist_stats = self._agent.whitelist._state.get_stats()
                        self._stats['domains_count'] = whitelist_stats.get('domains_count', 0)
                        self._stats['patterns_count'] = whitelist_stats.get('patterns_count', 0)
                        self._stats['ips_count'] = whitelist_stats.get('ips_count', 0)
                    
                    # Sniffer stats (if available)
                    if self._agent.sniffer and hasattr(self._agent.sniffer, 'packet_count'):
                        self._stats['packets_captured'] = getattr(self._agent.sniffer, 'packet_count', 0)
                    
                    # Log sender stats
                    if self._agent.log_sender and hasattr(self._agent.log_sender, 'get_status'):
                        sender_status = self._agent.log_sender.get_status()
                        self._stats['logs_sent'] = sender_status.get('logs_sent', 0)
                        self._stats['queue_size'] = sender_status.get('queue_size', 0)
                        
        except Exception as e:
            logger.debug(f"Stats update error: {e}")
    
    def get_agent_info(self) -> Dict:
        """Get current agent information."""
        with self._stats_lock:
            stats_copy = self._stats.copy()

        info = {
            'status': self._status.name,
            'is_running': self.is_running,
            'stats': stats_copy,
        }
        
        if self._agent:
            info['hostname'] = self._agent.hostname
            info['device_id'] = self._agent.device_id
            info['agent_id'] = self._agent.get_agent_id()
            info['is_registered'] = self._agent.is_registered()
        
        if self._config:
            info['firewall_mode'] = self._config.get('firewall', {}).get('mode', 'unknown')
            info['firewall_enabled'] = self._config.get('firewall', {}).get('enabled', False)
        
        return info
    
    def get_stats(self) -> Dict:
        """Get current agent statistics."""
        with self._stats_lock:
            return self._stats.copy()
    
    def force_whitelist_sync(self) -> bool:
        """Force immediate whitelist sync."""
        if not self.is_running or not self._agent:
            return False
        
        try:
            if self._agent.whitelist:
                success = self._agent.whitelist.sync_now()
                if success:
                    self.signals.emit('whitelist_synced', {'success': True})
                return success
        except Exception as e:
            logger.error(f"Force sync error: {e}")
            self.signals.emit('error_occurred', {'error': str(e)})
        
        return False


# Global controller instance
def get_agent_controller() -> AgentController:
    """Get the global agent controller instance."""
    return AgentController()
