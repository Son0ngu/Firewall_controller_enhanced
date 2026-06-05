"""
Lifecycle management - Agent initialization and cleanup.
- Clean implementation.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from shared.time_utils import now, now_iso
from utils import check_admin_privileges, get_local_ip
from .agent import (
    AgentRuntime,
    get_agent,
    agent_state,
    DeviceIdentityProvider,
)
from .token_manager import init_token_manager, get_token_manager

logger = logging.getLogger("core.lifecycle")

# Component status values
STATUS_OK = "ok"            # initialized and working
STATUS_SKIPPED = "skipped"  # intentionally not run (disabled in config / no admin)
STATUS_DEGRADED = "degraded"  # tried but failed in a non-critical way (offline mode)
STATUS_FAILED = "failed"    # critical failure - agent cannot operate safely

_STATUS_ICON = {
    STATUS_OK: "[+]",
    STATUS_SKIPPED: "[-]",
    STATUS_DEGRADED: "[!]",
    STATUS_FAILED: "[x]",
}


@dataclass
class ComponentStatus:
    """Outcome of initializing a single agent component."""
    name: str
    status: str
    detail: str = ""


@dataclass
class InitResult:
    """
    Aggregate result of `initialize_components`.

    Truthy unless a critical component failed (so existing
    `if not initialize_components(...)` callers still work).
    """
    components: List[ComponentStatus] = field(default_factory=list)

    def record(self, name: str, status: str, detail: str = "") -> None:
        self.components.append(ComponentStatus(name=name, status=status, detail=detail))

    @property
    def overall(self) -> str:
        if any(c.status == STATUS_FAILED for c in self.components):
            return STATUS_FAILED
        if any(c.status in (STATUS_DEGRADED, STATUS_SKIPPED) for c in self.components):
            return STATUS_DEGRADED
        return STATUS_OK

    def has_failure(self) -> bool:
        return self.overall == STATUS_FAILED

    @property
    def issues(self) -> List[ComponentStatus]:
        """Components that are not fully ok - useful for surfacing to the user."""
        return [c for c in self.components if c.status != STATUS_OK]

    def __bool__(self) -> bool:
        return not self.has_failure()


def _latest_component_status(
    result: InitResult,
    name: str,
) -> Optional[ComponentStatus]:
    """Return the latest recorded status for a lifecycle component."""
    for component in reversed(result.components):
        if component.name == name:
            return component
    return None


@dataclass
class LifecycleContext:
    """Mutable context passed to each lifecycle component."""

    runtime: AgentRuntime
    config: Dict
    result: InitResult
    started_components: List["AgentComponent"] = field(default_factory=list)

    @property
    def agent(self) -> AgentRuntime:
        return self.runtime


class AgentComponent:
    """Minimal lifecycle component contract.

    Components own their start/stop behavior and expose a small health
    snapshot. The orchestrator only knows the contract, not component
    internals.
    """

    name = "component"

    def start(self, context: LifecycleContext) -> None:
        raise NotImplementedError

    def stop(self, context: LifecycleContext) -> None:
        return None

    def health(self, context: LifecycleContext) -> Dict:
        return {"name": self.name, "status": STATUS_OK}


class RegistrationComponent(AgentComponent):
    name = "registration"

    def start(self, context: LifecycleContext) -> None:
        _init_registration(context.agent, context.config, context.result)


class TokenManagerComponent(AgentComponent):
    name = "token_manager"

    def start(self, context: LifecycleContext) -> None:
        _init_token_manager(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        token_manager = get_token_manager()
        if token_manager:
            logger.info("Stopping token manager...")
            token_manager.stop_auto_refresh()


class WhitelistComponent(AgentComponent):
    name = "whitelist"

    def start(self, context: LifecycleContext) -> None:
        _init_whitelist_manager(context.agent, context.config, context.result)
        _init_whitelist_sync(context.agent, context.config, context.result)
        _init_periodic_whitelist_sync(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        agent = context.agent
        if hasattr(agent, "whitelist") and agent.whitelist:
            logger.info("Stopping whitelist sync...")
            try:
                agent.whitelist.cleanup()
            except Exception as e:
                logger.warning(f"Whitelist cleanup failed: {e}")
            agent.whitelist = None


class FirewallComponent(AgentComponent):
    name = "firewall"

    def start(self, context: LifecycleContext) -> None:
        _init_firewall(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        agent = context.agent
        if hasattr(agent, "firewall") and agent.firewall:
            logger.info("Cleaning up firewall...")
            if hasattr(agent.firewall, "cleanup"):
                agent.firewall.cleanup()
            elif hasattr(agent.firewall, "cleanup_whitelist_firewall"):
                agent.firewall.cleanup_whitelist_firewall()
            agent.firewall = None

        try:
            from capture.winpcap_installer import cleanup_winpcap, was_installed_by_us
            if was_installed_by_us():
                logger.info("Cleaning up WinPcap (auto-installed)...")
                cleanup_winpcap()
        except Exception as e:
            logger.warning(f"WinPcap cleanup failed: {e}")


class LogSenderComponent(AgentComponent):
    name = "log_sender"

    def start(self, context: LifecycleContext) -> None:
        _init_log_sender(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        agent = context.agent
        if hasattr(agent, "log_sender") and agent.log_sender:
            logger.info("Flushing and stopping log sender...")

            if context.config and context.config.get("agent_id"):
                shutdown_log = build_lifecycle_log(
                    context.config,
                    event_type="agent_shutdown",
                    action="SHUTDOWN",
                    message="Agent shutdown",
                )
                agent.log_sender.queue_log(shutdown_log)

            agent.log_sender.stop()
            agent.log_sender = None


class HeartbeatComponent(AgentComponent):
    name = "heartbeat_sender"

    def start(self, context: LifecycleContext) -> None:
        _init_heartbeat(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        agent = context.agent
        if hasattr(agent, "heartbeat") and agent.heartbeat:
            logger.info("Stopping heartbeat sender...")
            agent.heartbeat.stop()
            agent.heartbeat = None


class PacketSnifferComponent(AgentComponent):
    name = "packet_sniffer"

    def start(self, context: LifecycleContext) -> None:
        _init_packet_sniffer(context.agent, context.config, context.result)

    def stop(self, context: LifecycleContext) -> None:
        agent = context.agent
        if hasattr(agent, "sniffer") and agent.sniffer:
            logger.info("Stopping packet sniffer...")
            agent.sniffer.stop()
            agent.sniffer = None


def build_default_components() -> List[AgentComponent]:
    """Return production lifecycle components in startup order."""
    return [
        RegistrationComponent(),
        TokenManagerComponent(),
        WhitelistComponent(),
        FirewallComponent(),
        LogSenderComponent(),
        HeartbeatComponent(),
        PacketSnifferComponent(),
    ]


def start_components(context: LifecycleContext,
                     components: Sequence[AgentComponent]) -> None:
    """Start components in order and cleanup already-started ones on failure."""
    for component in components:
        try:
            logger.debug("Starting component: %s", component.name)
            context.started_components.append(component)
            context.runtime.components = list(context.started_components)
            component.start(context)
            if context.result.has_failure():
                raise RuntimeError(f"Component {component.name} reported failure")
        except Exception as exc:
            if not any(
                status.name == component.name and status.status == STATUS_FAILED
                for status in context.result.components
            ):
                context.result.record(component.name, STATUS_FAILED, str(exc))
            logger.error(
                "Component %s failed during start: %s",
                component.name, exc, exc_info=True,
            )
            stop_components(context)
            raise


def stop_components(context: LifecycleContext) -> None:
    """Stop started components in reverse order."""
    for component in reversed(context.started_components):
        try:
            logger.debug("Stopping component: %s", component.name)
            component.stop(context)
        except Exception as exc:
            logger.warning(
                "Component %s failed during stop: %s",
                component.name, exc,
            )
    context.started_components.clear()
    context.runtime.components = []


def initialize_components(config: Dict,
                          runtime: Optional[AgentRuntime] = None) -> InitResult:
    """
    Initialize all agent components in correct order.

    Returns an :class:`InitResult` describing the outcome of each step.
    The result is truthy unless a *critical* component failed, so legacy
    callers using ``if not initialize_components(...)`` keep working.

    ``runtime`` is an optional injected :class:`AgentRuntime`. Production
    callers omit it and we fall back to :func:`get_agent` (the singleton);
    tests or harnesses that need isolation construct their own via
    :func:`agent.core.make_runtime` and pass it in. Either path stores
    ``config`` on the runtime and attaches the started components to it.

    The orchestrator is intentionally thin — each numbered step lives in
    its own ``_init_*`` helper below. Ordering still matters (e.g.
    whitelist must sync before firewall enables Default Deny; logger and
    heartbeat both depend on agent credentials being set), so the
    helpers are called in a fixed sequence rather than discovered.
    """
    agent = runtime if runtime is not None else get_agent()
    agent.config = config  # Store config in agent
    result = InitResult()
    context = LifecycleContext(runtime=agent, config=config, result=result)

    try:
        logger.info("=" * 50)
        logger.info("INITIALIZING AGENT COMPONENTS")
        logger.info("=" * 50)

        start_components(context, build_default_components())

        # Mark agent as running
        agent.running = True
        agent_state['initialization_completed'] = True
        agent_state['initialization_time'] = now()

        _log_init_summary(result)
        return result

    except Exception as e:
        logger.error(f"Error during component initialization: {e}", exc_info=True)
        if not result.has_failure():
            result.record("initialization", STATUS_FAILED, str(e))
        _log_init_summary(result)
        return result


# ---------------------------------------------------------------------------
# Per-step helpers. Each takes ``(agent, config, result)``, records its
# outcome, and reads/writes attributes on ``agent`` for the next step. They
# are private to this module — the orchestrator above is the public surface.
# ---------------------------------------------------------------------------


def _init_registration(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 1: register with server (or stay offline if no URL configured)."""
    logger.info("Step 1: Registering with server...")
    from .registry import register_agent, _collect_server_urls

    configured_urls = _collect_server_urls(config)
    if not configured_urls:
        # First-run state: no server URL set yet. Do NOT attempt to call any
        # default endpoint - this protects the user from leaking device info
        # to an unconfigured server. The GUI should prompt the user to set
        # a URL in Settings.
        logger.warning(
            "Server URL is empty - agent will start in OFFLINE mode. "
            "Open Settings → enter a Server URL → Save to enable sync."
        )
        result.record("registration", STATUS_SKIPPED,
                      "no server URL configured (Settings → Server URL)")
    elif not register_agent(config):
        logger.error("Failed to register with server")
        # Continue anyway - can work offline with cached whitelist
        logger.warning("Continuing with offline mode...")
        result.record("registration", STATUS_DEGRADED,
                      "server unreachable, continuing offline")
    else:
        logger.info(f"Registered successfully - Agent ID: {config.get('agent_id')}")
        result.record("registration", STATUS_OK,
                      f"agent_id={config.get('agent_id')}")


def _init_token_manager(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 1.5: init TokenManager and wire re-registration callbacks.

    Callbacks are defined inline so they close over ``config`` and the
    ``token_manager`` reference. Each callback step is independently
    try/except'd — see the long comment inside for why a partial failure
    must not leave TokenManager half-applied.
    """
    logger.info("Step 1.5: Initializing Token Manager...")
    from .registry import register_agent
    token_manager = init_token_manager(config)

    def on_token_expired():
        """Handle token expiry - trigger re-registration."""
        logger.warning("JWT tokens expired - triggering re-registration")
        try:
            ok = register_agent(config)
        except Exception as e:
            logger.error(f"Re-registration raised: {e}", exc_info=True)
            return

        if not ok:
            logger.error("Re-registration failed")
            return

        logger.info("Re-registration successful")
        try:
            token_manager.reset_reregistration_flag()
        except Exception as e:
            logger.warning(f"reset_reregistration_flag failed: {e}")
        try:
            token_manager._load_tokens_from_config()
        except Exception as e:
            logger.warning(f"_load_tokens_from_config failed: {e}")

    def on_token_refreshed():
        """Handle successful token refresh."""
        try:
            logger.debug("JWT tokens refreshed successfully")
        except Exception:  # pragma: no cover — logger shouldn't raise
            pass

    token_manager.start_auto_refresh(
        on_refreshed=on_token_refreshed,
        on_expired=on_token_expired,
    )
    logger.info("Token Manager initialized with auto-refresh")
    result.record("token_manager", STATUS_OK)


def _init_whitelist_manager(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 2: construct the WhitelistManager.

    Critical step — if this raises, the agent can't run safely (nothing
    below has a whitelist to consult), so we record FAILED and re-raise.
    The orchestrator's outer try/except will log and return a failed
    InitResult.
    """
    logger.info("Step 2: Initializing whitelist manager...")
    from whitelist import WhitelistManager
    try:
        agent.whitelist = WhitelistManager(config)
        logger.info("Whitelist manager initialized")
        result.record("whitelist_manager", STATUS_OK)
    except Exception as e:
        logger.error(f"Whitelist manager init failed: {e}", exc_info=True)
        result.record("whitelist_manager", STATUS_FAILED, str(e))
        raise


def _init_whitelist_sync(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 2.5: do the initial whitelist sync *before* the firewall flips
    Default Deny. Firewall enforcement is allowed only after this step records
    OK, so a bad URL/API key cannot create allow rules by itself."""
    if not config.get("whitelist", {}).get("auto_sync", True):
        result.record("whitelist_sync", STATUS_SKIPPED,
                      "auto_sync disabled in config")
        return

    logger.info("Step 2.5: Syncing whitelist from server (BEFORE firewall)...")
    try:
        sync_success = agent.whitelist.sync_now()
        if sync_success:
            stats = agent.whitelist.get_stats()
            domains = stats.get('domains_count', stats.get('domain_count', 0))
            ips = stats.get('ips_count', stats.get('ip_count', 0))
            logger.info(f"Whitelist synced: {domains} domains, {ips} IPs")
            result.record("whitelist_sync", STATUS_OK,
                          f"{domains} domains, {ips} IPs")
        else:
            logger.warning(
                "Whitelist sync failed - firewall enforcement will stay disabled"
            )
            result.record("whitelist_sync", STATUS_DEGRADED,
                          "sync failed (auth or server unreachable)")
    except Exception as e:
        logger.warning(f"Whitelist sync error: {e}")
        result.record("whitelist_sync", STATUS_DEGRADED, str(e))

    # Early GUI wire-up: nếu caller (AgentController) gắn callback lên
    # runtime trước khi gọi initialize_components, fire ngay tại đây để
    # WhitelistController bám vào manager ngay sau khi state đã có data.
    # Callback là tùy chọn — headless/tests không gắn, attr không tồn tại,
    # getattr trả None, không làm gì. Lỗi trong callback không phá lifecycle.
    callback = getattr(agent, "_on_whitelist_ready_callback", None)
    if callback is not None:
        try:
            callback(agent.whitelist)
        except Exception as e:
            logger.warning(
                f"_on_whitelist_ready_callback raised, ignoring: {e}"
            )


def _init_firewall(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 3: init FirewallManager + enable whitelist_only mode.

    Gated on ``firewall.enabled`` config + admin privileges. Without admin
    netsh fails silently, so we don't lie to the user about enforcement —
    we record SKIPPED with a "relaunch as admin" hint instead.
    """
    admin_status = check_admin_privileges()
    firewall_config = config.get("firewall", {})
    firewall_enabled = bool(firewall_config.get("enabled"))

    if not firewall_enabled:
        logger.info("Step 3: Firewall disabled in config")
        result.record("firewall", STATUS_SKIPPED, "disabled in config")
        return

    sync_status = _latest_component_status(result, "whitelist_sync")
    if sync_status is None or sync_status.status != STATUS_OK:
        detail = sync_status.detail if sync_status else "whitelist sync did not run"
        logger.warning(
            "Step 3: Firewall enforcement skipped because whitelist sync is "
            "not ready: %s",
            detail,
        )
        result.record(
            "firewall",
            STATUS_SKIPPED,
            f"waiting for successful whitelist sync ({detail})",
        )
        return

    if not admin_status:
        logger.warning(
            "Step 3: Firewall requires administrator privileges - "
            "running without enforcement. Relaunch as admin to apply rules."
        )
        result.record("firewall", STATUS_SKIPPED,
                      "no admin privileges (relaunch as administrator)")
        return

    # 3.1. Auto-install WinPcap so packet capture works
    logger.info("Step 3.1: Checking WinPcap for packet capture...")
    try:
        from capture.winpcap_installer import (
            ensure_winpcap_available, is_winpcap_installed,
        )
        if not is_winpcap_installed():
            logger.info("WinPcap not found - attempting auto-installation...")
            success, message = ensure_winpcap_available()
            if success:
                logger.info(message)
            else:
                logger.warning("WinPcap auto-install: %s", message)
                logger.warning("Packet capture may not work without WinPcap/Npcap")
        else:
            logger.info("WinPcap/Npcap already installed")
    except Exception as e:
        logger.warning("WinPcap check/install failed: %s", e)

    logger.info("Step 3: Initializing firewall manager...")
    from firewall import FirewallManager
    agent.firewall = FirewallManager(
        firewall_config.get("rule_prefix", "FirewallController")
    )

    # Save pre-SAINT firewall state once so Restore can revert to it.
    # Skip-if-exists prevents clobbering the genuine baseline after a
    # crashed run.
    backup_cfg = firewall_config.get("backup", {}) or {}
    if backup_cfg.get("enabled", True):
        backup_path = backup_cfg.get(
            "path", "profiles/backup.saint-snapshot.json"
        )
        logger.info("Saving pre-SAINT firewall snapshot (if missing)...")
        agent.firewall.save_snapshot(backup_path)
    else:
        logger.info("Firewall backup disabled by config; skipping snapshot.")

    # Link firewall to whitelist
    if agent.whitelist:
        agent.whitelist.set_firewall_manager(agent.firewall)
        logger.info("Firewall manager linked to whitelist")

    # Enable whitelist_only mode (the only supported mode).
    logger.info("Enabling whitelist_only mode (Default Deny + allow whitelist)...")
    server_config = config.get("server", {})
    server_urls = []
    if server_config.get("urls"):
        server_urls.extend(server_config["urls"])
    if server_config.get("url"):
        server_urls.append(server_config["url"])

    whitelist_ips: set = set()
    whitelist_domains: set = set()
    if agent.whitelist and hasattr(agent.whitelist, "_state"):
        whitelist_ips = agent.whitelist._state.get_all_ips()
        whitelist_domains = agent.whitelist._state.get_all_domains()

    logger.info(
        "Whitelist data: %d IPs, %d exact domains",
        len(whitelist_ips), len(whitelist_domains),
    )

    if agent.firewall.enable_whitelist_mode(
        server_urls=server_urls,
        whitelist_ips=whitelist_ips,
        whitelist_domains=whitelist_domains,
    ):
        logger.info(
            "Default Deny enabled - non-whitelisted traffic will be blocked"
        )
        result.record("firewall", STATUS_OK,
                      f"whitelist_only mode ({len(whitelist_ips)} IPs, "
                      f"{len(whitelist_domains)} domains)")
    else:
        logger.error("Failed to enable Default Deny policy")
        result.record("firewall", STATUS_FAILED,
                      "enable_whitelist_mode returned False")


def _init_periodic_whitelist_sync(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 4: kick the periodic sync thread (initial sync already done)."""
    if config.get("whitelist", {}).get("auto_sync", True):
        agent.whitelist.start_sync()
        interval = config.get('whitelist', {}).get('update_interval', 60)
        logger.info(f"Whitelist periodic sync started (interval: {interval}s)")


def _init_log_sender(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 5: build & start LogSender."""
    logger.info("Step 5: Initializing log sender...")
    from logging_module import LogSender

    server_url = config.get("server_url") or config.get("server", {}).get("url")
    agent_id = config.get("agent_id")
    missing_creds = _missing_server_creds(server_url, agent_id)

    if missing_creds:
        msg = f"missing config: {', '.join(missing_creds)}"
        logger.warning(f"Log sender not initialized - {msg}")
        result.record("log_sender", STATUS_DEGRADED, msg)
        return

    try:
        log_sender_config = {
            "server": config.get("server", {}),
            "server_url": server_url,
            "agent_id": agent_id,
            "batch_size": config.get("logging", {}).get("sender", {}).get("batch_size", 100),
            "max_queue_size": config.get("logging", {}).get("sender", {}).get("max_queue_size", 1000),
            "send_interval": config.get("logging", {}).get("sender", {}).get("send_interval", 2),
        }
        agent.log_sender = LogSender(log_sender_config)
        agent.log_sender.start()
        logger.info("Log sender initialized and started")
        result.record("log_sender", STATUS_OK)
    except Exception as e:
        logger.warning(f"Log sender init failed: {e}")
        result.record("log_sender", STATUS_DEGRADED, str(e))


def _init_heartbeat(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 6: build & start HeartbeatSender, wire force_sync + version getter."""
    logger.info("Step 6: Initializing heartbeat sender...")
    from services import HeartbeatSender

    server_url = config.get("server_url") or config.get("server", {}).get("url")
    agent_id = config.get("agent_id")
    missing_creds = _missing_server_creds(server_url, agent_id)

    if missing_creds:
        msg = f"missing config: {', '.join(missing_creds)}"
        logger.warning(f"Heartbeat sender not initialized - {msg}")
        result.record("heartbeat_sender", STATUS_DEGRADED, msg)
        return

    try:
        heartbeat_config = {
            "server": config.get("server", {}),
            "heartbeat": config.get("heartbeat", {}),
            "device_id": config.get("device_id") or agent.device_id,
        }
        agent.heartbeat = HeartbeatSender(heartbeat_config)
        agent.heartbeat.set_agent_credentials(agent_id, config.get("agent_token", ""))
        # Wire force_sync callback: when server requests re-sync (policy/whitelist changed)
        if agent.whitelist and hasattr(agent.whitelist, 'sync_now'):
            agent.heartbeat.on_force_sync = agent.whitelist.sync_now
        # Wire whitelist version getter so heartbeat reports current versions
        if agent.whitelist and hasattr(agent.whitelist, '_state'):
            agent.heartbeat.get_whitelist_versions = lambda: {
                "global_version": agent.whitelist._state._version or None,
                "group_version": agent.whitelist._state._group_version or None,
            }
        agent.heartbeat.start()
        logger.info("Heartbeat sender initialized and started")
        result.record("heartbeat_sender", STATUS_OK)
    except Exception as e:
        logger.warning(f"Heartbeat sender init failed: {e}")
        result.record("heartbeat_sender", STATUS_DEGRADED, str(e))


def _init_packet_sniffer(agent: AgentRuntime, config: Dict, result: InitResult) -> None:
    """Step 7: start packet capture (if enabled in config)."""
    capture_config = config.get("capture", config.get("packet_capture", {}))
    if not capture_config.get("enabled", True):
        logger.info("Step 7: Packet capture disabled in config")
        result.record("packet_sniffer", STATUS_SKIPPED, "disabled in config")
        return

    logger.info("Step 7: Initializing packet sniffer...")
    try:
        from capture.scapy_config import ensure_pcap_driver
        if not ensure_pcap_driver():
            logger.warning(
                "Packet capture skipped - Npcap/WinPcap driver was not found"
            )
            result.record(
                "packet_sniffer",
                STATUS_SKIPPED,
                "Npcap/WinPcap driver not installed",
            )
            return

        from capture import PacketSniffer
        from .handlers import create_domain_handler

        domain_handler = create_domain_handler(config, agent)
        agent.sniffer = PacketSniffer(callback=domain_handler)
        agent.sniffer.start()
        logger.info("Packet sniffer initialized and started")
        result.record("packet_sniffer", STATUS_OK)
    except Exception as e:
        logger.warning(f"Could not initialize packet sniffer: {e}")
        logger.warning("Continuing without packet capture...")
        result.record("packet_sniffer", STATUS_DEGRADED, str(e))


def _missing_server_creds(server_url: Optional[str], agent_id: Optional[str]) -> List[str]:
    """Return the names of server-side credentials that are missing."""
    missing: List[str] = []
    if not server_url:
        missing.append("server_url")
    if not agent_id:
        missing.append("agent_id")
    return missing


def _log_init_summary(result: InitResult) -> None:
    """Log a per-component summary table after initialization."""
    overall = result.overall
    issue_count = sum(1 for c in result.components if c.status != STATUS_OK)

    if overall == STATUS_OK:
        headline = "ALL COMPONENTS INITIALIZED SUCCESSFULLY"
    elif overall == STATUS_DEGRADED:
        headline = f"AGENT INITIALIZED (DEGRADED) - {issue_count} issue(s)"
    else:
        headline = f"AGENT INITIALIZATION FAILED - {issue_count} issue(s)"

    logger.info("=" * 60)
    logger.info(headline)
    name_width = max((len(c.name) for c in result.components), default=0)
    for c in result.components:
        icon = _STATUS_ICON.get(c.status, "[?]")
        line = f"  {icon} {c.name.ljust(name_width)}  {c.status}"
        if c.detail:
            line = f"{line} - {c.detail}"
        if c.status == STATUS_FAILED:
            logger.error(line)
        elif c.status in (STATUS_DEGRADED, STATUS_SKIPPED):
            logger.warning(line)
        else:
            logger.info(line)
    logger.info("=" * 60)


def cleanup(config: Optional[Dict] = None,
            runtime: Optional[AgentRuntime] = None) -> None:
    """
    Cleanup all agent resources.

    Args:
        config: Optional configuration for shutdown logging
        runtime: Optional :class:`AgentRuntime` to clean up. Defaults to the
            singleton so existing callers don't change; tests that
            constructed their own runtime via :func:`make_runtime` should
            pass it explicitly to avoid touching the process singleton.
    """
    agent = runtime if runtime is not None else get_agent()
    config = config or agent.config or {}
    context = LifecycleContext(
        runtime=agent,
        config=config,
        result=InitResult(),
        started_components=list(getattr(agent, "components", []) or []),
    )
    
    logger.info("=" * 50)
    logger.info("SHUTTING DOWN AGENT")
    logger.info("=" * 50)
    
    try:
        if context.started_components:
            stop_components(context)
        else:
            # Defensive fallback for runtimes created before component stack
            # tracking existed, or for tests that attach handles directly.
            context.started_components = build_default_components()
            stop_components(context)
        
        agent.running = False
        
        logger.info("=" * 50)
        logger.info("AGENT SHUTDOWN COMPLETE")
        logger.info("=" * 50)
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}", exc_info=True)


def build_lifecycle_log(config: Dict, event_type: str, action: str, message: str) -> Dict:
    """Build a lifecycle log entry with proper field values."""
    from shared.time_utils import now_iso, uptime_string
    
    local_ip = get_local_ip()
    
    return {
        "timestamp": now_iso(),
        "event_type": event_type,
        "action": action,
        "message": message,
        "level": "INFO",
        "agent_id": config.get("agent_id", "unknown"),
        "device_id": DeviceIdentityProvider.get_device_id(),
        "hostname": DeviceIdentityProvider.get_hostname(),
        "ip_address": local_ip,
        "uptime": uptime_string(),
        "firewall_mode": config.get("firewall", {}).get("mode", "whitelist_only"),
        # Lifecycle events use agent as source/destination
        "source": "agent",
        "source_ip": local_ip,
        "dest_ip": "N/A",
        "destination": "N/A",
        "domain": "N/A",
        "protocol": "N/A",
        "port": "N/A",
        "is_lifecycle_event": True
    }
