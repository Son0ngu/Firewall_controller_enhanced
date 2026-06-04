#!/usr/bin/env python
"""Windows-admin smoke test for the SAINT agent/server contract.

The script is intentionally deterministic:
- build the PyInstaller artifact from agent/saint_agent.spec;
- register the agent with a supplied API key;
- send one heartbeat;
- receive one whitelist sync response;
- send one structured log batch;
- optionally exercise managed firewall rule writes.

Results are written as both human-readable TXT and structured JSON. Runtime
configs may contain secrets; only the TXT/JSON outputs are redacted.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = REPO_ROOT / "agent"
DEFAULT_BUILD_SPEC = AGENT_DIR / "saint_agent.spec"
DEFAULT_EXE = REPO_ROOT / "dist" / "SAINT.exe"
DEFAULT_RESULTS_ROOT = REPO_ROOT / "test-results" / "agent-admin-smoke"
SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "agent_token",
    "token",
    "secret",
    "password",
)


class StepFailure(Exception):
    """Failure with optional structured details."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.details = details or {}


@dataclass
class StepResult:
    name: str
    status: str
    duration_ms: int
    required: bool = True
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def normalize_server_url(value: str) -> str:
    raw = (value or "").strip()
    if raw and "://" not in raw:
        raw = "http://" + raw
    return raw.rstrip("/")


def is_admin() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def add_agent_path() -> None:
    agent_path = str(AGENT_DIR)
    if agent_path not in sys.path:
        sys.path.insert(0, agent_path)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def truncate_text(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"... <truncated {len(value) - limit} chars>"


class AgentAdminSmoke:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_id = args.run_id or now_stamp()
        if args.output_dir:
            output_dir = Path(args.output_dir)
            if not output_dir.is_absolute():
                output_dir = REPO_ROOT / output_dir
        else:
            output_dir = DEFAULT_RESULTS_ROOT / self.run_id

        self.output_dir = output_dir.resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.txt_path = self.output_dir / f"agent_admin_smoke_{self.run_id}.txt"
        self.json_path = self.output_dir / f"agent_admin_smoke_{self.run_id}.json"
        self.pyinstaller_log_path = self.output_dir / "pyinstaller_stdout.log"
        self.agent_log_path = self.output_dir / "agent_smoke.log"
        self.config_path = self.output_dir / "agent_config.json"
        self.snapshot_path = self.output_dir / "firewall_snapshot.saint-snapshot.json"

        self.server_url = normalize_server_url(
            args.server_url or os.environ.get("SAINT_SMOKE_SERVER_URL", "")
        )
        self.api_key = args.api_key or os.environ.get("SAINT_SMOKE_API_KEY", "")
        self.config: Optional[Dict[str, Any]] = None
        self.results: List[StepResult] = []
        self.secrets: List[str] = []
        self.metadata: Dict[str, Any] = {}

        if self.api_key:
            self.secrets.append(self.api_key)

        self._configure_logging()

    def _configure_logging(self) -> None:
        logging.basicConfig(
            level=logging.DEBUG if self.args.verbose else logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            handlers=[
                logging.FileHandler(self.agent_log_path, encoding="utf-8"),
                logging.StreamHandler(sys.stdout),
            ],
            force=True,
        )
        self.logger = logging.getLogger("agent_admin_smoke")

    def run(self) -> int:
        self.metadata = {
            "run_id": self.run_id,
            "repo_root": str(REPO_ROOT),
            "output_dir": str(self.output_dir),
            "config_path": str(self.config_path),
            "txt_path": str(self.txt_path),
            "json_path": str(self.json_path),
            "pyinstaller_log_path": str(self.pyinstaller_log_path),
            "agent_log_path": str(self.agent_log_path),
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "platform": platform.platform(),
            "python": sys.version.replace("\n", " "),
            "admin": is_admin(),
            "server_url": self.server_url,
            "firewall_read_provider": self.args.read_provider,
            "firewall_write_backend": self.args.write_backend,
        }

        self.run_step("environment_admin_check", self.step_environment_admin_check)
        self.run_step("input_validation", self.step_input_validation)

        if self.args.skip_build:
            self.skip_step("build_saint_exe", "Skipped by --skip-build", required=False)
            self.run_step("verify_existing_saint_exe", self.step_verify_existing_exe)
        else:
            self.run_step("build_saint_exe", self.step_build_saint_exe)

        if self.args.no_network_smoke:
            self.skip_step(
                "agent_server_smoke",
                "Skipped by --no-network-smoke",
                required=False,
            )
        elif not self.server_url or not self.api_key:
            self.skip_step(
                "agent_server_smoke",
                "Missing ServerUrl or ApiKey",
            )
        else:
            self.run_step("create_runtime_config", self.step_create_runtime_config)
            self.run_step("server_health", self.step_server_health)
            self.run_step("agent_register", self.step_agent_register)
            self.run_step("auth_headers", self.step_auth_headers)
            self.run_step("heartbeat_send", self.step_heartbeat_send)
            self.run_step("whitelist_sync_receive", self.step_whitelist_sync_receive)
            self.run_step("log_send", self.step_log_send)

        if self.args.enable_default_deny_smoke:
            self.args.enable_firewall_smoke = True

        if self.args.enable_firewall_smoke:
            if not is_admin():
                self.skip_step("firewall_smoke", "Administrator rights required")
            else:
                self.run_step("firewall_provider_probe", self.step_firewall_provider_probe)
                self.run_step("firewall_managed_rule_smoke", self.step_firewall_rule_smoke)

        if self.args.enable_default_deny_smoke:
            if not is_admin():
                self.skip_step(
                    "firewall_default_deny_smoke",
                    "Administrator rights required",
                )
            elif not self.server_url:
                self.skip_step(
                    "firewall_default_deny_smoke",
                    "ServerUrl required to preserve server reachability",
                )
            else:
                self.run_step(
                    "firewall_default_deny_smoke",
                    self.step_firewall_default_deny_smoke,
                )
        elif not self.args.enable_firewall_smoke:
            self.skip_step(
                "firewall_smoke",
                "Firewall tests are opt-in; pass --enable-firewall-smoke",
                required=False,
            )

        required_failures = [
            r for r in self.results if r.required and r.status == "FAIL"
        ]
        self.metadata["finished_at"] = datetime.now().isoformat(timespec="seconds")
        self.metadata["exit_code"] = 1 if required_failures else 0
        self.metadata["required_failures"] = len(required_failures)
        return self.metadata["exit_code"]

    def run_step(
        self,
        name: str,
        func: Callable[[], Optional[Dict[str, Any]]],
        *,
        required: bool = True,
    ) -> None:
        self.logger.info("STEP %s started", name)
        started = time.monotonic()
        try:
            details = func() or {}
            self.results.append(
                StepResult(
                    name=name,
                    status="PASS",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    required=required,
                    details=self.sanitize(details),
                )
            )
            self.logger.info("STEP %s passed", name)
        except StepFailure as exc:
            self.results.append(
                StepResult(
                    name=name,
                    status="FAIL",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    required=required,
                    details=self.sanitize(exc.details),
                    error=self.mask_text(str(exc)),
                )
            )
            self.logger.error("STEP %s failed: %s", name, self.mask_text(str(exc)))
        except Exception as exc:  # noqa: BLE001 - smoke runner must continue
            self.results.append(
                StepResult(
                    name=name,
                    status="FAIL",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    required=required,
                    details={"traceback": self.mask_text(traceback.format_exc())},
                    error=self.mask_text(str(exc)),
                )
            )
            self.logger.exception("STEP %s failed", name)

    def skip_step(self, name: str, reason: str, *, required: bool = True) -> None:
        self.results.append(
            StepResult(
                name=name,
                status="SKIP",
                duration_ms=0,
                required=required,
                details={"reason": reason},
            )
        )
        self.logger.info("STEP %s skipped: %s", name, reason)

    def step_environment_admin_check(self) -> Dict[str, Any]:
        admin = is_admin()
        details = {
            "admin": admin,
            "os_name": os.name,
            "platform": platform.platform(),
            "python_executable": sys.executable,
            "cwd": str(Path.cwd()),
        }
        if not admin:
            raise StepFailure(
                "Script is not running with Administrator privileges",
                details,
            )
        return details

    def step_input_validation(self) -> Dict[str, Any]:
        details = {
            "server_url_present": bool(self.server_url),
            "api_key_present": bool(self.api_key),
            "network_smoke_disabled": self.args.no_network_smoke,
        }
        if self.server_url:
            parsed = urlparse(self.server_url)
            details["server_url"] = self.server_url
            details["server_scheme"] = parsed.scheme
            details["server_netloc"] = parsed.netloc
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise StepFailure("ServerUrl must be an http(s) URL", details)

        if not self.args.no_network_smoke:
            missing = []
            if not self.server_url:
                missing.append("ServerUrl")
            if not self.api_key:
                missing.append("ApiKey")
            if missing:
                raise StepFailure("Missing required input: " + ", ".join(missing), details)
        return details

    def step_build_saint_exe(self) -> Dict[str, Any]:
        if not DEFAULT_BUILD_SPEC.exists():
            raise StepFailure("Build spec not found", {"spec": str(DEFAULT_BUILD_SPEC)})

        pyinstaller = REPO_ROOT / ".venv" / "Scripts" / "pyinstaller.exe"
        command: List[str]
        if pyinstaller.exists():
            command = [str(pyinstaller), "--clean", "--noconfirm", str(DEFAULT_BUILD_SPEC)]
        else:
            found = shutil.which("pyinstaller")
            if not found:
                raise StepFailure(
                    "PyInstaller not found",
                    {
                        "expected": str(pyinstaller),
                        "hint": "Install dependencies in .venv or put pyinstaller on PATH",
                    },
                )
            command = [found, "--clean", "--noconfirm", str(DEFAULT_BUILD_SPEC)]

        env = os.environ.copy()
        result = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.args.build_timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.pyinstaller_log_path.write_text(
            "COMMAND: " + " ".join(command) + "\n\n"
            "STDOUT:\n" + result.stdout + "\n\n"
            "STDERR:\n" + result.stderr,
            encoding="utf-8",
        )

        details = {
            "command": command,
            "returncode": result.returncode,
            "pyinstaller_log": str(self.pyinstaller_log_path),
            "stdout_tail": result.stdout[-3000:],
            "stderr_tail": result.stderr[-3000:],
        }
        if result.returncode != 0:
            raise StepFailure("PyInstaller build failed", details)

        details.update(self.verify_exe_metadata())
        return details

    def step_verify_existing_exe(self) -> Dict[str, Any]:
        return self.verify_exe_metadata()

    def verify_exe_metadata(self) -> Dict[str, Any]:
        if not DEFAULT_EXE.exists():
            raise StepFailure("SAINT.exe not found", {"expected": str(DEFAULT_EXE)})
        stat = DEFAULT_EXE.stat()
        return {
            "exe_path": str(DEFAULT_EXE),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(
                timespec="seconds"
            ),
            "sha256": sha256_file(DEFAULT_EXE),
        }

    def step_create_runtime_config(self) -> Dict[str, Any]:
        add_agent_path()
        from config.defaults import DEFAULT_CONFIG  # pylint: disable=import-error

        config = copy.deepcopy(DEFAULT_CONFIG)
        config["server"]["url"] = self.server_url
        config["server"]["urls"] = [self.server_url]
        config["server"]["connect_timeout"] = self.args.timeout_seconds
        config["server"]["read_timeout"] = self.args.timeout_seconds
        config["server"]["max_retries"] = 1
        config["auth"]["api_key"] = self.api_key
        config["auth"]["auth_method"] = "api_key"
        config["firewall"]["enabled"] = False
        config["firewall"]["rule_prefix"] = self.firewall_rule_prefix
        config["logging"]["file"] = str(self.agent_log_path)
        config["logging"]["sender"]["batch_size"] = 1
        config["logging"]["sender"]["send_interval"] = 1
        config["heartbeat"]["interval"] = 20
        config["heartbeat"]["timeout"] = self.args.timeout_seconds
        config["heartbeat"]["max_failures"] = 1
        config["general"]["debug"] = bool(self.args.verbose)

        self.config = config
        os.environ["FIREWALL_CONTROLLER_CONFIG"] = str(self.config_path)
        self.save_runtime_config()

        return {
            "config_path": str(self.config_path),
            "server_url": self.server_url,
            "firewall_enabled": config["firewall"]["enabled"],
            "note": "Runtime config contains credentials; send only TXT/JSON outputs.",
        }

    def save_runtime_config(self) -> None:
        if self.config is None:
            return
        self.config_path.write_text(
            json.dumps(self.config, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )

    def step_server_health(self) -> Dict[str, Any]:
        import requests

        url = self.server_url.rstrip("/") + "/api/health"
        response = requests.get(url, timeout=self.args.timeout_seconds)
        body = truncate_text(response.text)
        details = {
            "url": url,
            "status_code": response.status_code,
            "body": body,
        }
        if response.status_code != 200:
            raise StepFailure("Server health check did not return HTTP 200", details)
        try:
            payload = response.json()
        except ValueError:
            raise StepFailure("Server health response is not JSON", details)
        details["json"] = payload
        return details

    def step_agent_register(self) -> Dict[str, Any]:
        self.require_config()
        add_agent_path()
        from core.agent import DeviceIdentityProvider  # pylint: disable=import-error
        from core.registry import register_agent  # pylint: disable=import-error

        assert self.config is not None
        device_id = DeviceIdentityProvider.get_device_id()
        self.config["device_id"] = device_id
        ok = register_agent(self.config)
        self.collect_config_secrets()
        self.save_runtime_config()

        details = {
            "registered": ok,
            "agent_id": self.config.get("agent_id"),
            "has_agent_token": bool(self.config.get("agent_token")),
            "has_jwt": bool(self.config.get("jwt", {}).get("access_token")),
            "server_url": self.config.get("server_url"),
            "device_id": device_id,
        }
        if not ok or not self.config.get("agent_id"):
            raise StepFailure("Agent registration failed", details)
        return details

    def step_auth_headers(self) -> Dict[str, Any]:
        self.require_registered_config()
        add_agent_path()
        from core.token_manager import get_auth_headers  # pylint: disable=import-error

        assert self.config is not None
        headers = get_auth_headers(self.config)
        details = {
            "header_names": sorted(headers.keys()),
            "has_authorization": "Authorization" in headers,
            "has_legacy_agent_token": "X-Agent-Token" in headers,
            "headers": headers,
        }
        if not any(k in headers for k in ("Authorization", "X-Agent-Token")):
            raise StepFailure("No JWT or legacy auth header available", details)
        return details

    def step_heartbeat_send(self) -> Dict[str, Any]:
        self.require_registered_config()
        add_agent_path()
        from services.heartbeat import HeartbeatSender  # pylint: disable=import-error

        assert self.config is not None
        heartbeat_config = {
            "server": self.config.get("server", {}),
            "heartbeat": self.config.get("heartbeat", {}),
            "device_id": self.config.get("device_id"),
            "jwt": self.config.get("jwt", {}),
            "agent_token": self.config.get("agent_token"),
        }
        sender = HeartbeatSender(heartbeat_config)
        sender.set_agent_credentials(
            self.config.get("agent_id", ""),
            self.config.get("agent_token", ""),
        )
        success = sender._send_heartbeat()  # Intentional one-shot smoke.
        status = sender.get_status()
        details = {
            "success": success,
            "status": status,
            "server_urls": sender.server_urls,
        }
        if not success:
            raise StepFailure("Heartbeat send failed", details)
        return details

    def step_whitelist_sync_receive(self) -> Dict[str, Any]:
        self.require_registered_config()
        add_agent_path()
        from shared.time_utils import now_iso  # pylint: disable=import-error
        from whitelist.sync import WhitelistSyncer  # pylint: disable=import-error

        assert self.config is not None
        syncer = WhitelistSyncer(
            self.config["server"]["urls"],
            self.config["agent_id"],
            config=self.config,
            connect_timeout=self.args.timeout_seconds,
            read_timeout=self.args.timeout_seconds,
            max_retries=1,
        )
        result = syncer.sync_with_server(
            {
                "agent_id": self.config["agent_id"],
                "global_version": None,
                "group_version": None,
                "policy_mode": "none",
                "timestamp": now_iso(),
            }
        )
        details = {"result": result}
        if not result.get("success"):
            raise StepFailure("Whitelist sync failed", details)

        data = result.get("data", {})
        return {
            "success": True,
            "count": data.get("count", len(data.get("domains", []))),
            "type": data.get("type"),
            "global_version": data.get("global_version"),
            "group_version": data.get("group_version"),
            "group_id": data.get("group_id"),
            "policy_mode": data.get("policy_mode"),
            "up_to_date": data.get("up_to_date"),
        }

    def step_log_send(self) -> Dict[str, Any]:
        self.require_registered_config()
        add_agent_path()
        from logging_module.sender import LogSender  # pylint: disable=import-error
        from shared.time_utils import now_iso  # pylint: disable=import-error

        assert self.config is not None
        sender_config = {
            "server": self.config.get("server", {}),
            "server_url": self.config.get("server_url") or self.server_url,
            "agent_id": self.config.get("agent_id"),
            "agent_token": self.config.get("agent_token"),
            "jwt": self.config.get("jwt", {}),
            "batch_size": 1,
            "max_queue_size": 10,
            "send_interval": 1,
            "max_retry_interval": 5,
        }
        sender = LogSender(sender_config)
        queued = sender.queue_log(
            {
                "timestamp": now_iso(),
                "agent_id": self.config.get("agent_id"),
                "level": "INFO",
                "action": "AGENT_ADMIN_SMOKE",
                "message": "agent admin smoke log send",
                "source": "agent_admin_smoke",
                "domain": "smoke.local",
                "destination": self.server_url,
                "source_ip": "unknown",
                "dest_ip": "unknown",
                "protocol": "HTTPS",
                "port": "443",
                "is_lifecycle_event": True,
            }
        )
        batch = []
        while not sender.log_queue.empty():
            item = sender.log_queue.get_nowait()
            sender.log_queue.task_done()
            batch.append(item)
        sent = sender._send_batch(batch) if batch else False
        details = {
            "queued": queued,
            "batch_size": len(batch),
            "sent": sent,
            "status": sender.get_status(),
        }
        if not queued or not sent:
            raise StepFailure("Log send failed", details)
        return details

    def step_firewall_provider_probe(self) -> Dict[str, Any]:
        self.apply_firewall_env()
        add_agent_path()
        from firewall.provider import (  # pylint: disable=import-error
            get_default_provider,
            get_write_provider,
        )

        read_provider = get_default_provider()
        write_provider = get_write_provider()
        return {
            "read_provider": read_provider.name,
            "write_provider": write_provider.name,
            "read_rule_count": read_provider.count_rules(
                rule_prefix=self.firewall_rule_prefix
            ),
            "write_backend_requested": self.args.write_backend,
            "read_provider_requested": self.args.read_provider,
        }

    def step_firewall_rule_smoke(self) -> Dict[str, Any]:
        self.apply_firewall_env()
        add_agent_path()
        from firewall.rules import RulesManager  # pylint: disable=import-error

        test_ip = self.args.firewall_test_ip
        manager = RulesManager(rule_prefix=self.firewall_rule_prefix)
        before = manager.get_rule_count()
        created = False
        removed = False
        cleared = False
        try:
            created = manager.create_allow_rule(test_ip)
            after_create = manager.get_rule_count()
            removed = manager.remove_allow_rule(test_ip)
            after_remove = manager.get_rule_count()
            cleared = manager.clear_all_rules()
            details = {
                "test_ip": test_ip,
                "rule_prefix": self.firewall_rule_prefix,
                "created": created,
                "removed": removed,
                "cleared": cleared,
                "rule_count_before": before,
                "rule_count_after_create": after_create,
                "rule_count_after_remove": after_remove,
                "rule_count_after_clear": manager.get_rule_count(),
            }
        except Exception as exc:
            try:
                cleared = manager.clear_all_rules()
            except Exception:
                cleared = False
            raise StepFailure(
                f"Managed firewall rule smoke failed: {exc}",
                {
                    "test_ip": test_ip,
                    "rule_prefix": self.firewall_rule_prefix,
                    "created": created,
                    "removed": removed,
                    "cleared_after_error": cleared,
                },
            )

        if not created or not removed or not cleared:
            raise StepFailure("Managed firewall rule smoke failed", details)
        return details

    def step_firewall_default_deny_smoke(self) -> Dict[str, Any]:
        self.apply_firewall_env()
        add_agent_path()
        from firewall.manager import FirewallManager  # pylint: disable=import-error

        manager = FirewallManager(rule_prefix=self.firewall_rule_prefix)
        before_policy = manager.get_firewall_policy_status()
        snapshot_saved = manager.save_snapshot(str(self.snapshot_path), force=True)
        enabled = False
        restore_ok = False
        clear_ok = False
        after_enable_policy: Dict[str, Any] = {}
        after_restore_policy: Dict[str, Any] = {}
        try:
            if not snapshot_saved:
                raise StepFailure(
                    "Firewall snapshot save failed",
                    {
                        "snapshot_path": str(self.snapshot_path),
                        "before_policy": before_policy,
                    },
                )

            enabled = manager.enable_whitelist_mode(
                server_urls=[self.server_url],
                whitelist_ips={self.args.firewall_test_ip},
                whitelist_domains=set(),
            )
            after_enable_policy = manager.get_firewall_policy_status()
            if not enabled:
                raise StepFailure("Default Deny enable returned False")
            return {
                "snapshot_path": str(self.snapshot_path),
                "rule_prefix": self.firewall_rule_prefix,
                "before_policy": before_policy,
                "enabled": enabled,
                "after_enable_policy": after_enable_policy,
            }
        finally:
            try:
                restore_ok = manager.restore_snapshot(str(self.snapshot_path))
            finally:
                clear_ok = manager.clear_all_rules()
                after_restore_policy = manager.get_firewall_policy_status()
                self.results.append(
                    StepResult(
                        name="firewall_default_deny_restore",
                        status="PASS" if restore_ok and clear_ok else "FAIL",
                        duration_ms=0,
                        required=True,
                        details=self.sanitize(
                            {
                                "restore_ok": restore_ok,
                                "clear_ok": clear_ok,
                                "after_restore_policy": after_restore_policy,
                            }
                        ),
                        error=None
                        if restore_ok and clear_ok
                        else "Firewall restore or cleanup failed",
                    )
                )

    def apply_firewall_env(self) -> None:
        if self.args.read_provider != "auto":
            os.environ["SAINT_FIREWALL_PROVIDER"] = self.args.read_provider
        else:
            os.environ.pop("SAINT_FIREWALL_PROVIDER", None)
        os.environ["FIREWALL_WRITE_BACKEND"] = self.args.write_backend

    @property
    def firewall_rule_prefix(self) -> str:
        return "SAINTSmoke_" + self.run_id.replace("-", "_")

    def require_config(self) -> None:
        if self.config is None:
            raise StepFailure("Runtime config has not been created")

    def require_registered_config(self) -> None:
        self.require_config()
        assert self.config is not None
        if not self.config.get("agent_id"):
            raise StepFailure("Agent is not registered")

    def collect_config_secrets(self) -> None:
        if not self.config:
            return
        candidates = [
            self.config.get("agent_token"),
            self.config.get("jwt", {}).get("access_token"),
            self.config.get("jwt", {}).get("refresh_token"),
        ]
        for value in candidates:
            if isinstance(value, str) and value and value not in self.secrets:
                self.secrets.append(value)

    def mask_secret(self, value: str) -> str:
        if not value:
            return value
        if len(value) <= 8:
            return "***"
        return value[:4] + "..." + value[-4:]

    def mask_text(self, text: str) -> str:
        masked = str(text)
        for secret in self.secrets:
            if not secret:
                continue
            masked = masked.replace(secret, self.mask_secret(secret))
        return masked

    def sanitize(self, value: Any, key: str = "") -> Any:
        key_lower = key.lower()
        if isinstance(value, dict):
            out: Dict[str, Any] = {}
            for k, v in value.items():
                out[str(k)] = self.sanitize(v, str(k))
            return out
        if isinstance(value, list):
            return [self.sanitize(v, key) for v in value]
        if isinstance(value, tuple):
            return [self.sanitize(v, key) for v in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, bytes):
            return self.mask_text(value.decode("utf-8", errors="replace"))
        if isinstance(value, str):
            if any(fragment in key_lower for fragment in SECRET_KEY_FRAGMENTS):
                return self.mask_secret(value)
            return self.mask_text(truncate_text(value))
        return value

    def write_outputs(self) -> None:
        payload = {
            "metadata": self.sanitize(self.metadata),
            "steps": [self.step_to_dict(result) for result in self.results],
            "summary": self.summary(),
        }
        self.json_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )
        self.txt_path.write_text(self.render_txt(payload), encoding="utf-8")

    def step_to_dict(self, result: StepResult) -> Dict[str, Any]:
        return {
            "name": result.name,
            "status": result.status,
            "duration_ms": result.duration_ms,
            "required": result.required,
            "details": self.sanitize(result.details),
            "error": self.sanitize(result.error),
        }

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return {
            "counts": counts,
            "required_failures": [
                result.name
                for result in self.results
                if result.required and result.status == "FAIL"
            ],
            "txt_path": str(self.txt_path),
            "json_path": str(self.json_path),
        }

    def render_txt(self, payload: Dict[str, Any]) -> str:
        lines = [
            "SAINT Agent Admin Smoke Test",
            "=" * 34,
            f"Run ID: {self.run_id}",
            f"Started: {self.metadata.get('started_at', '')}",
            f"Finished: {self.metadata.get('finished_at', '')}",
            f"Repo: {REPO_ROOT}",
            f"Output: {self.output_dir}",
            f"Server URL: {self.server_url or '<missing>'}",
            f"Admin: {self.metadata.get('admin')}",
            "",
            "Important:",
            "- Send back the TXT and JSON result files.",
            "- Do not send agent_config.json because it may contain credentials.",
            "",
            "Summary:",
        ]
        counts = payload["summary"]["counts"]
        lines.append(
            f"PASS={counts.get('PASS', 0)} "
            f"FAIL={counts.get('FAIL', 0)} "
            f"SKIP={counts.get('SKIP', 0)}"
        )
        required_failures = payload["summary"]["required_failures"]
        if required_failures:
            lines.append("Required failures: " + ", ".join(required_failures))
        else:
            lines.append("Required failures: none")

        lines.extend(["", "Steps:"])
        for result in self.results:
            lines.append(
                f"[{result.status}] {result.name} "
                f"({result.duration_ms} ms, required={result.required})"
            )
            if result.error:
                lines.append("  Error: " + result.error)
            if result.details:
                detail_json = json.dumps(
                    self.sanitize(result.details),
                    indent=2,
                    ensure_ascii=True,
                )
                for line in detail_json.splitlines():
                    lines.append("  " + line)
            lines.append("")

        lines.extend(
            [
                "Artifacts:",
                f"- TXT: {self.txt_path}",
                f"- JSON: {self.json_path}",
                f"- Agent log: {self.agent_log_path}",
                f"- PyInstaller log: {self.pyinstaller_log_path}",
                f"- Runtime config: {self.config_path} (do not share)",
            ]
        )
        return "\n".join(lines) + "\n"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build SAINT.exe and run an admin smoke test against the server."
    )
    parser.add_argument("--server-url", dest="server_url", default=None)
    parser.add_argument("--api-key", dest="api_key", default=None)
    parser.add_argument("--output-dir", dest="output_dir", default=None)
    parser.add_argument("--run-id", dest="run_id", default=None)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--no-network-smoke", action="store_true")
    parser.add_argument("--enable-firewall-smoke", action="store_true")
    parser.add_argument("--enable-default-deny-smoke", action="store_true")
    parser.add_argument(
        "--read-provider",
        choices=("auto", "netsh", "netsecurity"),
        default="auto",
    )
    parser.add_argument(
        "--write-backend",
        choices=("netsh", "powershell", "netsecurity"),
        default="netsh",
    )
    parser.add_argument("--timeout-seconds", type=int, default=15)
    parser.add_argument("--build-timeout-seconds", type=int, default=900)
    parser.add_argument("--firewall-test-ip", default="203.0.113.10")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    runner = AgentAdminSmoke(args)
    exit_code = 1
    try:
        exit_code = runner.run()
    except Exception as exc:  # noqa: BLE001 - always write result artifacts
        runner.results.append(
            StepResult(
                name="fatal_runner_error",
                status="FAIL",
                duration_ms=0,
                required=True,
                details={"traceback": runner.mask_text(traceback.format_exc())},
                error=runner.mask_text(str(exc)),
            )
        )
        runner.metadata["finished_at"] = datetime.now().isoformat(timespec="seconds")
        runner.metadata["exit_code"] = 1
    finally:
        runner.write_outputs()
        print(f"TXT_RESULT={runner.txt_path}")
        print(f"JSON_RESULT={runner.json_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
