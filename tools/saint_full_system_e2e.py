#!/usr/bin/env python
"""Full SAINT agent/server E2E runner for a Windows admin workstation.

This is intentionally a black-box test against a real server. It creates
temporary users, groups, API keys, whitelist rows, an agent registration, logs,
and optional local firewall policy changes. All created server-side resources
use a run_id prefix and are cleaned up at the end unless --keep-test-data is
set.

Do not share files ending in .local.json from the output folder. TXT/JSON result
files are redacted and are safe to send back for analysis.
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
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_DIR = REPO_ROOT / "agent"
DEFAULT_BUILD_SPEC = AGENT_DIR / "saint_agent.spec"
DEFAULT_EXE = REPO_ROOT / "dist" / "SAINT.exe"
DEFAULT_RESULTS_ROOT = REPO_ROOT / "test-results" / "saint-full-system-e2e"

SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "agent_token",
    "token",
    "password",
    "secret",
    "cookie",
    "set-cookie",
)


class StepFailure(Exception):
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
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def normalize_server_url(value: str) -> str:
    raw = (value or "").strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    return raw.rstrip("/")


def add_agent_path() -> None:
    agent_path = str(AGENT_DIR)
    if agent_path not in sys.path:
        sys.path.insert(0, agent_path)


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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def truncate_text(value: str, limit: int = 3000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"... <truncated {len(value) - limit} chars>"


def first_present(data: Dict[str, Any], paths: Iterable[Tuple[str, ...]]) -> Any:
    for path in paths:
        cur: Any = data
        ok = True
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                ok = False
                break
            cur = cur[key]
        if ok:
            return cur
    return None


class Redactor:
    def __init__(self) -> None:
        self.secrets: List[str] = []

    def add(self, value: Any) -> None:
        if isinstance(value, str) and value and value not in self.secrets:
            self.secrets.append(value)

    def add_many(self, values: Iterable[Any]) -> None:
        for value in values:
            self.add(value)

    @staticmethod
    def mask_secret(value: str) -> str:
        if not value:
            return value
        if len(value) <= 8:
            return "***"
        return value[:4] + "..." + value[-4:]

    def mask_text(self, text: Any) -> str:
        masked = str(text)
        for secret in self.secrets:
            if secret:
                masked = masked.replace(secret, self.mask_secret(secret))
        return masked

    def sanitize(self, value: Any, key: str = "") -> Any:
        key_lower = key.lower()
        if isinstance(value, dict):
            return {str(k): self.sanitize(v, str(k)) for k, v in value.items()}
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


class ApiClient:
    def __init__(
        self,
        name: str,
        base_url: str,
        redactor: Redactor,
        raw_log: List[Dict[str, Any]],
        timeout: int,
    ) -> None:
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.redactor = redactor
        self.raw_log = raw_log
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": f"SAINT-Full-E2E/{name}"})
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.user: Optional[Dict[str, Any]] = None

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return self.base_url + "/" + path.lstrip("/")

    def login(self, username: str, password: str) -> Dict[str, Any]:
        self.redactor.add_many([username, password])
        data = self.request(
            "POST",
            "/api/admin/auth/login",
            json_body={"username": username, "password": password},
            expected=(200,),
            use_bearer=False,
            check_success=True,
            label=f"{self.name}.login",
        )
        payload = data.get("data", {})
        tokens = payload.get("tokens", {})
        self.access_token = tokens.get("access_token")
        self.refresh_token = tokens.get("refresh_token")
        self.csrf_token = payload.get("csrf_token")
        self.user = payload.get("user")
        self.redactor.add_many([self.access_token, self.refresh_token, self.csrf_token])
        return data

    def headers(
        self,
        *,
        use_bearer: bool = True,
        use_csrf: bool = True,
        extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if use_bearer and self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if use_csrf and self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if extra:
            headers.update(extra)
        return headers

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: Tuple[int, ...] = (200,),
        json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        use_bearer: bool = True,
        use_csrf: bool = True,
        headers: Optional[Dict[str, str]] = None,
        check_success: Optional[bool] = None,
        allow_text: bool = False,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = self.url(path)
        request_headers = self.headers(
            use_bearer=use_bearer,
            use_csrf=use_csrf,
            extra=headers,
        )
        method_upper = method.upper()
        max_attempts = 3 if method_upper in ("GET", "HEAD", "OPTIONS") or path == "/api/admin/auth/login" else 1
        response = None
        duration_ms = 0
        for attempt in range(1, max_attempts + 1):
            started = time.monotonic()
            try:
                response = self.session.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=request_headers,
                    timeout=self.timeout,
                )
                duration_ms = int((time.monotonic() - started) * 1000)
                break
            except (requests.Timeout, requests.ConnectionError) as exc:
                duration_ms = int((time.monotonic() - started) * 1000)
                raw_entry = {
                    "label": label or path,
                    "client": self.name,
                    "method": method,
                    "url": url,
                    "attempt": attempt,
                    "duration_ms": duration_ms,
                    "params": params,
                    "request_json": json_body,
                    "exception": type(exc).__name__,
                    "error": str(exc),
                }
                self.raw_log.append(self.redactor.sanitize(raw_entry))
                if attempt >= max_attempts:
                    raise
                time.sleep(min(2 * attempt, 5))
        assert response is not None
        content_type = response.headers.get("Content-Type", "")
        parsed: Any
        try:
            parsed = response.json()
        except ValueError:
            parsed = {"text": truncate_text(response.text)}

        raw_entry = {
            "label": label or path,
            "client": self.name,
            "method": method,
            "url": url,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "params": params,
            "request_json": json_body,
            "response": parsed,
            "content_type": content_type,
        }
        self.raw_log.append(self.redactor.sanitize(raw_entry))

        if response.status_code not in expected:
            raise StepFailure(
                f"{method} {path} returned HTTP {response.status_code}, expected {expected}",
                raw_entry,
            )

        if check_success is True and isinstance(parsed, dict) and parsed.get("success") is False:
            raise StepFailure(f"{method} {path} returned success=false", raw_entry)
        if check_success is False and isinstance(parsed, dict) and parsed.get("success") is True:
            raise StepFailure(f"{method} {path} unexpectedly returned success=true", raw_entry)

        if allow_text and not isinstance(parsed, dict):
            return {"text": str(parsed)}
        return parsed if isinstance(parsed, dict) else {"data": parsed}


class FullSystemE2E:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.run_id = (args.run_id or now_stamp()).lower().replace("-", "_")
        self.prefix = f"e2e_{self.run_id}"
        self.domain_prefix = self.prefix.replace("_", "-")
        output_dir = Path(args.output_dir) if args.output_dir else DEFAULT_RESULTS_ROOT / self.run_id
        if not output_dir.is_absolute():
            output_dir = REPO_ROOT / output_dir
        self.output_dir = output_dir.resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.txt_path = self.output_dir / f"full_system_e2e_{self.run_id}.txt"
        self.json_path = self.output_dir / f"full_system_e2e_{self.run_id}.json"
        self.raw_log_path = self.output_dir / f"full_system_e2e_{self.run_id}_raw.json"
        self.local_secrets_path = self.output_dir / "full_system_e2e.local.json"
        self.build_log_path = self.output_dir / "pyinstaller_stdout.log"
        self.agent_runtime_config_path = self.output_dir / "agent_runtime_config.local.json"
        self.firewall_snapshot_path = self.output_dir / "firewall_snapshot.saint-snapshot.json"

        self.server_url = normalize_server_url(
            args.server_url or os.environ.get("SAINT_E2E_SERVER_URL", "")
        )
        self.bootstrap_username = (
            args.bootstrap_admin_username
            or os.environ.get("SAINT_E2E_BOOTSTRAP_ADMIN_USERNAME", "")
        )
        self.bootstrap_password = (
            args.bootstrap_admin_password
            or os.environ.get("SAINT_E2E_BOOTSTRAP_ADMIN_PASSWORD", "")
        )

        self.redactor = Redactor()
        self.redactor.add_many([self.bootstrap_username, self.bootstrap_password])
        self.raw_log: List[Dict[str, Any]] = []
        self.results: List[StepResult] = []
        self.metadata: Dict[str, Any] = {}
        self.cleanup_results: List[Dict[str, Any]] = []
        self.deep_whitelist_matrix: Dict[str, Any] = {}
        self.deep_policy_matrix: Dict[str, Any] = {}
        self.deep_firewall_packet_matrix: Dict[str, Any] = {}
        self.deep_classroom_matrix: Dict[str, Any] = {}
        self.deep_service_autostart_matrix: Dict[str, Any] = {}
        self.deep_gui_matrix: Dict[str, Any] = {}
        self.deep_websocket_matrix: Dict[str, Any] = {}
        self.deep_soak_matrix: Dict[str, Any] = {}
        self.coverage_not_tested: List[str] = [
            "physical multi-machine hardware scale; deep mode uses many synthetic registered agents unless the script is run from multiple Windows endpoints",
            "actual Windows reboot cycle; deep mode checks service/autostart readiness and records whether service persistence is configured",
            "soak longer than the configured --deep-soak-minutes window",
        ]

        self.bootstrap: Optional[ApiClient] = None
        self.admin: Optional[ApiClient] = None
        self.teacher: Optional[ApiClient] = None
        self.agent_access_token: Optional[str] = None
        self.agent_refresh_token: Optional[str] = None
        self.agent_token: Optional[str] = None
        self.agent_id: Optional[str] = None
        self.agent_device_id = f"{self.prefix}_device"
        self.agent_hostname = f"{self.prefix}_agent"
        self.agent_process: Optional[subprocess.Popen] = None

        self.state: Dict[str, Any] = {
            "temp_admin": {},
            "temp_teacher": {},
            "api_key": {},
            "groups": {},
            "whitelist_ids": [],
            "profiles": [],
            "log_ids": [],
            "extra_agents": [],
            "agent_deleted": False,
        }

        self.temp_admin_username = f"{self.prefix}_admin"
        self.temp_teacher_username = f"{self.prefix}_teacher"
        self.temp_admin_password = f"Adm1n_{self.run_id}_123456"
        self.temp_teacher_password = f"Teach3r_{self.run_id}_123456"
        self.temp_teacher_reset_password = f"Teach3rReset_{self.run_id}_123456"
        self.redactor.add_many(
            [
                self.temp_admin_password,
                self.temp_teacher_password,
                self.temp_teacher_reset_password,
            ]
        )

        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
            handlers=[
                logging.FileHandler(self.output_dir / "full_system_e2e.log", encoding="utf-8"),
                logging.StreamHandler(sys.stdout),
            ],
            force=True,
        )
        self.logger = logging.getLogger("saint_full_system_e2e")

    def run(self) -> int:
        self.metadata = {
            "run_id": self.run_id,
            "prefix": self.prefix,
            "repo_root": str(REPO_ROOT),
            "output_dir": str(self.output_dir),
            "server_url": self.server_url,
            "platform": platform.platform(),
            "python": sys.version.replace("\n", " "),
            "admin": is_admin(),
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "run_real_firewall_policy": bool(self.args.run_real_firewall_policy),
            "write_backend": self.args.write_backend,
            "read_provider": self.args.read_provider,
            "deep": bool(self.args.deep),
            "deep_classroom_agent_count": self.args.deep_classroom_agent_count,
            "deep_soak_minutes": self.args.deep_soak_minutes,
            "deep_soak_interval_seconds": self.args.deep_soak_interval_seconds,
        }

        self.step("environment_and_inputs", self.step_environment_and_inputs)
        if self.args.cleanup_result_json:
            if not self.args.dry_run:
                self.step("public_server_surface", self.step_public_server_surface)
                self.step("bootstrap_login", self.step_bootstrap_login)
            self.step("load_cleanup_result_json", self.step_load_cleanup_result_json)
        elif self.args.dry_run:
            self.skip("dry_run_requested", "No network or mutation executed", required=False)
        elif self.args.firewall_only:
            for name, func, required in (
                ("public_server_surface", self.step_public_server_surface, True),
                ("bootstrap_login", self.step_bootstrap_login, True),
                ("firewall_only_api_key", self.step_firewall_only_api_key, True),
                ("build_agent_exe", self.step_build_agent_exe, not self.args.skip_build),
                ("agent_registration_and_auth", self.step_agent_registration_and_auth, True),
                ("agent_heartbeat_sync_logs", self.step_agent_heartbeat_sync_logs, True),
                ("real_firewall_default_deny_contract", self.step_real_firewall_contract, True),
            ):
                if self.has_required_failure():
                    self.skip(name, "Skipped because an earlier required firewall-only prerequisite failed", required=False)
                    continue
                self.step(name, func, required=required)
        else:
            self.step("public_server_surface", self.step_public_server_surface)
            self.step("bootstrap_login", self.step_bootstrap_login)
            self.step("csrf_negative_cookie_mutation", self.step_csrf_negative)
            self.step("temporary_users", self.step_temporary_users)
            self.step("temporary_user_auth", self.step_temporary_user_auth)
            self.step("user_management_contract", self.step_user_management_contract)
            self.step("api_key_contract", self.step_api_key_contract)
            self.step("group_rbac_contract", self.step_group_rbac_contract)
            self.step("whitelist_contract", self.step_whitelist_contract)
            self.step("profile_contract", self.step_profile_contract)
            self.step("build_agent_exe", self.step_build_agent_exe, required=not self.args.skip_build)
            self.step("agent_registration_and_auth", self.step_agent_registration_and_auth)
            self.step("agent_heartbeat_sync_logs", self.step_agent_heartbeat_sync_logs)
            self.step("agent_admin_teacher_policy_rbac", self.step_agent_admin_teacher_policy_rbac)
            if self.args.deep:
                self.step("deep_whitelist_conflict_matrix", self.step_deep_whitelist_conflict_matrix)
                self.step("deep_policy_matrix", self.step_deep_policy_matrix)
                self.step("deep_classroom_scale_matrix", self.step_deep_classroom_scale_matrix)
                self.step("deep_service_autostart_matrix", self.step_deep_service_autostart_matrix)
                self.step("deep_gui_click_matrix", self.step_deep_gui_click_matrix)
                self.step("deep_websocket_realtime_matrix", self.step_deep_websocket_realtime_matrix)
                if self.args.deep_soak_minutes > 0:
                    self.step("deep_long_soak_matrix", self.step_deep_long_soak_matrix)
                else:
                    self.skip("deep_long_soak_matrix", "Skipped because --deep-soak-minutes is 0", required=False)
            self.step("logs_and_audit_contract", self.step_logs_and_audit_contract)
            if self.args.run_real_firewall_policy:
                self.step("real_firewall_default_deny_contract", self.step_real_firewall_contract)
            else:
                self.skip(
                    "real_firewall_default_deny_contract",
                    "Skipped; pass --run-real-firewall-policy to mutate Windows Firewall",
                    required=False,
                )

        self.cleanup()
        self.metadata["finished_at"] = datetime.now().isoformat(timespec="seconds")
        required_failures = [r for r in self.results if r.required and r.status == "FAIL"]
        cleanup_failures = [r for r in self.cleanup_results if r.get("status") == "CLEANUP_FAIL"]
        self.metadata["exit_code"] = 1 if required_failures or cleanup_failures else 0
        self.metadata["required_failures"] = len(required_failures)
        self.metadata["cleanup_failures"] = len(cleanup_failures)
        return int(self.metadata["exit_code"])

    def step(
        self,
        name: str,
        func: Callable[[], Optional[Dict[str, Any]]],
        *,
        required: bool = True,
    ) -> None:
        started = time.monotonic()
        self.logger.info("STEP %s started", name)
        try:
            details = func() or {}
            self.results.append(
                StepResult(
                    name=name,
                    status="PASS",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    required=required,
                    details=self.redactor.sanitize(details),
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
                    details=self.redactor.sanitize(exc.details),
                    error=self.redactor.mask_text(str(exc)),
                )
            )
            self.logger.error("STEP %s failed: %s", name, self.redactor.mask_text(str(exc)))
        except Exception as exc:  # noqa: BLE001 - E2E runner must continue
            self.results.append(
                StepResult(
                    name=name,
                    status="FAIL",
                    duration_ms=int((time.monotonic() - started) * 1000),
                    required=required,
                    details={"traceback": self.redactor.mask_text(traceback.format_exc())},
                    error=self.redactor.mask_text(str(exc)),
                )
            )
            self.logger.exception("STEP %s failed", name)

    def has_required_failure(self) -> bool:
        return any(result.required and result.status == "FAIL" for result in self.results)

    def skip(self, name: str, reason: str, *, required: bool = True) -> None:
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

    def step_environment_and_inputs(self) -> Dict[str, Any]:
        details = {
            "admin": is_admin(),
            "server_url_present": bool(self.server_url),
            "bootstrap_username_present": bool(self.bootstrap_username),
            "bootstrap_password_present": bool(self.bootstrap_password),
            "output_dir": str(self.output_dir),
            "dry_run": self.args.dry_run,
            "deep": self.args.deep,
        }
        if self.server_url:
            parsed = urlparse(self.server_url)
            details["server_scheme"] = parsed.scheme
            details["server_netloc"] = parsed.netloc
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise StepFailure("ServerUrl must be an http(s) URL", details)
        if not self.args.dry_run:
            missing = []
            if not self.server_url:
                missing.append("ServerUrl")
            if not self.bootstrap_username:
                missing.append("BootstrapAdminUsername")
            if not self.bootstrap_password:
                missing.append("BootstrapAdminPassword")
            if missing:
                raise StepFailure("Missing required input: " + ", ".join(missing), details)
        if self.args.run_real_firewall_policy and not self.args.dry_run and not is_admin():
            raise StepFailure("Real firewall policy test requires Administrator", details)
        if self.args.deep and not self.args.run_real_firewall_policy and not self.args.dry_run:
            raise StepFailure("Deep mode requires --run-real-firewall-policy so packet-level firewall coverage is not skipped", details)
        if self.args.firewall_only and not self.args.run_real_firewall_policy and not self.args.dry_run:
            raise StepFailure("--firewall-only requires --run-real-firewall-policy", details)
        if self.args.deep_classroom_agent_count < 0:
            raise StepFailure("--deep-classroom-agent-count must be >= 0", details)
        if self.args.deep_soak_minutes < 0:
            raise StepFailure("--deep-soak-minutes must be >= 0", details)
        if self.args.deep_soak_interval_seconds < 10:
            raise StepFailure("--deep-soak-interval-seconds must be >= 10", details)
        self.write_local_secrets()
        return details

    def make_client(self, name: str) -> ApiClient:
        return ApiClient(name, self.server_url, self.redactor, self.raw_log, self.args.timeout_seconds)

    def configure_firewall_env(self) -> None:
        os.environ["FIREWALL_WRITE_BACKEND"] = self.args.write_backend
        if self.args.read_provider != "auto":
            os.environ["SAINT_FIREWALL_PROVIDER"] = self.args.read_provider
        else:
            os.environ.pop("SAINT_FIREWALL_PROVIDER", None)

    def step_public_server_surface(self) -> Dict[str, Any]:
        client = self.make_client("public")
        repair = None
        try:
            health = client.request("GET", "/api/health", expected=(200,), use_bearer=False)
        except requests.RequestException as exc:
            if self.args.run_real_firewall_policy and self.is_socket_permission_error(exc):
                repair = self.force_firewall_default_allow("preflight_socket_permission_error")
                health = client.request("GET", "/api/health", expected=(200,), use_bearer=False)
            else:
                raise
        config = client.request("GET", "/api/config", expected=(200,), use_bearer=False)
        page_statuses = {}
        for path in ("/", "/login", "/agents", "/groups", "/whitelist", "/logs"):
            resp = client.session.get(client.url(path), timeout=self.args.timeout_seconds)
            self.raw_log.append(
                self.redactor.sanitize(
                    {
                        "label": f"page:{path}",
                        "method": "GET",
                        "url": client.url(path),
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "text_head": resp.text[:300],
                    }
                )
            )
            if resp.status_code >= 500:
                raise StepFailure(f"Page {path} returned HTTP {resp.status_code}")
            page_statuses[path] = resp.status_code
        result = {"health": health, "config": config, "page_statuses": page_statuses}
        if repair:
            result["local_firewall_repair"] = repair
        return result

    def step_bootstrap_login(self) -> Dict[str, Any]:
        self.bootstrap = self.make_client("bootstrap_admin")
        data = self.bootstrap.login(self.bootstrap_username, self.bootstrap_password)
        me = self.bootstrap.request("GET", "/api/admin/auth/me", expected=(200,), check_success=True)
        user = me.get("data", {})
        if user.get("role") != "admin":
            raise StepFailure("Bootstrap user is not admin", {"me": me})
        return {"login": data, "me": me}

    def step_csrf_negative(self) -> Dict[str, Any]:
        self.require_bootstrap()
        assert self.bootstrap is not None
        payload = {
            "username": f"{self.prefix}_csrf_should_not_create",
            "password": "ShouldNotCreate123456",
            "role": "teacher",
        }
        resp = self.bootstrap.session.post(
            self.bootstrap.url("/api/admin/users"),
            json=payload,
            timeout=self.args.timeout_seconds,
        )
        try:
            body = resp.json()
        except ValueError:
            body = {"text": resp.text[:500]}
        self.raw_log.append(
            self.redactor.sanitize(
                {
                    "label": "csrf_negative_cookie_mutation",
                    "method": "POST",
                    "url": self.bootstrap.url("/api/admin/users"),
                    "status_code": resp.status_code,
                    "response": body,
                }
            )
        )
        if resp.status_code != 403:
            raise StepFailure("CSRF negative check did not return HTTP 403", {"status": resp.status_code, "body": body})
        return {"status_code": resp.status_code, "body": body}

    def step_load_cleanup_result_json(self) -> Dict[str, Any]:
        path = Path(self.args.cleanup_result_json)
        if not path.is_absolute():
            path = (REPO_ROOT / path).resolve()
        if not path.exists():
            raise StepFailure("Cleanup result JSON not found", {"path": str(path)})

        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise StepFailure("Cleanup result JSON must be a structured E2E JSON object")

        metadata = data.get("metadata") or {}
        old_prefix = metadata.get("prefix")
        if old_prefix:
            self.prefix = str(old_prefix)
            self.domain_prefix = self.prefix.replace("_", "-")

        state = data.get("state") or {}
        if isinstance(state, dict):
            for key, value in state.items():
                if key in self.state and isinstance(self.state[key], dict) and isinstance(value, dict):
                    self.state[key].update(value)
                else:
                    self.state[key] = value

        scan_payloads: List[Any] = [data]
        summary = data.get("summary") or {}
        raw_path_value = summary.get("raw_log_path")
        candidate_raw_paths = []
        if raw_path_value:
            candidate_raw_paths.append(Path(raw_path_value))
        if path.name.endswith(".json") and not path.name.endswith("_raw.json"):
            candidate_raw_paths.append(path.with_name(path.stem + "_raw.json"))
        for raw_path in candidate_raw_paths:
            if not raw_path.is_absolute():
                raw_path = (REPO_ROOT / raw_path).resolve()
            if raw_path.exists():
                try:
                    scan_payloads.append(json.loads(raw_path.read_text(encoding="utf-8")))
                except Exception as exc:
                    self.cleanup_results.append(
                        {
                            "name": "load_cleanup_raw_log",
                            "status": "CLEANUP_FAIL",
                            "path": str(raw_path),
                            "error": str(exc),
                        }
                    )

        self.agent_id = self.find_agent_id_in_payloads(scan_payloads)
        if not self.agent_id and self.bootstrap and self.prefix:
            listed = self.bootstrap.request(
                "GET",
                "/api/agents",
                params={"hostname": self.prefix},
                expected=(200,),
                check_success=None,
            )
            agents = listed.get("agents") or listed.get("data", {}).get("agents") or []
            for agent in agents:
                if isinstance(agent, dict) and agent.get("agent_id"):
                    self.agent_id = str(agent["agent_id"])
                    break

        return {
            "source": str(path),
            "loaded_prefix": self.prefix,
            "loaded_agent_id": self.agent_id,
            "state_keys": sorted(self.state.keys()),
        }

    def step_temporary_users(self) -> Dict[str, Any]:
        self.require_bootstrap()
        assert self.bootstrap is not None
        admin = self.bootstrap.request(
            "POST",
            "/api/admin/users",
            expected=(201,),
            json_body={
                "username": self.temp_admin_username,
                "password": self.temp_admin_password,
                "role": "admin",
                "email": f"{self.temp_admin_username}@example.test",
            },
            check_success=True,
            label="create_temp_admin",
        )
        teacher = self.bootstrap.request(
            "POST",
            "/api/admin/users",
            expected=(201,),
            json_body={
                "username": self.temp_teacher_username,
                "password": self.temp_teacher_password,
                "role": "teacher",
                "email": f"{self.temp_teacher_username}@example.test",
            },
            check_success=True,
            label="create_temp_teacher",
        )
        self.state["temp_admin"] = admin.get("user", {})
        self.state["temp_teacher"] = teacher.get("user", {})
        return {
            "temp_admin_id": self.state["temp_admin"].get("_id"),
            "temp_teacher_id": self.state["temp_teacher"].get("_id"),
        }

    def step_temporary_user_auth(self) -> Dict[str, Any]:
        self.admin = self.make_client("temp_admin")
        self.teacher = self.make_client("temp_teacher")
        admin_login = self.admin.login(self.temp_admin_username, self.temp_admin_password)
        teacher_login = self.teacher.login(self.temp_teacher_username, self.temp_teacher_password)
        admin_me = self.admin.request("GET", "/api/admin/auth/me", expected=(200,), check_success=True)
        teacher_me = self.teacher.request("GET", "/api/admin/auth/me", expected=(200,), check_success=True)
        if admin_me.get("data", {}).get("role") != "admin":
            raise StepFailure("Temporary admin role mismatch", {"me": admin_me})
        if teacher_me.get("data", {}).get("role") != "teacher":
            raise StepFailure("Temporary teacher role mismatch", {"me": teacher_me})
        return {"admin_login": admin_login, "teacher_login": teacher_login, "admin_me": admin_me, "teacher_me": teacher_me}

    def step_user_management_contract(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None and self.teacher is not None
        teacher_id = self.state["temp_teacher"].get("_id")
        admin_id = self.state["temp_admin"].get("_id")
        details: Dict[str, Any] = {}
        details["list"] = self.admin.request("GET", "/api/admin/users", params={"search": self.prefix}, expected=(200,), check_success=True)
        details["stats"] = self.admin.request("GET", "/api/admin/users/statistics", expected=(200,), check_success=True)
        details["get_teacher"] = self.admin.request("GET", f"/api/admin/users/{teacher_id}", expected=(200,), check_success=True)
        details["update_teacher"] = self.admin.request(
            "PATCH",
            f"/api/admin/users/{teacher_id}",
            expected=(200,),
            json_body={"email": f"{self.temp_teacher_username}.updated@example.test"},
            check_success=True,
        )
        details["reset_teacher_password"] = self.admin.request(
            "POST",
            f"/api/admin/users/{teacher_id}/reset-password",
            expected=(200,),
            json_body={"new_password": self.temp_teacher_reset_password},
            check_success=True,
        )
        refreshed_teacher = self.make_client("temp_teacher_after_reset")
        refreshed_teacher.login(self.temp_teacher_username, self.temp_teacher_reset_password)
        self.teacher = refreshed_teacher
        details["toggle_teacher_inactive"] = self.admin.request(
            "PATCH",
            f"/api/admin/users/{teacher_id}",
            expected=(200,),
            json_body={"is_active": False},
            check_success=True,
        )
        inactive_login = self.make_client("temp_teacher_inactive_check")
        try:
            inactive_login.login(self.temp_teacher_username, self.temp_teacher_reset_password)
            raise StepFailure("Inactive teacher login unexpectedly succeeded")
        except StepFailure as exc:
            if "HTTP 401" not in str(exc) and "returned success=false" not in str(exc):
                raise
            details["inactive_login_denied"] = str(exc)
        details["toggle_teacher_active"] = self.admin.request(
            "PATCH",
            f"/api/admin/users/{teacher_id}",
            expected=(200,),
            json_body={"is_active": True},
            check_success=True,
        )
        self.teacher = self.make_client("temp_teacher")
        self.teacher.login(self.temp_teacher_username, self.temp_teacher_reset_password)
        details["update_admin_email"] = self.admin.request(
            "PATCH",
            f"/api/admin/users/{admin_id}",
            expected=(200,),
            json_body={"email": f"{self.temp_admin_username}.updated@example.test"},
            check_success=True,
        )
        details["teacher_users_denied"] = self.teacher.request("GET", "/api/admin/users", expected=(403,))
        return details

    def step_api_key_contract(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None
        key_name = f"{self.prefix}_agent_key"
        created = self.admin.request(
            "POST",
            "/api/api-keys",
            expected=(201,),
            json_body={
                "name": key_name,
                "description": f"Full system E2E {self.run_id}",
                "expires_in_days": 1,
                "permissions": ["agent_register", "whitelist_sync", "logs_write"],
            },
            check_success=True,
            label="create_api_key",
        )
        api_key = created.get("api_key")
        key_id = created.get("key_id")
        self.redactor.add(api_key)
        self.state["api_key"] = {"api_key": api_key, "key_id": key_id, "name": key_name}
        details = {"created": created}
        details["list"] = self.admin.request("GET", "/api/api-keys", params={"include_revoked": "true"}, expected=(200,), check_success=True)
        details["get"] = self.admin.request("GET", f"/api/api-keys/{key_id}", expected=(200,), check_success=True)
        details["update"] = self.admin.request(
            "PATCH",
            f"/api/api-keys/{key_id}",
            expected=(200,),
            json_body={
                "description": f"Full system E2E updated {self.run_id}",
                "permissions": ["agent_register", "whitelist_sync", "logs_write", "agent_read"],
            },
            check_success=True,
        )
        details["stats"] = self.admin.request("GET", "/api/api-keys/stats", expected=(200,), check_success=True)
        details["validate_register"] = self.admin.request(
            "POST",
            "/api/api-keys/validate",
            expected=(200,),
            json_body={"api_key": api_key, "permission": "agent_register"},
            check_success=True,
        )
        if not details["validate_register"].get("valid"):
            raise StepFailure("Temporary API key did not validate for agent_register", details)
        details["validate_admin_denied"] = self.admin.request(
            "POST",
            "/api/api-keys/validate",
            expected=(200,),
            json_body={"api_key": api_key, "permission": "admin"},
            check_success=True,
        )
        if details["validate_admin_denied"].get("valid") is not False:
            raise StepFailure("Temporary API key unexpectedly validated for admin permission", details)
        details["validate_bad_key"] = self.admin.request(
            "POST",
            "/api/api-keys/validate",
            expected=(200,),
            json_body={"api_key": "fc_badbadbadbadbadbadbadbadbadbadba", "permission": "agent_register"},
            check_success=True,
        )
        if details["validate_bad_key"].get("valid") is not False:
            raise StepFailure("Bad API key unexpectedly validated", details)
        return details

    def step_firewall_only_api_key(self) -> Dict[str, Any]:
        self.require_bootstrap()
        assert self.bootstrap is not None
        self.admin = self.bootstrap
        key_name = f"{self.prefix}_firewall_packet_key"
        created = self.bootstrap.request(
            "POST",
            "/api/api-keys",
            expected=(201,),
            json_body={
                "name": key_name,
                "description": f"Firewall-only packet E2E {self.run_id}",
                "expires_in_days": 1,
                "permissions": ["agent_register", "whitelist_sync", "logs_write"],
            },
            check_success=True,
            label="firewall_only_create_api_key",
        )
        api_key = created.get("api_key")
        key_id = created.get("key_id")
        self.redactor.add(api_key)
        self.state["api_key"] = {"api_key": api_key, "key_id": key_id, "name": key_name}
        validate = self.bootstrap.request(
            "POST",
            "/api/api-keys/validate",
            expected=(200,),
            json_body={"api_key": api_key, "permission": "agent_register"},
            check_success=True,
            label="firewall_only_validate_api_key",
        )
        if not validate.get("valid"):
            raise StepFailure("Firewall-only API key did not validate for agent_register", {"created": created, "validate": validate})
        return {"created": created, "validate_register": validate}

    def step_group_rbac_contract(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None and self.teacher is not None
        teacher_id = self.state["temp_teacher"].get("_id")
        group_a = self.admin.request(
            "POST",
            "/api/groups",
            expected=(201,),
            json_body={"name": f"{self.prefix}_group_a", "description": "E2E group A", "whitelist": []},
            check_success=True,
        )
        group_b = self.admin.request(
            "POST",
            "/api/groups",
            expected=(201,),
            json_body={"name": f"{self.prefix}_group_b", "description": "E2E group B", "whitelist": []},
            check_success=True,
        )
        group_a_id = group_a.get("data", {}).get("_id")
        group_b_id = group_b.get("data", {}).get("_id")
        self.state["groups"] = {"a": group_a_id, "b": group_b_id}
        details = {"created_a": group_a, "created_b": group_b}
        details["assign_teacher_a"] = self.admin.request(
            "POST",
            f"/api/groups/{group_a_id}/teachers",
            expected=(200,),
            json_body={"teacher_ids": [teacher_id]},
            check_success=True,
        )
        details["admin_list"] = self.admin.request("GET", "/api/groups", expected=(200,), check_success=True)
        details["admin_get_a"] = self.admin.request("GET", f"/api/groups/{group_a_id}", expected=(200,), check_success=True)
        details["admin_update_b"] = self.admin.request(
            "PATCH",
            f"/api/groups/{group_b_id}",
            expected=(200,),
            json_body={"description": "E2E group B updated"},
            check_success=True,
        )
        teacher_list = self.teacher.request("GET", "/api/groups", expected=(200,), check_success=True)
        teacher_ids = {str(g.get("_id")) for g in teacher_list.get("data", [])}
        details["teacher_list"] = teacher_list
        if group_a_id not in teacher_ids or group_b_id in teacher_ids:
            raise StepFailure("Teacher group filtering mismatch", {"teacher_ids": list(teacher_ids), "group_a": group_a_id, "group_b": group_b_id})
        details["teacher_get_a"] = self.teacher.request("GET", f"/api/groups/{group_a_id}", expected=(200,), check_success=True)
        details["teacher_get_b_denied"] = self.teacher.request("GET", f"/api/groups/{group_b_id}", expected=(403,))
        details["teacher_create_denied"] = self.teacher.request(
            "POST",
            "/api/groups",
            expected=(403,),
            json_body={"name": f"{self.prefix}_teacher_forbidden"},
        )
        details["teacher_update_a"] = self.teacher.request(
            "PATCH",
            f"/api/groups/{group_a_id}",
            expected=(200,),
            json_body={"description": "Teacher-visible update"},
            check_success=True,
        )
        details["teacher_update_b_denied"] = self.teacher.request(
            "PATCH",
            f"/api/groups/{group_b_id}",
            expected=(403,),
            json_body={"description": "should fail"},
        )
        return details

    def step_whitelist_contract(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        details: Dict[str, Any] = {}
        global_value = f"{self.domain_prefix}-global.example.com"
        group_a_value = f"{self.domain_prefix}-group-a.example.com"
        teacher_value = f"{self.domain_prefix}-teacher-a.example.com"

        global_add = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"type": "domain", "value": global_value, "category": "e2e"},
            check_success=True,
        )
        global_id = global_add.get("id")
        self.track_whitelist_id(global_id)
        details["global_add"] = global_add

        group_add = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"scope": "group", "group_id": group_a_id, "type": "domain", "value": group_a_value, "category": "e2e"},
            check_success=True,
        )
        group_id = group_add.get("id")
        self.assert_real_id(group_id, "admin group whitelist entry")
        self.track_whitelist_id(group_id)
        details["group_add"] = group_add

        details["list_search"] = self.admin.request("GET", "/api/whitelist", params={"search": self.domain_prefix}, expected=(200,), check_success=True)
        details["scoped_group_a"] = self.admin.request("GET", "/api/whitelist", params={"group_id": group_a_id}, expected=(200,), check_success=True)
        details["statistics"] = self.admin.request("GET", "/api/whitelist/statistics", expected=(200,), check_success=True)
        details["export_json"] = self.admin.request("GET", "/api/whitelist/export", params={"format": "json"}, expected=(200,), check_success=True)

        bulk_values = [f"{self.domain_prefix}-bulk-1.example.com", f"{self.domain_prefix}-bulk-2.example.com"]
        details["bulk_add"] = self.admin.request(
            "POST",
            "/api/whitelist/bulk",
            expected=(200,),
            json_body={
                "items": [
                    {"scope": "group", "group_id": group_a_id, "type": "domain", "value": bulk_values[0], "category": "e2e"},
                    {"scope": "group", "group_id": group_a_id, "type": "domain", "value": bulk_values[1], "category": "e2e"},
                ]
            },
            check_success=True,
        )
        bulk_ids = self.find_whitelist_ids(group_a_id, bulk_values)
        for item_id in bulk_ids:
            self.assert_real_id(item_id, "bulk group whitelist entry")
            self.track_whitelist_id(item_id)
        if bulk_ids:
            details["bulk_update_false"] = self.admin.request(
                "POST",
                "/api/whitelist/bulk-update",
                expected=(200,),
                json_body={"item_ids": [bulk_ids[0]], "active": False},
                check_success=True,
            )
            details["bulk_update_true"] = self.admin.request(
                "POST",
                "/api/whitelist/bulk-update",
                expected=(200,),
                json_body={"item_ids": [bulk_ids[0]], "active": True},
                check_success=True,
            )
            details["bulk_delete_one"] = self.admin.request(
                "POST",
                "/api/whitelist/bulk-delete",
                expected=(200,),
                json_body={"item_ids": [bulk_ids[-1]]},
                check_success=True,
            )
            self.untrack_whitelist_id(bulk_ids[-1])

        details["teacher_global_denied"] = self.teacher.request(
            "POST",
            "/api/whitelist",
            expected=(403,),
            json_body={"type": "domain", "value": f"{self.domain_prefix}-teacher-global-denied.example.com", "category": "e2e"},
        )
        teacher_add = self.teacher.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"scope": "group", "group_id": group_a_id, "type": "domain", "value": teacher_value, "category": "e2e"},
            check_success=True,
        )
        teacher_entry_id = teacher_add.get("id")
        self.assert_real_id(teacher_entry_id, "teacher group whitelist entry")
        self.track_whitelist_id(teacher_entry_id)
        details["teacher_add_group_a"] = teacher_add
        details["teacher_group_b_denied"] = self.teacher.request(
            "POST",
            "/api/whitelist",
            expected=(403,),
            json_body={"scope": "group", "group_id": group_b_id, "type": "domain", "value": f"{self.domain_prefix}-teacher-b-denied.example.com", "category": "e2e"},
        )
        details["teacher_delete_group_a"] = self.teacher.request("DELETE", f"/api/whitelist/{teacher_entry_id}", expected=(200,), check_success=True)
        self.untrack_whitelist_id(teacher_entry_id)
        return details

    def step_profile_contract(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        details: Dict[str, Any] = {}
        details["admin_list_group_a"] = self.admin.request("GET", f"/api/groups/{group_a_id}/profiles", expected=(200,), check_success=True)
        details["teacher_create_group_b_denied"] = self.teacher.request(
            "POST",
            f"/api/groups/{group_b_id}/profiles",
            expected=(403,),
            json_body={"name": f"{self.prefix}_forbidden_profile", "domains": []},
        )
        created = self.teacher.request(
            "POST",
            f"/api/groups/{group_a_id}/profiles",
            expected=(201,),
            json_body={
                "name": f"{self.prefix}_profile",
                "domains": [{"domain": "wikipedia.org", "category": "education"}],
            },
            check_success=True,
        )
        profile_id = created.get("data", {}).get("_id")
        self.state["profiles"].append({"group_id": group_a_id, "profile_id": profile_id})
        details["created"] = created
        details["teacher_my_profiles"] = self.teacher.request("GET", "/api/my-profiles", expected=(200,), check_success=True)
        details["teacher_list_group_a"] = self.teacher.request("GET", f"/api/groups/{group_a_id}/profiles", expected=(200,), check_success=True)
        details["update"] = self.teacher.request(
            "PATCH",
            f"/api/groups/{group_a_id}/profiles/{profile_id}",
            expected=(200,),
            json_body={
                "name": f"{self.prefix}_profile_updated",
                "domains": [{"domain": "khanacademy.org", "category": "education"}],
            },
            check_success=True,
        )
        details["activate"] = self.teacher.request("POST", f"/api/groups/{group_a_id}/profiles/{profile_id}/activate", expected=(200,), check_success=True)
        details["deactivate"] = self.teacher.request("POST", f"/api/groups/{group_a_id}/profiles/{profile_id}/deactivate", expected=(200,), check_success=True)
        details["delete"] = self.teacher.request("DELETE", f"/api/groups/{group_a_id}/profiles/{profile_id}", expected=(200,), check_success=True)
        self.state["profiles"] = [p for p in self.state["profiles"] if p.get("profile_id") != profile_id]
        return details

    def step_build_agent_exe(self) -> Dict[str, Any]:
        if self.args.skip_build:
            return self.verify_exe_metadata()
        if not DEFAULT_BUILD_SPEC.exists():
            raise StepFailure("Build spec not found", {"spec": str(DEFAULT_BUILD_SPEC)})
        pyinstaller = REPO_ROOT / ".venv" / "Scripts" / "pyinstaller.exe"
        command: List[str]
        if pyinstaller.exists():
            command = [str(pyinstaller), "--clean", "--noconfirm", str(DEFAULT_BUILD_SPEC)]
        else:
            found = shutil.which("pyinstaller")
            if not found:
                raise StepFailure("PyInstaller not found", {"expected": str(pyinstaller)})
            command = [found, "--clean", "--noconfirm", str(DEFAULT_BUILD_SPEC)]
        result = subprocess.run(
            command,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.args.build_timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.build_log_path.write_text(
            "COMMAND: " + " ".join(command) + "\n\nSTDOUT:\n" + result.stdout + "\n\nSTDERR:\n" + result.stderr,
            encoding="utf-8",
        )
        details = {
            "command": command,
            "returncode": result.returncode,
            "build_log": str(self.build_log_path),
            "stdout_tail": result.stdout[-3000:],
            "stderr_tail": result.stderr[-3000:],
        }
        if result.returncode != 0:
            raise StepFailure("PyInstaller build failed", details)
        details.update(self.verify_exe_metadata())
        return details

    def verify_exe_metadata(self) -> Dict[str, Any]:
        if not DEFAULT_EXE.exists():
            raise StepFailure("SAINT.exe not found", {"expected": str(DEFAULT_EXE)})
        stat = DEFAULT_EXE.stat()
        return {
            "exe_path": str(DEFAULT_EXE),
            "size_bytes": stat.st_size,
            "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
            "sha256": sha256_file(DEFAULT_EXE),
        }

    def step_agent_registration_and_auth(self) -> Dict[str, Any]:
        api_key = self.state["api_key"].get("api_key")
        if not api_key:
            raise StepFailure("Temporary API key is not available")
        payload = {
            "hostname": self.agent_hostname,
            "device_id": self.agent_device_id,
            "ip_address": self.local_ip(),
            "platform": platform.system(),
            "os_info": platform.platform(),
            "agent_version": "e2e",
            "admin_privileges": is_admin(),
            "capabilities": {
                "packet_capture": True,
                "firewall_management": is_admin(),
                "whitelist_sync": True,
            },
        }
        client = self.make_client("agent_register")
        registered = client.request(
            "POST",
            "/api/agents/register",
            expected=(200,),
            json_body=payload,
            headers={"X-API-Key": api_key},
            use_bearer=False,
            check_success=True,
        )
        data = registered.get("data", {})
        self.agent_id = data.get("agent_id")
        self.agent_token = data.get("token")
        jwt_data = data.get("jwt", {})
        self.agent_access_token = jwt_data.get("access_token")
        self.agent_refresh_token = jwt_data.get("refresh_token")
        self.redactor.add_many([self.agent_token, self.agent_access_token, self.agent_refresh_token])
        if not self.agent_id or not self.agent_token:
            raise StepFailure("Agent registration response missing id/token", registered)
        details = {"registered": registered}
        details["verify_access"] = self.agent_api_request(
            "POST",
            "/api/auth/verify",
            json_body={"token": self.agent_access_token, "token_type": "access"},
            expected=(200,),
            check_success=True,
        )
        details["token_info"] = self.agent_api_request("GET", "/api/auth/token-info", expected=(200,), check_success=True)
        refreshed = self.agent_api_request(
            "POST",
            "/api/auth/refresh",
            json_body={"refresh_token": self.agent_refresh_token, "rotate": True},
            expected=(200,),
            check_success=True,
            use_agent_bearer=False,
        )
        refresh_data = refreshed.get("data", {})
        self.agent_access_token = refresh_data.get("access_token") or self.agent_access_token
        self.agent_refresh_token = refresh_data.get("refresh_token") or self.agent_refresh_token
        self.redactor.add_many([self.agent_access_token, self.agent_refresh_token])
        details["refresh_rotate"] = refreshed
        return details

    def step_agent_heartbeat_sync_logs(self) -> Dict[str, Any]:
        self.require_agent()
        details: Dict[str, Any] = {}
        details["heartbeat"] = self.send_agent_heartbeat()
        details["sync"] = self.agent_api_request(
            "GET",
            "/api/whitelist/agent-sync",
            params={"agent_id": self.agent_id, "policy_mode": "none", "timestamp": datetime.now().isoformat()},
            expected=(200,),
            check_success=True,
        )
        details["log_send"] = self.send_agent_logs([
            {"level": "INFO", "action": "AGENT_ADMIN_SMOKE", "message": f"{self.prefix} lifecycle smoke", "is_lifecycle_event": True},
            {"level": "ALLOWED", "action": "ALLOWED", "message": f"{self.prefix} allowed log", "domain": "wikipedia.org", "destination": "wikipedia.org", "protocol": "HTTPS", "port": "443"},
            {"level": "BLOCKED", "action": "BLOCKED", "message": f"{self.prefix} blocked log", "domain": "blocked.example.com", "destination": "blocked.example.com", "protocol": "HTTPS", "port": "443"},
        ])
        return details

    def step_agent_admin_teacher_policy_rbac(self) -> Dict[str, Any]:
        self.require_clients()
        self.require_agent()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        details: Dict[str, Any] = {}
        details["admin_list_agents"] = self.admin.request("GET", "/api/agents", params={"hostname": self.prefix}, expected=(200,), check_success=True)
        details["admin_stats"] = self.admin.request("GET", "/api/agents/statistics", expected=(200,), check_success=True)
        details["admin_get_agent"] = self.admin.request("GET", f"/api/agents/{self.agent_id}", expected=(200,), check_success=True)
        details["admin_display_name"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/display-name",
            expected=(200,),
            json_body={"display_name": f"{self.prefix} Display"},
            check_success=True,
        )
        details["admin_position"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/position",
            expected=(200,),
            json_body={"position": 1},
            check_success=True,
        )
        details["admin_move_group_a"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/group",
            expected=(200,),
            json_body={"group_id": group_a_id},
            check_success=True,
        )
        details["teacher_list_agents"] = self.teacher.request("GET", "/api/agents", params={"hostname": self.prefix}, expected=(200,), check_success=True)
        details["teacher_get_agent"] = self.teacher.request("GET", f"/api/agents/{self.agent_id}", expected=(200,), check_success=True)
        details["teacher_move_denied"] = self.teacher.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/group",
            expected=(403,),
            json_body={"group_id": group_b_id},
        )
        details["teacher_set_isolate"] = self.teacher.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(200,),
            json_body={"mode": "isolate", "reason": f"{self.prefix} isolate smoke", "duration_minutes": 5},
            check_success=True,
        )
        details["teacher_get_policy"] = self.teacher.request("GET", f"/api/agents/{self.agent_id}/policy", expected=(200,), check_success=True)
        details["sync_isolate"] = self.agent_api_request(
            "GET",
            "/api/whitelist/agent-sync",
            params={"agent_id": self.agent_id, "policy_mode": "none", "timestamp": datetime.now().isoformat()},
            expected=(200,),
            check_success=True,
        )
        details["admin_reset_policy"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(200,),
            json_body={"mode": "none", "reason": f"{self.prefix} reset"},
            check_success=True,
        )
        details["admin_move_group_b"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/group",
            expected=(200,),
            json_body={"group_id": group_b_id},
            check_success=True,
        )
        details["teacher_get_group_b_agent_denied"] = self.teacher.request("GET", f"/api/agents/{self.agent_id}", expected=(403,))
        details["admin_move_group_a_again"] = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/group",
            expected=(200,),
            json_body={"group_id": group_a_id},
            check_success=True,
        )
        return details

    def step_deep_whitelist_conflict_matrix(self) -> Dict[str, Any]:
        self.require_clients()
        self.require_agent()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        conflict_value = f"{self.domain_prefix}-scope-conflict.example.com"
        cross_value = f"{self.domain_prefix}-cross-group.example.com"
        bulk_dup_value = f"{self.domain_prefix}-bulk-dupe.example.com"
        profile_only_value = f"{self.domain_prefix}-profile-only.example.com"
        matrix: Dict[str, Any] = {
            "passed": False,
            "values": {
                "scope_conflict": conflict_value,
                "cross_group": cross_value,
                "bulk_duplicate": bulk_dup_value,
                "profile_only": profile_only_value,
            },
            "cases": {},
        }
        self.deep_whitelist_matrix = matrix

        def ok(name: str, details: Dict[str, Any]) -> None:
            matrix["cases"][name] = {"passed": True, **details}

        def fail(name: str, message: str, details: Dict[str, Any]) -> None:
            matrix["cases"][name] = {"passed": False, "message": message, **details}
            raise StepFailure(message, matrix)

        global_add = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"type": "domain", "value": conflict_value, "category": "deep-global", "priority": "high"},
            check_success=True,
            label="deep_global_conflict_add",
        )
        global_id = str(global_add.get("id"))
        self.assert_real_id(global_id, "deep global conflict")
        self.track_whitelist_id(global_id)

        group_add = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={
                "scope": "group",
                "group_id": group_a_id,
                "type": "domain",
                "value": conflict_value,
                "category": "deep-group",
                "priority": "normal",
            },
            check_success=True,
            label="deep_group_conflict_add",
        )
        group_conflict_id = str(group_add.get("id"))
        self.assert_real_id(group_conflict_id, "deep group conflict")
        self.track_whitelist_id(group_conflict_id)

        scoped = self.admin.request("GET", "/api/whitelist", params={"group_id": group_a_id}, expected=(200,), check_success=True)
        merged_conflict = self.entries_for_value(scoped.get("merged", []), conflict_value)
        if len(merged_conflict) != 1:
            fail("scoped_merge_single", "Scoped whitelist did not return exactly one merged conflict entry", {"entries": merged_conflict})
        merged = merged_conflict[0]
        if str(merged.get("_id") or merged.get("id")) != group_conflict_id or merged.get("scope") != "group":
            fail("scoped_group_wins", "Group entry did not win scoped whitelist conflict", {"merged": merged, "group_id": group_conflict_id})
        if merged.get("priority") != "high":
            fail("scoped_priority_high_preserved", "Merged conflict did not preserve high priority", {"merged": merged})
        ok("scoped_group_wins_with_global_priority", {"group_entry_id": group_conflict_id, "global_entry_id": global_id})

        sync = self.agent_sync(policy_mode="none")
        sync_conflict = self.entries_for_value(sync.get("domains", []), conflict_value)
        if len(sync_conflict) != 1:
            fail("agent_sync_single_conflict", "Agent sync did not return exactly one conflict entry", {"entries": sync_conflict})
        sync_entry = sync_conflict[0]
        if (
            sync_entry.get("scope") == "global"
            or str(sync_entry.get("_id") or sync_entry.get("id")) == global_id
            or sync_entry.get("category") == "deep-global"
        ):
            fail("agent_sync_group_wins", "Agent sync used global entry instead of group conflict entry", {"entry": sync_entry})
        ok("agent_sync_group_wins", {"entry": sync_entry})

        cross_a = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"scope": "group", "group_id": group_a_id, "type": "domain", "value": cross_value, "category": "deep-a"},
            check_success=True,
            label="deep_cross_group_a_add",
        )
        cross_a_id = str(cross_a.get("id"))
        self.assert_real_id(cross_a_id, "deep cross group A")
        self.track_whitelist_id(cross_a_id)
        cross_b = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"scope": "group", "group_id": group_b_id, "type": "domain", "value": cross_value, "category": "deep-b"},
            check_success=True,
            label="deep_cross_group_b_add",
        )
        cross_b_id = str(cross_b.get("id"))
        self.assert_real_id(cross_b_id, "deep cross group B")
        self.track_whitelist_id(cross_b_id)
        sync_cross = self.entries_for_value(self.agent_sync(policy_mode="none").get("domains", []), cross_value)
        if len(sync_cross) != 1:
            fail("cross_group_agent_scope", "Agent sync did not return exactly one own-group cross entry", {"entries": sync_cross})
        if str(sync_cross[0].get("_id") or sync_cross[0].get("id")) == cross_b_id or str(sync_cross[0].get("group_id")) == group_b_id:
            fail("cross_group_b_not_visible", "Group B entry leaked into group A agent sync", {"entry": sync_cross[0]})
        teacher_b_update = self.teacher.request(
            "POST",
            "/api/whitelist/bulk-update",
            expected=(403,),
            json_body={"item_ids": [cross_b_id], "active": False},
            label="deep_teacher_group_b_update_denied",
        )
        ok("cross_group_isolated_and_teacher_denied", {"group_a_entry_id": cross_a_id, "group_b_entry_id": cross_b_id, "teacher_b_update": teacher_b_update})

        duplicate_global = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(400,),
            json_body={"type": "domain", "value": conflict_value, "category": "deep-duplicate"},
            label="deep_duplicate_global_denied",
        )
        duplicate_group = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(400,),
            json_body={"scope": "group", "group_id": group_a_id, "type": "domain", "value": conflict_value, "category": "deep-duplicate"},
            label="deep_duplicate_group_denied",
        )
        bulk_dup = self.admin.request(
            "POST",
            "/api/whitelist/bulk",
            expected=(200,),
            json_body={
                "items": [
                    {"scope": "group", "group_id": group_a_id, "type": "domain", "value": bulk_dup_value, "category": "deep"},
                    {"scope": "group", "group_id": group_a_id, "type": "domain", "value": bulk_dup_value, "category": "deep"},
                ]
            },
            check_success=True,
            label="deep_bulk_duplicate_batch",
        )
        bulk_ids = self.find_whitelist_ids(group_a_id, [bulk_dup_value])
        for item_id in bulk_ids:
            self.assert_real_id(item_id, "deep bulk duplicate group entry")
            self.track_whitelist_id(item_id)
        if len(bulk_ids) > 1:
            fail("bulk_duplicate_no_duplicate_rows", "Bulk duplicate inserted more than one row", {"ids": bulk_ids, "response": bulk_dup})
        ok("duplicate_same_scope_denied", {"global": duplicate_global, "group": duplicate_group, "bulk": bulk_dup, "bulk_ids": bulk_ids})

        self.admin.request(
            "POST",
            "/api/whitelist/bulk-update",
            expected=(200,),
            json_body={"item_ids": [group_conflict_id], "active": False},
            check_success=True,
            label="deep_disable_group_conflict",
        )
        disabled_sync_entry = self.single_value_entry(self.agent_sync(policy_mode="none").get("domains", []), conflict_value)
        if disabled_sync_entry.get("scope") == "group" or str(disabled_sync_entry.get("_id") or disabled_sync_entry.get("id")) == group_conflict_id:
            fail("disabled_group_falls_back_global", "Disabled group conflict did not fall back to global", {"entry": disabled_sync_entry})
        self.admin.request(
            "POST",
            "/api/whitelist/bulk-update",
            expected=(200,),
            json_body={"item_ids": [group_conflict_id], "active": True},
            check_success=True,
            label="deep_reenable_group_conflict",
        )
        restored_sync_entry = self.single_value_entry(self.agent_sync(policy_mode="none").get("domains", []), conflict_value)
        if (
            restored_sync_entry.get("scope") == "global"
            or str(restored_sync_entry.get("_id") or restored_sync_entry.get("id")) == global_id
            or restored_sync_entry.get("category") == "deep-global"
        ):
            fail("reenabled_group_wins", "Re-enabled group conflict did not win", {"entry": restored_sync_entry})
        ok("disable_restore_group_conflict", {"disabled_entry": disabled_sync_entry, "restored_entry": restored_sync_entry})

        self.admin.request("DELETE", f"/api/whitelist/{group_conflict_id}", expected=(200,), check_success=True, label="deep_delete_group_conflict")
        self.untrack_whitelist_id(group_conflict_id)
        deleted_sync_entry = self.single_value_entry(self.agent_sync(policy_mode="none").get("domains", []), conflict_value)
        if (
            deleted_sync_entry.get("scope") == "group"
            or (
                str(deleted_sync_entry.get("_id") or deleted_sync_entry.get("id")) != global_id
                and deleted_sync_entry.get("category") != "deep-global"
            )
        ):
            fail("deleted_group_falls_back_global", "Deleted group conflict did not fall back to global", {"entry": deleted_sync_entry})
        restored_group = self.admin.request(
            "POST",
            "/api/whitelist",
            expected=(201,),
            json_body={"scope": "group", "group_id": group_a_id, "type": "domain", "value": conflict_value, "category": "deep-group-restore"},
            check_success=True,
            label="deep_restore_group_conflict",
        )
        group_conflict_id = str(restored_group.get("id"))
        self.assert_real_id(group_conflict_id, "deep restored group conflict")
        self.track_whitelist_id(group_conflict_id)
        self.state.setdefault("deep", {})["conflict_group_id"] = group_conflict_id
        self.state.setdefault("deep", {})["conflict_global_id"] = global_id
        self.state.setdefault("deep", {})["conflict_value"] = conflict_value
        restored_after_delete = self.single_value_entry(self.agent_sync(policy_mode="none").get("domains", []), conflict_value)
        if (
            restored_after_delete.get("scope") == "global"
            or str(restored_after_delete.get("_id") or restored_after_delete.get("id")) == global_id
            or restored_after_delete.get("category") == "deep-global"
        ):
            fail("restored_group_wins_after_delete", "Restored group conflict did not win after delete", {"entry": restored_after_delete})
        ok("delete_restore_group_conflict", {"deleted_entry": deleted_sync_entry, "restored_entry": restored_after_delete})

        profile = self.teacher.request(
            "POST",
            f"/api/groups/{group_a_id}/profiles",
            expected=(201,),
            json_body={"name": f"{self.prefix}_deep_profile", "domains": [{"domain": profile_only_value, "category": "deep-profile"}]},
            check_success=True,
            label="deep_profile_create",
        )
        profile_id = str(profile.get("data", {}).get("_id") or profile.get("_id") or profile.get("id"))
        if not profile_id or profile_id == "None":
            fail("active_profile_id_present", "Profile create response did not include an id", {"profile": profile})
        self.state["profiles"].append({"group_id": group_a_id, "profile_id": profile_id})
        self.teacher.request("POST", f"/api/groups/{group_a_id}/profiles/{profile_id}/activate", expected=(200,), check_success=True, label="deep_profile_activate")
        profile_sync = self.agent_sync(policy_mode="none")
        profile_conflict = self.single_value_entry(profile_sync.get("domains", []), conflict_value)
        if (
            profile_conflict.get("scope") == "group"
            or str(profile_conflict.get("_id") or profile_conflict.get("id")) == group_conflict_id
            or profile_conflict.get("category") != "deep-global"
        ):
            fail("active_profile_suppresses_group_base", "Active profile leaked group base conflict entry", {"entry": profile_conflict})
        if len(self.entries_for_value(profile_sync.get("domains", []), profile_only_value)) != 1:
            fail("active_profile_domain_present", "Active profile domain missing from sync", {"domains": profile_sync.get("domains", [])})
        self.teacher.request("POST", f"/api/groups/{group_a_id}/profiles/{profile_id}/deactivate", expected=(200,), check_success=True, label="deep_profile_deactivate")
        self.teacher.request("DELETE", f"/api/groups/{group_a_id}/profiles/{profile_id}", expected=(200,), check_success=True, label="deep_profile_delete")
        self.state["profiles"] = [p for p in self.state["profiles"] if p.get("profile_id") != profile_id]
        ok("active_profile_overrides_group_base", {"profile_id": profile_id, "profile_conflict_entry": profile_conflict})

        matrix["passed"] = True
        return matrix

    def step_deep_policy_matrix(self) -> Dict[str, Any]:
        self.require_clients()
        self.require_agent()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        conflict_value = self.state.get("deep", {}).get("conflict_value")
        custom_value = f"{self.domain_prefix}-custom-policy.example.com"
        matrix: Dict[str, Any] = {
            "passed": False,
            "values": {"conflict": conflict_value, "custom": custom_value},
            "cases": {},
        }
        self.deep_policy_matrix = matrix

        def ok(name: str, details: Dict[str, Any]) -> None:
            matrix["cases"][name] = {"passed": True, **details}

        def fail(name: str, message: str, details: Dict[str, Any]) -> None:
            matrix["cases"][name] = {"passed": False, "message": message, **details}
            raise StepFailure(message, matrix)

        sync_none = self.agent_sync(policy_mode="none")
        if sync_none.get("policy_mode") != "none" or sync_none.get("policy_active") is not False:
            fail("none_policy_inactive", "Policy none sync reported active policy", {"sync": sync_none})
        if conflict_value:
            conflict_entry = self.single_value_entry(sync_none.get("domains", []), conflict_value)
            if conflict_entry.get("scope") == "global" or conflict_entry.get("category") == "deep-global":
                fail("none_policy_group_conflict_visible", "Policy none did not preserve group conflict merge", {"entry": conflict_entry})
        repeat = self.agent_sync(
            policy_mode="none",
            global_version=sync_none.get("global_version"),
            group_version=sync_none.get("group_version"),
        )
        if repeat.get("up_to_date") is not True or repeat.get("count") != 0:
            fail("versioned_sync_up_to_date", "Repeated sync with current versions was not up_to_date", {"repeat": repeat})
        ok("none_policy_and_version_cache", {"sync_count": sync_none.get("count"), "repeat": repeat})

        self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(200,),
            json_body={"mode": "isolate", "reason": f"{self.prefix} deep isolate", "duration_minutes": 5},
            check_success=True,
            label="deep_policy_isolate",
        )
        heartbeat = self.send_agent_heartbeat()
        heartbeat_data = heartbeat.get("data", heartbeat)
        if heartbeat_data.get("force_sync") is not True or heartbeat_data.get("policy_mode") != "isolate":
            fail("isolate_heartbeat_force_sync", "Heartbeat did not request force sync for isolate", {"heartbeat": heartbeat})
        isolate_sync = self.agent_sync(policy_mode="none")
        isolate_values = {self.entry_value(e) for e in isolate_sync.get("domains", [])}
        if isolate_sync.get("policy_mode") != "isolate" or isolate_sync.get("policy_active") is not True:
            fail("isolate_sync_policy_active", "Isolate sync did not report active isolate policy", {"sync": isolate_sync})
        if conflict_value and conflict_value in isolate_values:
            fail("isolate_suppresses_group_whitelist", "Isolate sync still contained base whitelist domain", {"values": sorted(isolate_values)})
        server_host = (urlparse(self.server_url).hostname or "").lower()
        if server_host and server_host not in isolate_values:
            fail("isolate_server_host_present", "Isolate sync missing server host entry", {"values": sorted(isolate_values), "server_host": server_host})
        if {"8.8.8.8", "8.8.4.4", "1.1.1.1"} & isolate_values:
            fail("isolate_no_public_dns", "Isolate sync unexpectedly contained public DNS entries", {"values": sorted(isolate_values)})
        ok("isolate_policy_sync", {"heartbeat": heartbeat, "count": isolate_sync.get("count"), "values": sorted(isolate_values)})

        self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(200,),
            json_body={
                "mode": "custom_whitelist",
                "reason": f"{self.prefix} deep custom",
                "custom_whitelist": [{"domain": custom_value, "category": "deep-custom"}],
                "duration_minutes": 5,
            },
            check_success=True,
            label="deep_policy_custom",
        )
        custom_sync = self.agent_sync(policy_mode="isolate")
        custom_values = {self.entry_value(e) for e in custom_sync.get("domains", [])}
        if custom_sync.get("policy_mode") != "custom_whitelist" or custom_sync.get("policy_active") is not True:
            fail("custom_sync_policy_active", "Custom whitelist sync did not report active custom policy", {"sync": custom_sync})
        if custom_value not in custom_values:
            fail("custom_domain_present", "Custom whitelist domain missing from sync", {"values": sorted(custom_values)})
        if conflict_value and conflict_value in custom_values:
            fail("custom_suppresses_group_whitelist", "Custom whitelist sync still contained base whitelist domain", {"values": sorted(custom_values)})
        ok("custom_policy_sync", {"count": custom_sync.get("count"), "values": sorted(custom_values)})

        invalid = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(400,),
            json_body={"mode": "not_a_policy"},
            label="deep_policy_invalid_mode",
        )
        teacher_denied: Dict[str, Any] = {}
        try:
            self.admin.request(
                "PATCH",
                f"/api/agents/{self.agent_id}/group",
                expected=(200,),
                json_body={"group_id": group_b_id},
                check_success=True,
                label="deep_policy_move_group_b",
            )
            teacher_denied = self.teacher.request(
                "PATCH",
                f"/api/agents/{self.agent_id}/policy",
                expected=(403,),
                json_body={"mode": "isolate", "reason": "should fail"},
                label="deep_teacher_policy_group_b_denied",
            )
        finally:
            self.admin.request(
                "PATCH",
                f"/api/agents/{self.agent_id}/group",
                expected=(200,),
                json_body={"group_id": group_a_id},
                check_success=True,
                label="deep_policy_move_group_a",
            )
        ok("policy_negative_paths", {"invalid_mode": invalid, "teacher_group_b_denied": teacher_denied})

        reset = self.admin.request(
            "PATCH",
            f"/api/agents/{self.agent_id}/policy",
            expected=(200,),
            json_body={"mode": "none", "reason": f"{self.prefix} deep reset"},
            check_success=True,
            label="deep_policy_reset",
        )
        reset_sync = self.agent_sync(policy_mode="custom_whitelist")
        if reset_sync.get("policy_mode") != "none" or reset_sync.get("policy_active") is not False:
            fail("reset_policy_none", "Reset policy sync did not return to none", {"sync": reset_sync, "reset": reset})
        if conflict_value:
            reset_conflict = self.single_value_entry(reset_sync.get("domains", []), conflict_value)
            if reset_conflict.get("scope") == "global" or reset_conflict.get("category") == "deep-global":
                fail("reset_restores_group_merge", "Reset did not restore group conflict merge", {"entry": reset_conflict})
        ok("reset_policy_restores_normal_sync", {"reset": reset, "sync_count": reset_sync.get("count")})

        matrix["passed"] = True
        return matrix

    def step_deep_classroom_scale_matrix(self) -> Dict[str, Any]:
        self.require_clients()
        self.require_agent()
        assert self.admin is not None and self.teacher is not None
        group_a_id = self.group_id("a")
        group_b_id = self.group_id("b")
        count = int(self.args.deep_classroom_agent_count)
        matrix: Dict[str, Any] = {
            "passed": False,
            "mode": "synthetic_registered_agents",
            "requested_agent_count": count,
            "cases": {},
        }
        self.deep_classroom_matrix = matrix
        if count == 0:
            matrix["passed"] = True
            matrix["skipped"] = True
            matrix["reason"] = "--deep-classroom-agent-count is 0"
            self.add_coverage_note("multi-machine classroom scale disabled by --deep-classroom-agent-count=0")
            return matrix

        group_a_agents: List[Dict[str, Any]] = []
        group_b_agents: List[Dict[str, Any]] = []
        registered_agents: List[Dict[str, Any]] = []
        for index in range(1, count + 1):
            hostname = f"{self.prefix}_classroom_{index:03d}"
            device_id = f"{self.prefix}_classroom_device_{index:03d}"
            agent = self.register_test_agent(hostname, device_id, f"deep_classroom_register_{index:03d}")
            target_group_id = group_a_id if index <= (count + 1) // 2 else group_b_id
            target_group_key = "a" if target_group_id == group_a_id else "b"
            self.admin.request(
                "PATCH",
                f"/api/agents/{agent['agent_id']}/group",
                expected=(200,),
                json_body={"group_id": target_group_id},
                check_success=True,
                label=f"deep_classroom_move_{index:03d}",
            )
            agent["group_key"] = target_group_key
            agent["group_id"] = target_group_id
            self.send_registered_agent_heartbeat(agent)
            self.sync_registered_agent(agent)
            self.send_registered_agent_logs(
                agent,
                [
                    {
                        "level": "INFO",
                        "action": "CLASSROOM_SCALE_HEARTBEAT",
                        "message": f"{self.prefix} classroom synthetic endpoint {index}",
                        "domain": f"classroom-{index:03d}.example.test",
                    }
                ],
            )
            registered_agents.append(agent)
            self.state["extra_agents"].append(agent)
            if target_group_key == "a":
                group_a_agents.append(agent)
            else:
                group_b_agents.append(agent)

        admin_list = self.admin.request("GET", "/api/agents", params={"hostname": f"{self.prefix}_classroom"}, expected=(200,), check_success=True)
        teacher_list = self.teacher.request("GET", "/api/agents", params={"hostname": f"{self.prefix}_classroom"}, expected=(200,), check_success=True)
        teacher_group_a_checks = [
            self.teacher.request("GET", f"/api/agents/{agent['agent_id']}", expected=(200,), check_success=True)
            for agent in group_a_agents[:3]
        ]
        teacher_group_b_denied = [
            self.teacher.request("GET", f"/api/agents/{agent['agent_id']}", expected=(403,))
            for agent in group_b_agents[:3]
        ]
        admin_stats = self.admin.request("GET", "/api/agents/statistics", expected=(200,), check_success=True)
        if len(registered_agents) != count:
            raise StepFailure("Classroom scale registration count mismatch", matrix)
        if not group_a_agents or (count > 1 and not group_b_agents):
            raise StepFailure("Classroom scale did not distribute agents across groups", matrix)

        matrix["cases"]["registration_heartbeat_sync_logs"] = {
            "passed": True,
            "registered_count": len(registered_agents),
            "group_a_count": len(group_a_agents),
            "group_b_count": len(group_b_agents),
        }
        matrix["cases"]["admin_teacher_scope"] = {
            "passed": True,
            "admin_list_summary": self.payload_list_summary(admin_list),
            "teacher_list_summary": self.payload_list_summary(teacher_list),
            "teacher_group_a_get_checks": len(teacher_group_a_checks),
            "teacher_group_b_denied_checks": len(teacher_group_b_denied),
            "admin_stats": admin_stats,
        }
        matrix["note"] = "This is server-side synthetic scale from one Windows runner, not a physical multi-PC lab run."
        matrix["passed"] = True
        return matrix

    def step_deep_service_autostart_matrix(self) -> Dict[str, Any]:
        matrix: Dict[str, Any] = {
            "passed": False,
            "actual_reboot_performed": False,
            "cases": {},
        }
        self.deep_service_autostart_matrix = matrix
        exe_meta = self.verify_exe_metadata()
        service_script = r"""
$services = Get-Service | Where-Object {
    $_.Name -match 'SAINT|FirewallController|Firewall Controller' -or
    $_.DisplayName -match 'SAINT|Firewall Controller|Network Access Control'
} | Select-Object Name,DisplayName,Status,StartType
@($services) | ConvertTo-Json -Depth 4 -Compress
"""
        startup_script = r"""
$registry = @()
foreach ($path in @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)) {
    if (Test-Path $path) {
        $props = Get-ItemProperty -Path $path
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -notlike 'PS*' -and "$($prop.Value)" -match 'SAINT|FirewallController|Firewall Controller') {
                $registry += [pscustomobject]@{Path=$path; Name=$prop.Name; Value="$($prop.Value)"}
            }
        }
    }
}
$startup = @()
foreach ($dir in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
    if ($dir -and (Test-Path $dir)) {
        Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match 'SAINT|FirewallController|Firewall Controller'
        } | ForEach-Object {
            $startup += [pscustomobject]@{Directory=$dir; Name=$_.Name; FullName=$_.FullName}
        }
    }
}
[pscustomobject]@{RegistryRun=$registry; StartupFolder=$startup} | ConvertTo-Json -Depth 6 -Compress
"""
        services = self.run_powershell_json(service_script, "deep_service_autostart_services", timeout=30)
        startup = self.run_powershell_json(startup_script, "deep_service_autostart_startup", timeout=30)
        post_reboot_script = self.output_dir / "post_reboot_autostart_check.ps1"
        post_reboot_output = self.output_dir / f"post_reboot_autostart_{self.run_id}.json"
        post_reboot_script.write_text(
            self.post_reboot_check_ps1(str(post_reboot_output)),
            encoding="utf-8",
        )
        service_items = [
            item for item in self.ensure_list(services.get("parsed"))
            if isinstance(item, dict) and any(item.values())
        ]
        startup_data = startup.get("parsed") if isinstance(startup.get("parsed"), dict) else {}
        registry_items = [
            item for item in self.ensure_list(startup_data.get("RegistryRun"))
            if isinstance(item, dict) and any(item.values())
        ]
        startup_items = [
            item for item in self.ensure_list(startup_data.get("StartupFolder"))
            if isinstance(item, dict) and any(item.values())
        ]
        configured = bool(service_items or registry_items or startup_items)
        automatic_services = [
            item for item in service_items
            if str(item.get("StartType", "")).lower() in ("automatic", "automaticdelayedstart")
        ]
        matrix["cases"]["exe_artifact"] = {"passed": True, **exe_meta}
        matrix["cases"]["service_inventory"] = {
            "passed": True,
            "services": service_items,
            "automatic_service_count": len(automatic_services),
        }
        matrix["cases"]["autostart_inventory"] = {
            "passed": True,
            "registry_run": registry_items,
            "startup_folder": startup_items,
        }
        matrix["service_or_autostart_configured"] = configured
        matrix["note"] = "The runner does not reboot Windows; it verifies whether persistence is configured before a manual reboot test."
        matrix["post_reboot_check_script"] = str(post_reboot_script)
        matrix["post_reboot_expected_output"] = str(post_reboot_output)
        matrix["passed"] = True
        return matrix

    def step_deep_gui_click_matrix(self) -> Dict[str, Any]:
        self.require_clients()
        node = shutil.which("node")
        matrix: Dict[str, Any] = {
            "passed": False,
            "tool": "node + @playwright/test",
            "node": node,
            "cases": {},
        }
        self.deep_gui_matrix = matrix
        if not node:
            self.add_coverage_note("GUI click-by-click skipped because node.exe is not available")
            raise StepFailure("Node.js not found for Playwright GUI click smoke", matrix)
        playwright_package = REPO_ROOT / "node_modules" / "@playwright" / "test"
        if not playwright_package.exists():
            self.add_coverage_note("GUI click-by-click skipped because @playwright/test is not installed")
            raise StepFailure("@playwright/test is not installed; run npm install before deep GUI smoke", matrix)

        script_path = self.output_dir / "deep_gui_click_smoke.js"
        script_path.write_text(self.gui_click_smoke_js(), encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "SAINT_E2E_SERVER_URL": self.server_url,
                "SAINT_E2E_USERNAME": self.temp_admin_username,
                "SAINT_E2E_PASSWORD": self.temp_admin_password,
            }
        )
        result = subprocess.run(
            [node, str(script_path)],
            cwd=str(REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.args.deep_gui_timeout_seconds,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        parsed = self.parse_last_json_object(result.stdout)
        matrix["returncode"] = result.returncode
        matrix["stdout_tail"] = truncate_text(result.stdout[-4000:])
        matrix["stderr_tail"] = truncate_text(result.stderr[-4000:])
        matrix["parsed"] = parsed
        if result.returncode != 0 or not parsed.get("ok"):
            raise StepFailure("Playwright GUI click smoke failed", matrix)
        matrix["cases"]["login_and_navigation_clicks"] = {
            "passed": True,
            "steps": parsed.get("steps", []),
            "http_errors": parsed.get("httpErrors", []),
            "browser": parsed.get("browser"),
        }
        matrix["passed"] = True
        return matrix

    def step_deep_websocket_realtime_matrix(self) -> Dict[str, Any]:
        self.require_clients()
        assert self.admin is not None
        matrix: Dict[str, Any] = {
            "passed": False,
            "events": [],
            "cases": {},
        }
        self.deep_websocket_matrix = matrix
        try:
            import socketio  # type: ignore[import-not-found]
        except Exception as exc:  # noqa: BLE001
            self.add_coverage_note("Socket.IO realtime skipped because python-socketio is not installed")
            raise StepFailure("python-socketio is not available for realtime smoke", {"error": str(exc), **matrix})

        events: List[Dict[str, Any]] = []
        sio = socketio.Client(reconnection=False, logger=False, engineio_logger=False, request_timeout=self.args.timeout_seconds)

        def record(name: str, payload: Any = None) -> None:
            events.append({"event": name, "payload": self.redactor.sanitize(payload), "at": datetime.now().isoformat(timespec="seconds")})

        @sio.event
        def connect():  # type: ignore[no-untyped-def]
            record("connect")

        @sio.event
        def disconnect():  # type: ignore[no-untyped-def]
            record("disconnect")

        @sio.on("server_message")
        def on_server_message(data):  # type: ignore[no-untyped-def]
            record("server_message", data)

        @sio.on("pong")
        def on_pong(data):  # type: ignore[no-untyped-def]
            record("pong", data)

        for event_name in ("whitelist_updated", "whitelist_added", "agent_heartbeat", "new_log"):
            sio.on(event_name, lambda data, event_name=event_name: record(event_name, data))

        try:
            sio.connect(self.server_url, transports=["polling", "websocket"], wait_timeout=self.args.deep_websocket_timeout_seconds)
            sio.emit("ping", {"run_id": self.run_id, "prefix": self.prefix})
            self.wait_for_event(events, "pong", self.args.deep_websocket_timeout_seconds)
            realtime_value = f"{self.domain_prefix}-socketio-realtime.example.com"
            created = self.admin.request(
                "POST",
                "/api/whitelist",
                expected=(201,),
                json_body={"type": "domain", "value": realtime_value, "category": "deep-realtime"},
                check_success=True,
                label="deep_socketio_whitelist_add",
            )
            created_id = created.get("_id") or created.get("id") or created.get("data", {}).get("_id") or created.get("data", {}).get("id")
            self.assert_real_id(created_id, "deep socketio whitelist entry")
            self.track_whitelist_id(created_id)
            self.wait_for_any_event(events, {"whitelist_updated", "whitelist_added"}, self.args.deep_websocket_timeout_seconds)
        finally:
            if sio.connected:
                sio.disconnect()
        matrix["events"] = events
        event_names = [item.get("event") for item in events]
        matrix["cases"]["connect_ping_pong"] = {
            "passed": "connect" in event_names and "pong" in event_names,
            "event_names": event_names,
        }
        matrix["cases"]["whitelist_realtime_event"] = {
            "passed": bool({"whitelist_updated", "whitelist_added"}.intersection(event_names)),
            "event_names": event_names,
        }
        if not matrix["cases"]["connect_ping_pong"]["passed"] or not matrix["cases"]["whitelist_realtime_event"]["passed"]:
            raise StepFailure("Socket.IO realtime event matrix did not receive required events", matrix)
        matrix["passed"] = True
        return matrix

    def step_deep_long_soak_matrix(self) -> Dict[str, Any]:
        self.require_agent()
        minutes = float(self.args.deep_soak_minutes)
        interval = int(self.args.deep_soak_interval_seconds)
        matrix: Dict[str, Any] = {
            "passed": False,
            "requested_minutes": minutes,
            "interval_seconds": interval,
            "samples": [],
        }
        self.deep_soak_matrix = matrix
        deadline = time.monotonic() + (minutes * 60.0)
        sample_index = 0
        public_client = self.make_client("deep_soak_public")
        extra_agents = list(self.state.get("extra_agents", []))
        while True:
            sample_index += 1
            sample_started = time.monotonic()
            sample: Dict[str, Any] = {
                "sample": sample_index,
                "at": datetime.now().isoformat(timespec="seconds"),
            }
            health = public_client.request("GET", "/api/health", expected=(200,), use_bearer=False)
            heartbeat = self.send_agent_heartbeat()
            sync = self.agent_sync(policy_mode="none")
            log_send = self.send_agent_logs(
                [
                    {
                        "level": "INFO",
                        "action": "DEEP_SOAK_SAMPLE",
                        "message": f"{self.prefix} soak sample {sample_index}",
                        "domain": f"soak-{sample_index:03d}.example.test",
                    }
                ]
            )
            sample.update(
                {
                    "duration_ms": int((time.monotonic() - sample_started) * 1000),
                    "health_status": health.get("status") or health.get("data", {}).get("status"),
                    "heartbeat_success": heartbeat.get("success"),
                    "sync_success": sync.get("success"),
                    "sync_count": sync.get("count"),
                    "log_success": log_send.get("success"),
                }
            )
            if extra_agents:
                extra = extra_agents[(sample_index - 1) % len(extra_agents)]
                extra_heartbeat = self.send_registered_agent_heartbeat(extra)
                sample["extra_agent_id"] = extra.get("agent_id")
                sample["extra_heartbeat_success"] = extra_heartbeat.get("success")
            matrix["samples"].append(sample)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))
        matrix["actual_samples"] = len(matrix["samples"])
        matrix["actual_duration_seconds"] = round(minutes * 60.0, 3)
        matrix["passed"] = True
        return matrix

    def step_logs_and_audit_contract(self) -> Dict[str, Any]:
        self.require_clients()
        self.require_agent()
        assert self.admin is not None and self.teacher is not None
        details: Dict[str, Any] = {}
        details["admin_logs"] = self.admin.request("GET", "/api/logs", params={"agent_id": self.agent_id, "limit": 20}, expected=(200,), check_success=None)
        logs = details["admin_logs"].get("logs") or details["admin_logs"].get("data", {}).get("logs") or []
        self.state["log_ids"] = [str(log.get("_id") or log.get("id")) for log in logs if log.get("_id") or log.get("id")]
        details["admin_log_stats"] = self.admin.request("GET", "/api/logs/stats", expected=(200,), check_success=True)
        details["admin_log_export"] = self.admin.request("GET", "/api/logs/export", params={"format": "json", "agent_id": self.agent_id}, expected=(200,), check_success=True)
        details["teacher_logs"] = self.teacher.request("GET", "/api/logs", params={"agent_id": self.agent_id, "limit": 20}, expected=(200,), check_success=None)
        details["teacher_clear_denied"] = self.teacher.request("DELETE", "/api/logs/clear", expected=(403,), json_body={"action": "selected", "log_ids": self.state["log_ids"][:1]})
        details["teacher_export_denied"] = self.teacher.request("GET", "/api/logs/export", params={"format": "json"}, expected=(403,))
        details["audit_list"] = self.admin.request("GET", "/api/admin/audit", params={"username": self.temp_admin_username, "limit": 50}, expected=(200,), check_success=True)
        teacher_id = self.state["temp_teacher"].get("_id")
        if teacher_id:
            details["audit_teacher_activity"] = self.admin.request("GET", f"/api/admin/audit/user/{teacher_id}", params={"limit": 50}, expected=(200,), check_success=True)
        # Delete only test log rows if the server returned concrete ids.
        if self.state["log_ids"]:
            details["admin_clear_selected_logs"] = self.admin.request(
                "DELETE",
                "/api/logs/clear",
                expected=(200,),
                json_body={"action": "selected", "log_ids": self.state["log_ids"][:50]},
                check_success=True,
            )
        return details

    def step_real_firewall_contract(self) -> Dict[str, Any]:
        self.require_agent()
        add_agent_path()
        self.configure_firewall_env()

        from firewall.manager import FirewallManager  # pylint: disable=import-error

        manager = FirewallManager(rule_prefix=self.firewall_rule_prefix)
        before_policy = manager.get_firewall_policy_status()
        snapshot_saved = manager.save_snapshot(str(self.firewall_snapshot_path), force=True)
        if not snapshot_saved:
            raise StepFailure("Firewall snapshot save failed", {"snapshot": str(self.firewall_snapshot_path), "before_policy": before_policy})
        snapshot_policies = self.read_firewall_snapshot_policies()
        if not snapshot_policies:
            repair = self.force_firewall_default_allow("snapshot_missing_profile_policies")
            raise StepFailure(
                "Firewall snapshot has no profile policies; refusing to enable Default Deny",
                {
                    "snapshot": str(self.firewall_snapshot_path),
                    "before_policy": before_policy,
                    "repair": repair,
                },
            )
        required_profiles = {"domain", "private", "public"}
        packet_matrix: Dict[str, Any] = {
            "passed": False,
            "snapshot_policies": snapshot_policies,
            "cases": {},
        }
        allowed_ip = self.args.firewall_test_ip
        blocked_ip: Optional[str] = None
        if self.args.deep:
            self.deep_firewall_packet_matrix = packet_matrix
            missing_profiles = sorted(required_profiles - set(snapshot_policies))
            if missing_profiles:
                raise StepFailure(
                    "Firewall snapshot is missing required profile policies",
                    {"snapshot": str(self.firewall_snapshot_path), "missing_profiles": missing_profiles, "policies": snapshot_policies},
                )
            allowed_ip = self.args.deep_allowed_ip
            allowed_preflight = self.tcp_probe(allowed_ip, self.args.deep_allowed_port, "deep_allowed_preflight")
            packet_matrix["cases"]["allowed_preflight"] = allowed_preflight
            if not allowed_preflight.get("ok"):
                raise StepFailure("Deep allowed IP is not reachable before firewall mutation", packet_matrix)
            blocked_ip, blocked_preflight = self.select_blocked_packet_candidate(allowed_ip)
            packet_matrix["blocked_ip"] = blocked_ip
            packet_matrix["cases"]["blocked_preflight"] = blocked_preflight

        enabled = False
        restored = False
        cleared = False
        forced_default_allow = None
        exe_launch = {}
        active_policy: Dict[str, Any] = {}
        health: Dict[str, Any] = {}
        heartbeat: Dict[str, Any] = {}
        log_send: Dict[str, Any] = {}
        created_rule = False
        removed_rule = False
        try:
            if DEFAULT_EXE.exists():
                manager.rules_manager.create_self_allow_rules(str(DEFAULT_EXE))
            enabled = manager.enable_whitelist_mode(
                server_urls=[self.server_url],
                whitelist_ips={allowed_ip},
                whitelist_domains=set(),
            )
            if not enabled:
                raise StepFailure("enable_whitelist_mode returned False")
            active_policy = manager.get_firewall_policy_status()
            if self.args.deep:
                if not self.profiles_are_all_block(active_policy.get("profiles") or {}):
                    raise StepFailure("Default Deny did not set every outbound profile to block", {"active_policy": active_policy})
                packet_matrix["cases"]["active_policy_block"] = active_policy
                self_allow_before = self.firewall_rule_summary(manager)
                manager.rules_manager.create_self_allow_rules(sys.executable)
                self_allow_after = self.firewall_rule_summary(manager)
                if self_allow_after.get("self_allow_count") != 3 or self_allow_after.get("duplicate_rule_names"):
                    raise StepFailure("Self-allow rules are missing or duplicated", {"before": self_allow_before, "after": self_allow_after})
                packet_matrix["cases"]["self_allow_idempotent"] = {"before": self_allow_before, "after": self_allow_after}

                allowed_active = self.tcp_probe(allowed_ip, self.args.deep_allowed_port, "deep_allowed_active")
                packet_matrix["cases"]["allowed_active"] = allowed_active
                if not allowed_active.get("ok"):
                    raise StepFailure("Allowed packet probe failed while Default Deny was active", packet_matrix)
                if blocked_ip:
                    blocked_active = self.tcp_probe(blocked_ip, self.args.deep_allowed_port, "deep_blocked_active")
                    packet_matrix["cases"]["blocked_active"] = blocked_active
                    if blocked_active.get("ok"):
                        raise StepFailure("Blocked packet probe unexpectedly succeeded while Default Deny was active", packet_matrix)

                before_rules = self.firewall_rule_summary(manager)
                created_rule = manager.rules_manager.create_allow_rule(self.args.deep_mutation_ip)
                after_add_rules = self.firewall_rule_summary(manager)
                removed_rule = manager.rules_manager.remove_allow_rule(self.args.deep_mutation_ip)
                after_remove_rules = self.firewall_rule_summary(manager)
                if not created_rule or not removed_rule:
                    raise StepFailure("Deep firewall add/remove rule mutation failed", {"created": created_rule, "removed": removed_rule})
                if after_add_rules.get("allow_rule_count", 0) <= before_rules.get("allow_rule_count", 0):
                    raise StepFailure("Deep firewall add rule did not increase managed allow rules", {"before": before_rules, "after_add": after_add_rules})
                if after_remove_rules.get("allow_rule_count", 0) > before_rules.get("allow_rule_count", 0):
                    raise StepFailure("Deep firewall remove rule did not restore managed allow rule count", {"before": before_rules, "after_remove": after_remove_rules})
                packet_matrix["cases"]["managed_rule_add_remove"] = {
                    "mutation_ip": self.args.deep_mutation_ip,
                    "before": before_rules,
                    "after_add": after_add_rules,
                    "after_remove": after_remove_rules,
                }
            health = requests.get(self.server_url.rstrip("/") + "/api/health", timeout=self.args.timeout_seconds).json()
            heartbeat = self.send_agent_heartbeat()
            log_send = self.send_agent_logs([
                {"level": "INFO", "action": "FIREWALL_E2E", "message": f"{self.prefix} firewall active log", "is_lifecycle_event": True}
            ])
            if not self.args.deep:
                created_rule = manager.rules_manager.create_allow_rule(self.args.firewall_test_ip)
                removed_rule = manager.rules_manager.remove_allow_rule(self.args.firewall_test_ip)
            if not self.args.skip_agent_exe_launch:
                exe_launch = self.launch_agent_exe_smoke()
            if self.args.deep:
                packet_matrix["passed"] = True
            return {
                "snapshot": str(self.firewall_snapshot_path),
                "before_policy": before_policy,
                "enabled": enabled,
                "active_policy": active_policy,
                "health": health,
                "heartbeat": heartbeat,
                "log_send": log_send,
                "rule_create": created_rule,
                "rule_remove": removed_rule,
                "exe_launch": exe_launch,
                "deep_packet_matrix": packet_matrix if self.args.deep else {},
            }
        finally:
            try:
                restored = manager.restore_snapshot(str(self.firewall_snapshot_path))
            finally:
                try:
                    cleared = manager.clear_all_rules()
                except Exception:
                    cleared = False
                after_policy = manager.get_firewall_policy_status()
                profiles = after_policy.get("profiles") or {}
                if not profiles or self.profiles_are_all_block(profiles):
                    forced_default_allow = manager.policy_manager.restore_default_policy()
                    after_policy = manager.get_firewall_policy_status()
                residual_rules = self.firewall_rule_summary(manager)
                post_restore_packet = None
                if self.args.deep:
                    if not self.profiles_are_all_allow(after_policy.get("profiles") or {}):
                        forced_default_allow = manager.policy_manager.restore_default_policy()
                        after_policy = manager.get_firewall_policy_status()
                    if blocked_ip:
                        post_restore_packet = self.tcp_probe(blocked_ip, self.args.deep_allowed_port, "deep_blocked_post_restore")
                        packet_matrix["cases"]["blocked_post_restore"] = post_restore_packet
                    packet_matrix["post_restore_policy"] = after_policy
                    packet_matrix["post_restore_rules"] = residual_rules
                    packet_matrix["passed"] = bool(
                        packet_matrix.get("passed")
                        and self.profiles_are_all_allow(after_policy.get("profiles") or {})
                        and residual_rules.get("total_count") == 0
                        and (post_restore_packet is None or post_restore_packet.get("ok"))
                    )
                    self.deep_firewall_packet_matrix = packet_matrix
                cleanup_ok = (
                    restored
                    and cleared
                    and forced_default_allow is not False
                    and self.profiles_are_all_allow(after_policy.get("profiles") or {})
                    and residual_rules.get("total_count") == 0
                    and (post_restore_packet is None or post_restore_packet.get("ok"))
                )
                self.cleanup_results.append(
                    self.redactor.sanitize(
                        {
                            "name": "firewall_restore",
                            "status": "CLEANUP_OK" if cleanup_ok else "CLEANUP_FAIL",
                            "restore_ok": restored,
                            "clear_rules_ok": cleared,
                            "forced_default_allow": forced_default_allow,
                            "after_policy": after_policy,
                            "residual_rules": residual_rules,
                            "post_restore_packet": post_restore_packet,
                        }
                    )
                )

    def cleanup(self) -> None:
        if self.args.dry_run or self.args.keep_test_data:
            self.cleanup_results.append({"name": "cleanup", "status": "SKIP", "reason": "dry_run or keep_test_data"})
            return
        # Firewall/process cleanup is local and must run first.
        self.cleanup_agent_process()
        if self.args.run_real_firewall_policy:
            self.cleanup_firewall_best_effort()
        if not self.bootstrap:
            self.cleanup_results.append({"name": "server_cleanup", "status": "SKIP", "reason": "bootstrap client unavailable"})
            return
        self.cleanup_agent_policy()
        self.cleanup_api_key()
        self.cleanup_whitelist()
        self.cleanup_profiles()
        self.cleanup_extra_agents()
        self.cleanup_agent()
        self.cleanup_groups()
        self.cleanup_users()

    def cleanup_call(self, name: str, func: Callable[[], Any]) -> None:
        started = time.monotonic()
        try:
            details = func()
            self.cleanup_results.append(
                self.redactor.sanitize(
                    {
                        "name": name,
                        "status": "CLEANUP_OK",
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "details": details,
                    }
                )
            )
        except Exception as exc:  # noqa: BLE001
            self.cleanup_results.append(
                self.redactor.sanitize(
                    {
                        "name": name,
                        "status": "CLEANUP_FAIL",
                        "duration_ms": int((time.monotonic() - started) * 1000),
                        "error": self.redactor.mask_text(str(exc)),
                        "traceback": self.redactor.mask_text(traceback.format_exc()),
                    }
                )
            )

    def cleanup_agent_policy(self) -> None:
        if not self.admin or not self.agent_id:
            return
        self.cleanup_call(
            "reset_agent_policy",
            lambda: self.admin.request(
                "PATCH",
                f"/api/agents/{self.agent_id}/policy",
                expected=(200, 400, 404),
                json_body={"mode": "none", "reason": f"{self.prefix} cleanup"},
            ),
        )

    def cleanup_api_key(self) -> None:
        key_id = self.state.get("api_key", {}).get("key_id")
        if not key_id or not self.bootstrap:
            return
        self.cleanup_call(
            "revoke_api_key",
            lambda: self.bootstrap.request("POST", f"/api/api-keys/{key_id}/revoke", expected=(200, 400, 404), check_success=None),
        )

    def cleanup_whitelist(self) -> None:
        if not self.bootstrap:
            return
        for item_id in list(reversed(self.state.get("whitelist_ids", []))):
            self.cleanup_call(
                f"delete_whitelist_{item_id}",
                lambda item_id=item_id: self.bootstrap.request("DELETE", f"/api/whitelist/{item_id}", expected=(200, 400, 403, 404), check_success=None),
            )

    def cleanup_profiles(self) -> None:
        if not self.bootstrap:
            return
        for profile in list(reversed(self.state.get("profiles", []))):
            group_id = profile.get("group_id")
            profile_id = profile.get("profile_id")
            if not group_id or not profile_id:
                continue
            self.cleanup_call(
                f"deactivate_profile_{profile_id}",
                lambda group_id=group_id, profile_id=profile_id: self.bootstrap.request("POST", f"/api/groups/{group_id}/profiles/{profile_id}/deactivate", expected=(200, 400, 403, 404), check_success=None),
            )
            self.cleanup_call(
                f"delete_profile_{profile_id}",
                lambda group_id=group_id, profile_id=profile_id: self.bootstrap.request("DELETE", f"/api/groups/{group_id}/profiles/{profile_id}", expected=(200, 400, 403, 404), check_success=None),
            )

    def cleanup_agent(self) -> None:
        if not self.bootstrap or not self.agent_id or self.state.get("agent_deleted"):
            return
        self.cleanup_call(
            "delete_agent",
            lambda: self.bootstrap.request("DELETE", f"/api/agents/{self.agent_id}", expected=(200, 400, 403, 404), check_success=None),
        )

    def cleanup_extra_agents(self) -> None:
        if not self.bootstrap:
            return
        for agent in list(reversed(self.state.get("extra_agents", []))):
            agent_id = agent.get("agent_id")
            if not agent_id:
                continue
            self.cleanup_call(
                f"delete_extra_agent_{agent_id}",
                lambda agent_id=agent_id: self.bootstrap.request("DELETE", f"/api/agents/{agent_id}", expected=(200, 400, 403, 404), check_success=None),
            )

    def cleanup_groups(self) -> None:
        if not self.bootstrap:
            return
        for key in ("b", "a"):
            group_id = self.state.get("groups", {}).get(key)
            if group_id:
                self.cleanup_call(
                    f"delete_group_{key}",
                    lambda group_id=group_id: self.bootstrap.request("DELETE", f"/api/groups/{group_id}", expected=(200, 400, 403, 404), check_success=None),
                )

    def cleanup_users(self) -> None:
        if not self.bootstrap:
            return
        for key in ("temp_teacher", "temp_admin"):
            user_id = self.state.get(key, {}).get("_id")
            if user_id:
                self.cleanup_call(
                    f"delete_user_{key}",
                    lambda user_id=user_id: self.bootstrap.request("DELETE", f"/api/admin/users/{user_id}", expected=(200, 400, 403, 404), check_success=None),
                )

    def cleanup_agent_process(self) -> None:
        proc = self.agent_process
        if not proc:
            return
        def _stop() -> Dict[str, Any]:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            return {"returncode": proc.poll()}
        self.cleanup_call("stop_agent_exe_process", _stop)

    def cleanup_firewall_best_effort(self) -> None:
        try:
            add_agent_path()
            self.configure_firewall_env()
            from firewall.manager import FirewallManager  # pylint: disable=import-error
            manager = FirewallManager(rule_prefix=self.firewall_rule_prefix)
            def _restore() -> Dict[str, Any]:
                restored = True
                if self.firewall_snapshot_path.exists():
                    restored = manager.restore_snapshot(str(self.firewall_snapshot_path))
                cleared = manager.clear_all_rules()
                after_policy = manager.get_firewall_policy_status()
                profiles = after_policy.get("profiles") or {}
                forced_default_allow = None
                if not profiles or self.profiles_are_all_block(profiles):
                    forced_default_allow = manager.policy_manager.restore_default_policy()
                    after_policy = manager.get_firewall_policy_status()
                return {
                    "restore_ok": restored,
                    "clear_rules_ok": cleared,
                    "forced_default_allow": forced_default_allow,
                    "after_policy": after_policy,
                }
            self.cleanup_call("firewall_best_effort_restore", _restore)
        except Exception as exc:
            self.cleanup_results.append({"name": "firewall_best_effort_restore", "status": "CLEANUP_FAIL", "error": str(exc)})

    def agent_api_request(
        self,
        method: str,
        path: str,
        *,
        expected: Tuple[int, ...] = (200,),
        json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        check_success: Optional[bool] = None,
        use_agent_bearer: bool = True,
    ) -> Dict[str, Any]:
        client = self.make_client("agent_api")
        if use_agent_bearer and self.agent_access_token:
            client.access_token = self.agent_access_token
        return client.request(
            method,
            path,
            expected=expected,
            json_body=json_body,
            params=params,
            use_bearer=use_agent_bearer,
            use_csrf=False,
            check_success=check_success,
        )

    def send_agent_heartbeat(self) -> Dict[str, Any]:
        self.require_agent()
        return self.agent_api_request(
            "POST",
            "/api/agents/heartbeat",
            expected=(200,),
            json_body={
                "agent_id": self.agent_id,
                "token": self.agent_token,
                "device_id": self.agent_device_id,
                "timestamp": datetime.now().isoformat(),
                "metrics": {"memory_percent": 1, "disk_percent": 1, "uptime_seconds": int(time.time())},
                "status": "active",
                "platform": platform.system(),
                "os_info": platform.platform(),
                "agent_version": "e2e",
            },
            check_success=True,
        )

    def send_agent_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.require_agent()
        normalized = []
        for log in logs:
            item = {
                "timestamp": datetime.now().isoformat(),
                "agent_id": self.agent_id,
                "source": "saint_full_system_e2e",
                "domain": log.get("domain", "e2e.local"),
                "destination": log.get("destination", "e2e.local"),
                "source_ip": self.local_ip(),
                "dest_ip": log.get("dest_ip", "203.0.113.10"),
                "protocol": log.get("protocol", "HTTPS"),
                "port": str(log.get("port", "443")),
                **log,
            }
            normalized.append(item)
        return self.agent_api_request(
            "POST",
            "/api/logs",
            expected=(200, 201, 202),
            json_body={"agent_id": self.agent_id, "logs": normalized},
            check_success=True,
        )

    def agent_sync(
        self,
        *,
        policy_mode: str = "none",
        global_version: Any = None,
        group_version: Any = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "agent_id": self.agent_id,
            "policy_mode": policy_mode,
            "timestamp": datetime.now().isoformat(),
        }
        if global_version is not None:
            params["global_version"] = global_version
        if group_version is not None:
            params["group_version"] = group_version
        return self.agent_api_request(
            "GET",
            "/api/whitelist/agent-sync",
            params=params,
            expected=(200,),
            check_success=True,
        )

    def register_test_agent(self, hostname: str, device_id: str, label: str) -> Dict[str, Any]:
        api_key = self.state["api_key"].get("api_key")
        if not api_key:
            raise StepFailure("Temporary API key is not available")
        payload = {
            "hostname": hostname,
            "device_id": device_id,
            "ip_address": self.local_ip(),
            "platform": platform.system(),
            "os_info": platform.platform(),
            "agent_version": "e2e-deep",
            "admin_privileges": is_admin(),
            "capabilities": {
                "packet_capture": True,
                "firewall_management": is_admin(),
                "whitelist_sync": True,
                "classroom_scale": True,
            },
        }
        client = self.make_client(label)
        registered = client.request(
            "POST",
            "/api/agents/register",
            expected=(200,),
            json_body=payload,
            headers={"X-API-Key": api_key},
            use_bearer=False,
            check_success=True,
            label=label,
        )
        data = registered.get("data", {})
        jwt_data = data.get("jwt", {})
        agent = {
            "agent_id": data.get("agent_id"),
            "token": data.get("token"),
            "access_token": jwt_data.get("access_token"),
            "refresh_token": jwt_data.get("refresh_token"),
            "hostname": hostname,
            "device_id": device_id,
            "label": label,
        }
        self.redactor.add_many([agent.get("token"), agent.get("access_token"), agent.get("refresh_token")])
        if not agent["agent_id"] or not agent["token"] or not agent["access_token"]:
            raise StepFailure("Registered test agent response missing credentials", {"registered": registered, "agent": agent})
        return agent

    def agent_request_for(
        self,
        agent: Dict[str, Any],
        method: str,
        path: str,
        *,
        expected: Tuple[int, ...] = (200,),
        json_body: Any = None,
        params: Optional[Dict[str, Any]] = None,
        check_success: Optional[bool] = None,
    ) -> Dict[str, Any]:
        client = self.make_client(str(agent.get("label") or agent.get("hostname") or "registered_agent"))
        client.access_token = agent.get("access_token")
        return client.request(
            method,
            path,
            expected=expected,
            json_body=json_body,
            params=params,
            use_bearer=True,
            use_csrf=False,
            check_success=check_success,
        )

    def send_registered_agent_heartbeat(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        return self.agent_request_for(
            agent,
            "POST",
            "/api/agents/heartbeat",
            expected=(200,),
            json_body={
                "agent_id": agent.get("agent_id"),
                "token": agent.get("token"),
                "device_id": agent.get("device_id"),
                "timestamp": datetime.now().isoformat(),
                "metrics": {"memory_percent": 2, "disk_percent": 2, "uptime_seconds": int(time.time())},
                "status": "active",
                "platform": platform.system(),
                "os_info": platform.platform(),
                "agent_version": "e2e-deep",
            },
            check_success=True,
        )

    def send_registered_agent_logs(self, agent: Dict[str, Any], logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        normalized = []
        for log in logs:
            item = {
                "timestamp": datetime.now().isoformat(),
                "agent_id": agent.get("agent_id"),
                "source": "saint_full_system_e2e_deep",
                "domain": log.get("domain", "e2e.local"),
                "destination": log.get("destination", "e2e.local"),
                "source_ip": self.local_ip(),
                "dest_ip": log.get("dest_ip", "203.0.113.10"),
                "protocol": log.get("protocol", "HTTPS"),
                "port": str(log.get("port", "443")),
                **log,
            }
            normalized.append(item)
        return self.agent_request_for(
            agent,
            "POST",
            "/api/logs",
            expected=(200, 201, 202),
            json_body={"agent_id": agent.get("agent_id"), "logs": normalized},
            check_success=True,
        )

    def sync_registered_agent(self, agent: Dict[str, Any], *, policy_mode: str = "none") -> Dict[str, Any]:
        return self.agent_request_for(
            agent,
            "GET",
            "/api/whitelist/agent-sync",
            params={"agent_id": agent.get("agent_id"), "policy_mode": policy_mode, "timestamp": datetime.now().isoformat()},
            expected=(200,),
            check_success=True,
        )

    @staticmethod
    def entry_value(entry: Dict[str, Any]) -> str:
        return str(entry.get("value") or entry.get("domain") or "").strip().lower()

    def entries_for_value(self, entries: Any, value: str) -> List[Dict[str, Any]]:
        wanted = value.strip().lower()
        if not isinstance(entries, list):
            return []
        return [
            entry for entry in entries
            if isinstance(entry, dict) and self.entry_value(entry) == wanted
        ]

    def single_value_entry(self, entries: Any, value: str) -> Dict[str, Any]:
        found = self.entries_for_value(entries, value)
        if len(found) != 1:
            raise StepFailure(
                f"Expected exactly one entry for {value}, found {len(found)}",
                {"value": value, "entries": found},
            )
        return found[0]

    def find_whitelist_ids(self, group_id: str, values: List[str]) -> List[str]:
        self.require_clients()
        assert self.admin is not None
        scoped = self.admin.request("GET", "/api/whitelist", params={"group_id": group_id}, expected=(200,), check_success=True)
        rows = []
        for key in ("merged", "domains", "items", "whitelist", "group"):
            if isinstance(scoped.get(key), list):
                rows.extend(scoped[key])
        found: List[str] = []
        seen: set[str] = set()
        wanted = set(values)
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get("value") or row.get("domain")
            row_id = row.get("_id") or row.get("id")
            if value in wanted and row_id and str(row_id) not in seen:
                seen.add(str(row_id))
                found.append(str(row_id))
        return found

    def track_whitelist_id(self, item_id: Any) -> None:
        if item_id and str(item_id) not in self.state["whitelist_ids"]:
            self.state["whitelist_ids"].append(str(item_id))

    def untrack_whitelist_id(self, item_id: Any) -> None:
        if item_id:
            self.state["whitelist_ids"] = [x for x in self.state["whitelist_ids"] if x != str(item_id)]

    def assert_real_id(self, item_id: Any, label: str) -> None:
        if not item_id:
            raise StepFailure(f"{label} did not return an id")
        if str(item_id).startswith("group::"):
            raise StepFailure(f"{label} returned legacy pseudo-ID", {"id": item_id})

    def group_id(self, key: str) -> str:
        group_id = self.state.get("groups", {}).get(key)
        if not group_id:
            raise StepFailure(f"Group {key} is not available")
        return str(group_id)

    @property
    def firewall_rule_prefix(self) -> str:
        return "SAINTE2E_" + self.run_id.replace("-", "_")

    @staticmethod
    def profiles_are_all_block(profiles: Dict[str, Any]) -> bool:
        values = [str(value).lower() for value in (profiles or {}).values()]
        return bool(values) and all(value == "block" for value in values)

    @staticmethod
    def profiles_are_all_allow(profiles: Dict[str, Any]) -> bool:
        values = [str(value).lower() for value in (profiles or {}).values()]
        return bool(values) and all(value == "allow" for value in values)

    def add_coverage_note(self, note: str) -> None:
        if note and note not in self.coverage_not_tested:
            self.coverage_not_tested.append(note)

    @staticmethod
    def ensure_list(value: Any) -> List[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def payload_list_summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        candidates: List[Any] = []
        for key in ("agents", "items", "results", "users", "groups", "logs", "data"):
            value = payload.get(key) if isinstance(payload, dict) else None
            if isinstance(value, list):
                candidates = value
                break
            if isinstance(value, dict):
                for nested_key in ("agents", "items", "results", "users", "groups", "logs"):
                    nested = value.get(nested_key)
                    if isinstance(nested, list):
                        candidates = nested
                        break
            if candidates:
                break
        return {
            "count": len(candidates),
            "sample_ids": [
                str(item.get("_id") or item.get("id") or item.get("agent_id"))
                for item in candidates[:5]
                if isinstance(item, dict)
            ],
        }

    def run_powershell_json(self, script: str, label: str, *, timeout: int) -> Dict[str, Any]:
        binary = shutil.which("powershell.exe") or shutil.which("powershell")
        if not binary:
            raise StepFailure("PowerShell not found", {"label": label})
        result = subprocess.run(
            [binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        parsed = self.parse_last_json_object(result.stdout)
        details = {
            "label": label,
            "returncode": result.returncode,
            "parsed": parsed,
            "stdout_tail": truncate_text((result.stdout or "")[-2000:]),
            "stderr_tail": truncate_text((result.stderr or "")[-2000:]),
        }
        if result.returncode != 0:
            raise StepFailure(f"PowerShell JSON command failed: {label}", details)
        return details

    @staticmethod
    def parse_last_json_object(text: str) -> Any:
        raw = (text or "").strip()
        if not raw:
            return {}
        for start in range(len(raw)):
            candidate = raw[start:].strip()
            if not candidate or candidate[0] not in "[{":
                continue
            try:
                return json.loads(candidate)
            except ValueError:
                continue
        match = re.search(r"(\{.*\}|\[.*\])", raw, flags=re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except ValueError:
                return {}
        return {}

    @staticmethod
    def wait_for_event(events: List[Dict[str, Any]], event_name: str, timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if any(item.get("event") == event_name for item in events):
                return
            time.sleep(0.25)
        raise StepFailure(f"Timed out waiting for Socket.IO event {event_name}", {"events": events})

    @staticmethod
    def wait_for_any_event(events: List[Dict[str, Any]], names: set[str], timeout_seconds: int) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if any(item.get("event") in names for item in events):
                return
            time.sleep(0.25)
        raise StepFailure("Timed out waiting for any Socket.IO event", {"wanted": sorted(names), "events": events})

    @staticmethod
    def gui_click_smoke_js() -> str:
        return r"""
const { chromium } = require('@playwright/test');

const base = (process.env.SAINT_E2E_SERVER_URL || '').replace(/\/$/, '');
const username = process.env.SAINT_E2E_USERNAME || '';
const password = process.env.SAINT_E2E_PASSWORD || '';
const steps = [];
const httpErrors = [];

function trimText(value, max = 300) {
  value = String(value || '');
  return value.length > max ? value.slice(0, max) + '...' : value;
}

async function launchBrowser() {
  const attempts = [
    { headless: true },
    { headless: true, channel: 'msedge' },
    { headless: true, channel: 'chrome' },
  ];
  const errors = [];
  for (const options of attempts) {
    try {
      const browser = await chromium.launch(options);
      return { browser, options };
    } catch (error) {
      errors.push(`${JSON.stringify(options)}: ${error.message}`);
    }
  }
  throw new Error('Unable to launch Chromium/Edge/Chrome: ' + errors.join(' | '));
}

async function step(name, fn) {
  const started = Date.now();
  try {
    const details = await fn();
    steps.push({ name, status: 'PASS', durationMs: Date.now() - started, details: details || {} });
  } catch (error) {
    steps.push({ name, status: 'FAIL', durationMs: Date.now() - started, error: error.message });
    throw error;
  }
}

(async () => {
  if (!base || !username || !password) throw new Error('Missing GUI smoke environment');
  const launched = await launchBrowser();
  const browser = launched.browser;
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  page.on('response', (response) => {
    if (response.status() >= 500) {
      httpErrors.push({ url: response.url(), status: response.status() });
    }
  });

  await step('open_login_page', async () => {
    await page.goto(`${base}/login`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('input[name="username"], #username', { timeout: 15000 });
    return { title: await page.title() };
  });

  await step('submit_login_form', async () => {
    await page.fill('input[name="username"], #username', username);
    await page.fill('input[name="password"], #password', password);
    await Promise.all([
      page.waitForResponse((response) => response.url().includes('/api/admin/auth/login'), { timeout: 15000 }).catch(() => null),
      page.click('button[type="submit"], button:has-text("Login"), button:has-text("Dang nhap")'),
    ]);
    await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
    const me = await context.request.get(`${base}/api/admin/auth/me`);
    if (!me.ok()) throw new Error(`/api/admin/auth/me after GUI login returned ${me.status()}`);
    return { currentUrl: page.url(), meStatus: me.status() };
  });

  const pages = [
    ['dashboard', '/'],
    ['agents', '/agents'],
    ['groups', '/groups'],
    ['whitelist', '/whitelist'],
    ['logs', '/logs'],
    ['api_keys', '/api-keys'],
    ['admin_users', '/admin/users'],
    ['admin_audit', '/admin/audit'],
    ['profile', '/profile'],
  ];
  for (const [name, path] of pages) {
    await step(`click_${name}`, async () => {
      const locator = page.locator(`a[href="${path}"], a[href="${path}/"]`).first();
      const visible = await locator.isVisible({ timeout: 2500 }).catch(() => false);
      if (visible) {
        await locator.click();
      } else {
        await page.goto(`${base}${path}`, { waitUntil: 'domcontentloaded' });
      }
      await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
      const body = trimText(await page.locator('body').innerText({ timeout: 10000 }));
      if (/Internal Server Error|Traceback|CSRF_FAIL/i.test(body)) {
        throw new Error(`Page ${path} shows server/auth failure: ${body}`);
      }
      return { path, url: page.url(), title: await page.title(), bodyHead: body };
    });
  }

  await browser.close();
  const ok = steps.every((item) => item.status === 'PASS') && httpErrors.length === 0;
  console.log(JSON.stringify({ ok, browser: launched.options, steps, httpErrors }));
})().catch(async (error) => {
  console.log(JSON.stringify({ ok: false, error: error.message, steps, httpErrors }));
  process.exit(1);
});
"""

    @staticmethod
    def post_reboot_check_ps1(output_path: str) -> str:
        escaped_output = output_path.replace("'", "''")
        return f"""$ErrorActionPreference = "Stop"
$services = Get-Service | Where-Object {{
    $_.Name -match 'SAINT|FirewallController|Firewall Controller' -or
    $_.DisplayName -match 'SAINT|Firewall Controller|Network Access Control'
}} | Select-Object Name,DisplayName,Status,StartType
$processes = Get-Process | Where-Object {{
    $_.ProcessName -match 'SAINT|FirewallController|Firewall'
}} | Select-Object ProcessName,Id,StartTime -ErrorAction SilentlyContinue
$payload = [pscustomobject]@{{
    checked_at = (Get-Date).ToString("o")
    computer = $env:COMPUTERNAME
    user = $env:USERNAME
    services = @($services)
    processes = @($processes)
    saint_running = [bool](@($services | Where-Object {{ $_.Status -eq 'Running' }}).Count -or @($processes).Count)
}}
$payload | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 -Path '{escaped_output}'
Write-Host "POST_REBOOT_AUTOSTART_RESULT={escaped_output}"
"""

    @staticmethod
    def is_socket_permission_error(exc: BaseException) -> bool:
        text = str(exc)
        return "WinError 10013" in text or "forbidden by its access permissions" in text

    def tcp_probe(self, host: str, port: int, label: str) -> Dict[str, Any]:
        binary = shutil.which("powershell.exe") or shutil.which("powershell")
        if not binary:
            return {"label": label, "host": host, "port": port, "ok": False, "error": "PowerShell not found"}
        script = "\n".join([
            "$ProgressPreference = 'SilentlyContinue'",
            "$ErrorActionPreference = 'SilentlyContinue'",
            f"$target = {json.dumps(str(host))}",
            f"$port = {int(port)}",
            "$r = Test-NetConnection -ComputerName $target -Port $port -InformationLevel Detailed -WarningAction SilentlyContinue",
            "[pscustomobject]@{",
            "  Host = $target",
            "  Port = $port",
            "  TcpTestSucceeded = [bool]$r.TcpTestSucceeded",
            "  RemoteAddress = \"$($r.RemoteAddress)\"",
            "  InterfaceAlias = \"$($r.InterfaceAlias)\"",
            "} | ConvertTo-Json -Compress",
        ])
        started = time.monotonic()
        try:
            result = subprocess.run(
                [binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.args.deep_packet_timeout_seconds,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")
            return {
                "label": label,
                "host": host,
                "port": port,
                "ok": False,
                "timeout": True,
                "duration_ms": int((time.monotonic() - started) * 1000),
                "stdout": truncate_text(stdout),
                "stderr": truncate_text(stderr),
            }
        duration_ms = int((time.monotonic() - started) * 1000)
        parsed: Dict[str, Any] = {}
        match = re.search(r"\{.*\}", result.stdout or "", flags=re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
            except ValueError:
                parsed = {}
        ok = bool(parsed.get("TcpTestSucceeded"))
        return {
            "label": label,
            "host": host,
            "port": port,
            "ok": ok,
            "returncode": result.returncode,
            "duration_ms": duration_ms,
            "remote_address": parsed.get("RemoteAddress"),
            "interface_alias": parsed.get("InterfaceAlias"),
            "stdout_tail": truncate_text(result.stdout[-1000:]),
            "stderr_tail": truncate_text(result.stderr[-1000:]),
        }

    def select_blocked_packet_candidate(self, allowed_ip: str) -> Tuple[str, Dict[str, Any]]:
        excluded = {allowed_ip}
        attempts = []
        for raw in str(self.args.deep_blocked_candidates or "").split(","):
            candidate = raw.strip()
            if not candidate or candidate in excluded:
                continue
            probe = self.tcp_probe(candidate, self.args.deep_allowed_port, f"deep_blocked_preflight_{candidate}")
            attempts.append(probe)
            if probe.get("ok"):
                return candidate, {"chosen": candidate, "attempts": attempts}
        raise StepFailure(
            "No reachable blocked packet candidate found before firewall mutation",
            {"allowed_ip": allowed_ip, "attempts": attempts},
        )

    def firewall_rule_summary(self, manager: Any) -> Dict[str, Any]:
        source = "provider"
        try:
            rules = manager.rules_manager._provider.list_rules(  # pylint: disable=protected-access
                rule_prefix=self.firewall_rule_prefix,
                enabled_only=False,
            )
        except Exception as exc:
            return {"error": str(exc), "total_count": -1, "self_allow_count": -1, "allow_rule_count": -1}
        if not rules:
            fallback_rules = self.list_firewall_rules_powershell(self.firewall_rule_prefix)
            if fallback_rules is not None:
                rules = fallback_rules
                source = "powershell_fallback"
        rules = [rule for rule in rules if isinstance(rule, dict) and rule.get("rule_name")]
        names = [str(rule.get("rule_name", "")) for rule in rules if rule.get("rule_name")]
        duplicate_names = sorted({name for name in names if names.count(name) > 1})
        self_allow = [name for name in names if "_SelfAllow_" in name]
        allow_rules = [name for name in names if "_Allow_" in name and "_SelfAllow_" not in name]
        return {
            "source": source,
            "total_count": len(names),
            "self_allow_count": len(self_allow),
            "allow_rule_count": len(allow_rules),
            "duplicate_rule_names": duplicate_names,
            "self_allow_names": sorted(self_allow),
            "allow_rule_names": sorted(allow_rules),
        }

    @staticmethod
    def list_firewall_rules_powershell(rule_prefix: str) -> Optional[List[Dict[str, Any]]]:
        binary = shutil.which("powershell.exe") or shutil.which("powershell")
        if not binary:
            return None
        prefix_literal = "'" + str(rule_prefix).replace("'", "''") + "*'"
        script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$rules = Get-NetFirewallRule -DisplayName {prefix_literal}
$out = foreach ($r in @($rules)) {{
    $addr = $r | Get-NetFirewallAddressFilter
    $port = $r | Get-NetFirewallPortFilter
    $app = $r | Get-NetFirewallApplicationFilter
    [pscustomobject]@{{
        rule_name = "$($r.DisplayName)"
        direction = "$($r.Direction)".ToLower()
        action = "$($r.Action)".ToLower()
        enabled = ($r.Enabled -eq 'True' -or $r.Enabled -eq $true)
        protocol = "$($port.Protocol)".ToLower()
        profile = "$($r.Profile)"
        program = "$($app.Program)"
        remote_addresses = @($addr.RemoteAddress)
        remote_ports = @($port.RemotePort)
    }}
}}
@($out) | ConvertTo-Json -Compress -Depth 5
"""
        try:
            result = subprocess.run(
                [binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            return None
        if result.returncode != 0:
            return None
        parsed = FullSystemE2E.parse_last_json_object(result.stdout)
        if isinstance(parsed, dict):
            return [parsed] if any(parsed.values()) else []
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict) and any(item.values())]
        return []

    @staticmethod
    def find_agent_id_in_payloads(payloads: Iterable[Any]) -> Optional[str]:
        uuid_re = re.compile(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
        )

        def walk(value: Any) -> Optional[str]:
            if isinstance(value, dict):
                direct = value.get("agent_id")
                if isinstance(direct, str) and uuid_re.fullmatch(direct):
                    return direct
                for item in value.values():
                    found = walk(item)
                    if found:
                        return found
            elif isinstance(value, list):
                for item in value:
                    found = walk(item)
                    if found:
                        return found
            elif isinstance(value, str):
                match = uuid_re.search(value)
                if match:
                    return match.group(0)
            return None

        for payload in payloads:
            found = walk(payload)
            if found:
                return found
        return None

    def read_firewall_snapshot_policies(self) -> Dict[str, str]:
        try:
            with open(self.firewall_snapshot_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            policies = data.get("policies") or {}
            return policies if isinstance(policies, dict) else {}
        except Exception:
            return {}

    def force_firewall_default_allow(self, reason: str) -> Dict[str, Any]:
        if not is_admin():
            return {"attempted": False, "reason": reason, "admin": False}
        add_agent_path()
        os.environ["FIREWALL_WRITE_BACKEND"] = self.args.write_backend
        if self.args.read_provider != "auto":
            os.environ["SAINT_FIREWALL_PROVIDER"] = self.args.read_provider
        from firewall.manager import FirewallManager  # pylint: disable=import-error

        manager = FirewallManager(rule_prefix=self.firewall_rule_prefix)
        before = manager.get_firewall_policy_status()
        restored = manager.policy_manager.restore_default_policy()
        cleared = manager.clear_all_rules()
        after = manager.get_firewall_policy_status()
        return {
            "attempted": True,
            "reason": reason,
            "restore_default_policy_ok": restored,
            "clear_rules_ok": cleared,
            "before_policy": before,
            "after_policy": after,
        }

    def launch_agent_exe_smoke(self) -> Dict[str, Any]:
        if not DEFAULT_EXE.exists():
            return {"skipped": True, "reason": "SAINT.exe not found"}
        runtime_config = self.build_agent_runtime_config()
        env = os.environ.copy()
        env["FIREWALL_CONTROLLER_CONFIG"] = str(self.agent_runtime_config_path)
        env["FIREWALL_WRITE_BACKEND"] = self.args.write_backend
        if self.args.read_provider != "auto":
            env["SAINT_FIREWALL_PROVIDER"] = self.args.read_provider
        proc = subprocess.Popen(
            [str(DEFAULT_EXE)],
            cwd=str(DEFAULT_EXE.parent),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.agent_process = proc
        time.sleep(self.args.agent_exe_smoke_seconds)
        running = proc.poll() is None
        return {
            "pid": proc.pid,
            "running_after_seconds": running,
            "seconds": self.args.agent_exe_smoke_seconds,
            "runtime_config": str(self.agent_runtime_config_path),
            "config_written": bool(runtime_config),
        }

    def build_agent_runtime_config(self) -> Dict[str, Any]:
        add_agent_path()
        from config.defaults import DEFAULT_CONFIG  # pylint: disable=import-error

        config = copy.deepcopy(DEFAULT_CONFIG)
        # Keep the GUI process smoke offline. The script already tests the
        # agent/server contract with a controlled E2E agent_id; allowing the
        # GUI exe to auto-register would use the machine's real device id and
        # create a production agent record that is hard to distinguish safely.
        config["server"]["url"] = ""
        config["server"]["urls"] = []
        config["auth"]["api_key"] = ""
        config["firewall"]["enabled"] = False
        config["firewall"]["rule_prefix"] = self.firewall_rule_prefix
        config["logging"]["file"] = str(self.output_dir / "agent_exe_smoke.log")
        self.agent_runtime_config_path.write_text(json.dumps(config, indent=2, ensure_ascii=True), encoding="utf-8")
        return config

    def local_ip(self) -> str:
        try:
            hostname_ip = socket.gethostbyname(socket.gethostname())
            if hostname_ip and not hostname_ip.startswith(("127.", "169.254.")):
                return hostname_ip
        except Exception:
            pass
        return "127.0.0.1"

    def require_bootstrap(self) -> None:
        if not self.bootstrap or not self.bootstrap.access_token:
            raise StepFailure("Bootstrap admin client is not logged in")

    def require_clients(self) -> None:
        if not self.admin or not self.teacher:
            raise StepFailure("Temporary admin/teacher clients are not logged in")

    def require_agent(self) -> None:
        if not self.agent_id or not self.agent_token or not self.agent_access_token:
            raise StepFailure("Agent credentials are not available")

    def write_local_secrets(self) -> None:
        payload = {
            "warning": "Local-only file. Do not share.",
            "server_url": self.server_url,
            "bootstrap_admin_username": self.bootstrap_username,
            "bootstrap_admin_password": self.bootstrap_password,
            "temp_admin_username": self.temp_admin_username,
            "temp_admin_password": self.temp_admin_password,
            "temp_teacher_username": self.temp_teacher_username,
            "temp_teacher_password": self.temp_teacher_password,
            "temp_teacher_reset_password": self.temp_teacher_reset_password,
        }
        self.local_secrets_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")

    def write_outputs(self) -> None:
        payload = {
            "metadata": self.redactor.sanitize(self.metadata),
            "summary": self.summary(),
            "steps": [self.step_to_dict(r) for r in self.results],
            "cleanup": self.redactor.sanitize(self.cleanup_results),
            "state": self.redactor.sanitize(self.state),
            "deep_whitelist_matrix": self.redactor.sanitize(self.deep_whitelist_matrix),
            "deep_policy_matrix": self.redactor.sanitize(self.deep_policy_matrix),
            "deep_firewall_packet_matrix": self.redactor.sanitize(self.deep_firewall_packet_matrix),
            "deep_classroom_matrix": self.redactor.sanitize(self.deep_classroom_matrix),
            "deep_service_autostart_matrix": self.redactor.sanitize(self.deep_service_autostart_matrix),
            "deep_gui_matrix": self.redactor.sanitize(self.deep_gui_matrix),
            "deep_websocket_matrix": self.redactor.sanitize(self.deep_websocket_matrix),
            "deep_soak_matrix": self.redactor.sanitize(self.deep_soak_matrix),
            "coverage_not_tested": self.coverage_not_tested,
        }
        self.json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True), encoding="utf-8")
        self.raw_log_path.write_text(json.dumps(self.raw_log, indent=2, ensure_ascii=True), encoding="utf-8")
        self.txt_path.write_text(self.render_txt(payload), encoding="utf-8")

    def step_to_dict(self, result: StepResult) -> Dict[str, Any]:
        return {
            "name": result.name,
            "status": result.status,
            "duration_ms": result.duration_ms,
            "required": result.required,
            "details": self.redactor.sanitize(result.details),
            "error": self.redactor.sanitize(result.error),
        }

    def summary(self) -> Dict[str, Any]:
        counts = {"PASS": 0, "FAIL": 0, "SKIP": 0}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        cleanup_counts: Dict[str, int] = {}
        for result in self.cleanup_results:
            status = str(result.get("status", "UNKNOWN"))
            cleanup_counts[status] = cleanup_counts.get(status, 0) + 1
        return {
            "counts": counts,
            "cleanup_counts": cleanup_counts,
            "required_failures": [r.name for r in self.results if r.required and r.status == "FAIL"],
            "cleanup_failures": [r.get("name") for r in self.cleanup_results if r.get("status") == "CLEANUP_FAIL"],
            "txt_path": str(self.txt_path),
            "json_path": str(self.json_path),
            "raw_log_path": str(self.raw_log_path),
        }

    def render_txt(self, payload: Dict[str, Any]) -> str:
        lines = [
            "SAINT Full System E2E",
            "=" * 22,
            f"Run ID: {self.run_id}",
            f"Server: {self.server_url}",
            f"Started: {self.metadata.get('started_at', '')}",
            f"Finished: {self.metadata.get('finished_at', '')}",
            f"Output: {self.output_dir}",
            f"Windows Administrator: {self.metadata.get('admin')}",
            f"Real firewall policy: {self.args.run_real_firewall_policy}",
            f"Deep mode: {self.args.deep}",
            "",
            "Important:",
            "- Send back TXT, JSON, and raw JSON result files.",
            "- Do not send *.local.json files because they may contain credentials.",
            "",
            "Summary:",
        ]
        summary = payload["summary"]
        counts = summary["counts"]
        cleanup_counts = summary["cleanup_counts"]
        lines.append(f"Steps: PASS={counts.get('PASS', 0)} FAIL={counts.get('FAIL', 0)} SKIP={counts.get('SKIP', 0)}")
        lines.append("Cleanup: " + json.dumps(cleanup_counts, ensure_ascii=True))
        lines.append("Required failures: " + (", ".join(summary["required_failures"]) or "none"))
        lines.append("Cleanup failures: " + (", ".join([str(x) for x in summary["cleanup_failures"]]) or "none"))
        if self.args.deep:
            lines.append("Deep whitelist matrix: " + ("PASS" if self.deep_whitelist_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep policy matrix: " + ("PASS" if self.deep_policy_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep classroom scale matrix: " + ("PASS" if self.deep_classroom_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep service/autostart matrix: " + ("PASS" if self.deep_service_autostart_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep GUI click matrix: " + ("PASS" if self.deep_gui_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep WebSocket matrix: " + ("PASS" if self.deep_websocket_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep soak matrix: " + ("PASS" if self.deep_soak_matrix.get("passed") else "CHECK JSON"))
            lines.append("Deep firewall packet matrix: " + ("PASS" if self.deep_firewall_packet_matrix.get("passed") else "CHECK JSON"))
        lines.extend(["", "Steps:"])
        for result in self.results:
            lines.append(f"[{result.status}] {result.name} ({result.duration_ms} ms, required={result.required})")
            if result.error:
                lines.append("  Error: " + str(result.error))
            if result.details:
                detail_json = json.dumps(self.redactor.sanitize(result.details), indent=2, ensure_ascii=True)
                for line in detail_json.splitlines()[:80]:
                    lines.append("  " + line)
                if len(detail_json.splitlines()) > 80:
                    lines.append("  ... details truncated in TXT; see JSON")
            lines.append("")
        lines.extend(["Cleanup:"])
        for result in self.cleanup_results:
            lines.append(json.dumps(self.redactor.sanitize(result), ensure_ascii=True))
        lines.extend(
            [
                "",
                "Artifacts:",
                f"- TXT: {self.txt_path}",
                f"- JSON: {self.json_path}",
                f"- Raw log JSON: {self.raw_log_path}",
                f"- Local secrets: {self.local_secrets_path} (do not share)",
                f"- Agent runtime config: {self.agent_runtime_config_path} (do not share)",
            ]
        )
        return "\n".join(lines) + "\n"


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run full SAINT agent/server E2E against a real server.")
    parser.add_argument("--server-url", default=None)
    parser.add_argument("--bootstrap-admin-username", default=None)
    parser.add_argument("--bootstrap-admin-password", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cleanup-result-json", default=None)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--firewall-only", action="store_true")
    parser.add_argument("--keep-test-data", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--run-real-firewall-policy", action="store_true")
    parser.add_argument("--skip-agent-exe-launch", action="store_true")
    parser.add_argument("--agent-exe-smoke-seconds", type=int, default=12)
    parser.add_argument("--timeout-seconds", type=int, default=20)
    parser.add_argument("--build-timeout-seconds", type=int, default=900)
    parser.add_argument("--firewall-test-ip", default="203.0.113.10")
    parser.add_argument("--deep-allowed-ip", default="151.101.1.69")
    parser.add_argument("--deep-allowed-port", type=int, default=443)
    parser.add_argument("--deep-blocked-candidates", default="151.101.1.69,104.16.132.229,142.250.190.14,93.184.216.34")
    parser.add_argument("--deep-mutation-ip", default="203.0.113.10")
    parser.add_argument("--deep-packet-timeout-seconds", type=int, default=25)
    parser.add_argument("--deep-classroom-agent-count", type=int, default=24)
    parser.add_argument("--deep-soak-minutes", type=float, default=30.0)
    parser.add_argument("--deep-soak-interval-seconds", type=int, default=60)
    parser.add_argument("--deep-gui-timeout-seconds", type=int, default=180)
    parser.add_argument("--deep-websocket-timeout-seconds", type=int, default=25)
    parser.add_argument("--read-provider", choices=("auto", "netsh", "netsecurity"), default="auto")
    parser.add_argument("--write-backend", choices=("netsh", "powershell", "netsecurity"), default="powershell")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    runner = FullSystemE2E(args)
    exit_code = 1
    try:
        exit_code = runner.run()
    except Exception as exc:  # noqa: BLE001
        runner.results.append(
            StepResult(
                name="fatal_runner_error",
                status="FAIL",
                duration_ms=0,
                required=True,
                details={"traceback": runner.redactor.mask_text(traceback.format_exc())},
                error=runner.redactor.mask_text(str(exc)),
            )
        )
        runner.cleanup()
        runner.metadata["finished_at"] = datetime.now().isoformat(timespec="seconds")
        runner.metadata["exit_code"] = 1
    finally:
        runner.write_outputs()
        print(f"TXT_RESULT={runner.txt_path}")
        print(f"JSON_RESULT={runner.json_path}")
        print(f"RAW_LOG_RESULT={runner.raw_log_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
