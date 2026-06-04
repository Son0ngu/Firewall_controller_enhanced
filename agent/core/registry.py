import logging
import platform
import socket
from typing import Dict, Tuple

import requests

from shared.time_utils import now, now_iso
from shared.os_info import get_os_details
from shared.server_urls import collect_server_urls

from .agent import agent_state, DeviceIdentityProvider
# Note: do NOT do ``from .agent import AGENT_DEVICE_ID`` at module level.
# That triggers ``agent.core.agent.__getattr__("AGENT_DEVICE_ID")``
# immediately at import time (PEP 562 fires the lookup on the *import*,
# not on later attribute access), which shells out to PowerShell. Any
# module that imports ``registry`` would then pay the WMI/CIM cost on
# its own import — defeating the whole point of the lazy provider.
# Callers must resolve the device id at call time via
# ``DeviceIdentityProvider.get_device_id()`` instead.
from utils.ip_detector import get_local_ip, check_admin_privileges
from utils.error_handler import CriticalErrorHandler

logger = logging.getLogger("core.registry")

DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_READ_TIMEOUT = 45.0


def _collect_server_urls(config: Dict) -> list:
    """Backwards-compatible wrapper — delegates to shared resolver.

    Kept so existing callers (lifecycle.py and any monkeypatches in tests)
    continue to work. New code should import collect_server_urls directly.
    """
    return collect_server_urls(config, allow_dev_default=False)


def _positive_timeout(value, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return parsed


def _registration_timeout(config: Dict) -> Tuple[float, float]:
    """Return (connect_timeout, read_timeout) for registration requests."""
    server_cfg = config.get("server", {}) if isinstance(config, dict) else {}
    connect_timeout = _positive_timeout(
        server_cfg.get("connect_timeout"),
        DEFAULT_CONNECT_TIMEOUT,
    )
    read_timeout = _positive_timeout(
        server_cfg.get("read_timeout"),
        DEFAULT_READ_TIMEOUT,
    )
    return connect_timeout, read_timeout


def _response_excerpt(response: requests.Response, limit: int = 240) -> str:
    text = (response.text or "").strip()
    if len(text) > limit:
        return text[:limit] + "..."
    return text


@CriticalErrorHandler.critical_operation("Agent Registration")
def register_agent(config: Dict) -> bool:
    try:
        server_urls = _collect_server_urls(config)

        # No server URL configured - do not contact anything. This is the
        # first-run default (see DEFAULT_CONFIG in agent/config/defaults.py).
        # Surfaced clearly to the user via the GUI status panel; the agent
        # continues to start in offline mode.
        if not server_urls:
            logger.warning(
                "Server URL not configured - open Settings to set one. "
                "Skipping registration; agent will run offline until then."
            )
            return False

        # Collect agent information
        local_ip = get_local_ip()
        admin_status = check_admin_privileges()
        os_details = get_os_details()

        agent_info = {
            "hostname": socket.gethostname(),
            "device_id": DeviceIdentityProvider.get_device_id(),
            "ip_address": local_ip,
            "platform": os_details["platform"],
            "os_info": f"{os_details['name']} {os_details['version']}",
            "agent_version": "1.0.0",
            "python_version": platform.python_version(),
            "admin_privileges": admin_status,
            "capabilities": {
                "packet_capture": True,
                "firewall_management": admin_status,
                "whitelist_sync": True
            },
            "registration_time": now_iso(),
            "registration_timestamp": now()
        }

        for server_url in server_urls:
            if try_register_with_server(server_url, agent_info, config):
                return True

        logger.error("Failed to register with any server")
        return False

    except Exception as e:
        logger.error(f"Error in agent registration: {e}")
        return False


def try_register_with_server(server_url: str, agent_info: Dict, config: Dict) -> bool:
    try:
        register_url = f"{server_url.rstrip('/')}/api/agents/register"
        timeout = _registration_timeout(config)
        logger.info(
            "Attempting registration with: %s (connect_timeout=%ss, read_timeout=%ss)",
            register_url,
            timeout[0],
            timeout[1],
        )
        
        # Build headers with API key for authentication
        headers = {'Content-Type': 'application/json'}
        
        # Add API key if configured (required for secure registration)
        api_key = config.get('auth', {}).get('api_key', '')
        if api_key:
            headers['X-API-Key'] = api_key
            logger.debug("API key included in registration request")
        else:
            logger.warning("No API key configured - registration may fail if server requires authentication")
        
        response = requests.post(
            register_url,
            json=agent_info,
            timeout=timeout,
            headers=headers
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                agent_data = data.get('data', {})
                
                # Save credentials globally
                config['agent_id'] = agent_data.get('agent_id')
                config['agent_token'] = agent_data.get('token')  # Legacy token
                config['user_id'] = agent_data.get('user_id')
                config['server_url'] = server_url
                
                # NEW: Save JWT tokens if provided (Phase 2)
                jwt_data = agent_data.get('jwt', {})
                if jwt_data:
                    config['jwt'] = {
                        'access_token': jwt_data.get('access_token'),
                        'refresh_token': jwt_data.get('refresh_token'),
                        'token_type': jwt_data.get('token_type', 'Bearer'),
                        'access_expires_at': jwt_data.get('access_expires_at'),
                        'refresh_expires_at': jwt_data.get('refresh_expires_at'),
                    }
                    logger.info("JWT tokens received and stored")
                else:
                    logger.warning("No JWT tokens in registration response - using legacy auth")
                
                # Update agent state
                agent_state['agent_id'] = config['agent_id']
                agent_state['registration_completed'] = True
                
                logger.info(f"Registration successful - Agent ID: {config['agent_id']}")
                return True
            else:
                logger.warning(
                    "Registration rejected by %s: %s",
                    server_url,
                    data.get("error") or data,
                )
                return False
        else:
            logger.warning(
                "Registration failed at %s: HTTP %s %s",
                server_url,
                response.status_code,
                _response_excerpt(response),
            )
            return False
            
    except requests.exceptions.ConnectTimeout:
        logger.warning(
            "Registration connection timeout to %s after %ss",
            server_url,
            _registration_timeout(config)[0],
        )
        return False
    except requests.exceptions.ReadTimeout:
        logger.warning(
            "Registration read timeout from %s after %ss",
            server_url,
            _registration_timeout(config)[1],
        )
        return False
    except requests.exceptions.Timeout:
        logger.warning(
            "Registration timeout with %s (connect=%ss, read=%ss)",
            server_url,
            *_registration_timeout(config),
        )
        return False
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection failed to {server_url}")
        return False
    except Exception as e:
        logger.error(f"Error registering with {server_url}: {e}")
        return False
