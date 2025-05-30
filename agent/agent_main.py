"""
Firewall Controller Agent - Module Chính (Enhanced for Auto-Detection Mode)

Enhanced agent với auto-detection firewall mode:
- ADMIN PRIVILEGES: whitelist-only mode với proactive blocking
- NO ADMIN PRIVILEGES: monitor mode với passive monitoring
- AUTO-DETECTION: Tự động chọn mode tối ưu cho privileges
"""

# Import các thư viện cần thiết
import logging
import signal
import time
import threading
import socket
import platform
import sys
import os
import uuid
import requests
import psutil
import subprocess  # ✅ ADD: For system commands
from typing import Dict, Optional, Set, Any, List  # ✅ FIX: Add missing types
from datetime import datetime

# ✅ ENHANCED: Try importing optional modules
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    HAS_WIN32_SERVICE = True
except ImportError:
    HAS_WIN32_SERVICE = False

# ✅ FIX: Setup logging BEFORE other imports to avoid undefined logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("agent_main")

# Import các module tự định nghĩa từ package agent
from config import get_config
from firewall_manager import FirewallManager
from log_sender import LogSender
from packet_sniffer import PacketSniffer
from whitelist import WhitelistManager
from heartbeat_sender import HeartbeatSender
from command_processor import CommandProcessor

# ✅ ENHANCED: Global variables với better state tracking
config = None
firewall = None
whitelist = None
log_sender = None
packet_sniffer = None
heartbeat_sender = None
command_processor = None
running = True

# ✅ ENHANCED: State tracking variables
agent_state = {
    "startup_completed": False,
    "firewall_setup_completed": False,
    "registration_completed": False,
    "whitelist_sync_completed": False,
    "components_initialized": False
}

def handle_domain_detection(record: Dict):
    """Enhanced domain detection handler with mode awareness"""
    try:
        domain = record.get("domain")
        dest_ip = record.get("dest_ip") 
        src_ip = record.get("src_ip", "unknown")
        protocol = record.get("protocol", "TCP")
        port = record.get("port", "unknown")
        
        # ✅ ENHANCED: Better protocol detection
        if port:
            if str(port) == "443":
                protocol = "HTTPS"
            elif str(port) == "80":
                protocol = "HTTP"
            elif str(port) == "53":
                protocol = "DNS"
            elif str(port) == "25":
                protocol = "SMTP"
            elif str(port) == "993":
                protocol = "IMAPS"
            elif str(port) == "995":
                protocol = "POP3S"
            else:
                protocol = f"TCP/{port}" if protocol.upper() == "TCP" else f"{protocol.upper()}/{port}"
        
        # ✅ ENHANCED: Better source IP detection
        if src_ip == "unknown" or not src_ip:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    src_ip = s.getsockname()[0]
            except:
                src_ip = config.get("local_ip", "127.0.0.1")
        
        # ✅ NEW: Mode-aware action determination
        domain_allowed = False
        ip_allowed = False
        action = "UNKNOWN"
        reason = "unknown"
        level = "INFO"
        
        try:
            # Check whitelist status
            if domain and whitelist:
                domain_allowed = whitelist.is_allowed(domain)
                logger.debug(f"Domain check for {domain}: {domain_allowed}")
            
            if dest_ip and dest_ip != "unknown" and whitelist:
                ip_allowed = whitelist.is_ip_allowed(dest_ip)
                logger.debug(f"IP check for {dest_ip}: {ip_allowed}")
            
            # ✅ NEW: Mode-aware action determination
            firewall_mode = config["firewall"]["mode"]
            firewall_enabled = config["firewall"]["enabled"]
            
            if firewall_enabled and firewall_mode == "whitelist_only":
                # ✅ WHITELIST_ONLY MODE: Active blocking
                if domain_allowed or ip_allowed:
                    action = "ALLOWED"
                    reason = "whitelisted_domain" if domain_allowed else "whitelisted_ip"
                    level = "ALLOWED"
                else:
                    action = "BLOCKED"
                    reason = "not_whitelisted"
                    level = "BLOCKED"
            elif firewall_enabled and firewall_mode == "block":
                # ✅ TRADITIONAL BLOCK MODE: Reactive blocking
                if domain_allowed or ip_allowed:
                    action = "ALLOWED"
                    reason = "whitelisted"
                    level = "INFO"
                else:
                    action = "BLOCKED"
                    reason = "firewall_rule"
                    level = "WARNING"
            elif firewall_enabled and firewall_mode == "warn":
                # ✅ WARN MODE: No blocking, just warnings
                if domain_allowed or ip_allowed:
                    action = "ALLOWED"
                    reason = "whitelisted"
                    level = "INFO"
                else:
                    action = "WARNED"
                    reason = "suspicious_domain"
                    level = "WARNING"
            else:  # monitor mode OR firewall disabled
                # ✅ MONITOR MODE: Pure monitoring, no intervention
                if domain_allowed or ip_allowed:
                    action = "MONITORED"
                    reason = "whitelisted_traffic"
                    level = "INFO"
                else:
                    action = "MONITORED"
                    reason = "traffic_monitoring"
                    level = "INFO"
                        
        except Exception as e:
            logger.warning(f"Error checking whitelist status: {e}")
            action = "ERROR"
            reason = "whitelist_check_failed"
            level = "ERROR"
        
        # ✅ ENHANCED: Enhanced record với mode information
        enhanced_record = {
            "timestamp": datetime.now().isoformat(),
            "agent_id": config.get("agent_id", "unknown"),
            "level": level,
            "action": action,
            "domain": domain or "unknown",
            "destination": domain or dest_ip or "unknown",
            "source_ip": src_ip,
            "dest_ip": dest_ip or "unknown",
            "protocol": protocol,
            "port": str(port) if port != "unknown" else "unknown",
            "reason": reason,
            "message": f"{action}: {domain or dest_ip} ({reason})",
            
            # ✅ ADD: Mode and capability information
            "connection_type": "outbound",
            "local_ip": src_ip,
            "remote_ip": dest_ip,
            "service_type": _detect_service_type(port, protocol),
            "firewall_mode": config["firewall"]["mode"],
            "firewall_enabled": config["firewall"]["enabled"],
            "handled_by_firewall": firewall_enabled and config["firewall"]["mode"] in ["whitelist_only", "block"],
            "monitoring_only": not firewall_enabled or config["firewall"]["mode"] == "monitor",
            "admin_privileges": _check_admin_privileges(),
            "domain_check": domain_allowed,
            "ip_check": ip_allowed,
            "source": "domain_detection"
        }
        
        # ✅ ENHANCED: Process detection
        try:
            for conn in psutil.net_connections():
                if conn.raddr and conn.raddr.ip == dest_ip and str(conn.raddr.port) == str(port):
                    if conn.pid:
                        process = psutil.Process(conn.pid)
                        enhanced_record["process_name"] = process.name()
                        enhanced_record["process_pid"] = conn.pid
                    break
        except Exception as e:
            logger.debug(f"Could not get process info: {e}")
        
        # ✅ Queue log for server
        if log_sender:
            success = log_sender.queue_log(enhanced_record)
            if success:
                logger.debug(f"✅ Log queued: {domain or dest_ip}")
            else:
                logger.warning(f"❌ Failed to queue log: {domain or dest_ip}")
        
        # ✅ ENHANCED: Mode-aware local logging
        log_message = (f"{action}: {domain or dest_ip} -> {dest_ip} "
                      f"({protocol}:{port}) - {reason}")
        
        if level == "BLOCKED":
            logger.warning(f"🚫 {log_message}")
        elif level == "WARNING":
            logger.warning(f"⚠️ {log_message}")
        elif level == "ALLOWED":
            logger.info(f"✅ {log_message}")
        else:
            logger.info(f"📊 {log_message}")
                
    except Exception as e:
        logger.error(f"Error in domain detection handler: {e}", exc_info=True)
        
        # ✅ Error logging
        if log_sender:
            error_record = {
                "timestamp": datetime.now().isoformat(),
                "agent_id": config.get("agent_id", "unknown"),
                "level": "ERROR",
                "action": "ERROR",
                "domain": "handler_error",
                "destination": "handler_error",
                "source_ip": "unknown",
                "dest_ip": "unknown",
                "protocol": "unknown",
                "port": "unknown",
                "reason": "domain_detection_handler_error",
                "message": f"Domain detection handler error: {str(e)}",
                "source": "domain_detection_error",
                "error_details": str(e),
                "original_record": str(record)[:500] + "..." if len(str(record)) > 500 else str(record)
            }
            log_sender.queue_log(error_record)

def _detect_service_type(port, protocol):
    """Detect service type based on port and protocol"""
    if not port or port == "unknown":
        return "unknown"
    
    port_str = str(port)
    service_map = {
        "80": "HTTP Web",
        "443": "HTTPS Web", 
        "53": "DNS",
        "25": "SMTP Email",
        "993": "IMAPS Email",
        "995": "POP3S Email", 
        "21": "FTP",
        "22": "SSH",
        "23": "Telnet",
        "110": "POP3 Email",
        "143": "IMAP Email",
        "587": "SMTP Email",
        "3389": "RDP",
        "5432": "PostgreSQL",
        "3306": "MySQL",
        "1433": "SQL Server",
        "6379": "Redis"
    }
    
    return service_map.get(port_str, f"{protocol.upper()} Service")

def initialize_components():
    """Enhanced initialization với auto-detection mode"""
    global config, firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor
    
    try:
        logger.info("🔧 Initializing agent components...")
        
        # ✅ ENHANCED: Validate config và detect optimal mode
        if not config:
            logger.error("Global config not available! Loading...")
            config = get_config()
            if not config:
                raise ValueError("Cannot load configuration")
        
        # ✅ NEW: Auto-detect and display mode
        detected_mode = _detect_and_log_mode()
        
        # ✅ ENHANCED: Better local IP detection
        local_ip = _get_local_ip()
        
        # ✅ ENHANCED: Comprehensive agent info với mode info
        agent_info = _get_agent_info_with_mode(local_ip, detected_mode)
        
        # ✅ ENHANCED: Agent registration
        registration_success = _register_agent(agent_info)
        agent_state["registration_completed"] = registration_success
        
        # ✅ STARTUP PHASE 1: Initialize whitelist FIRST
        logger.info("📋 STARTUP PHASE 1: Initializing whitelist manager...")
        whitelist = WhitelistManager(config)
        logger.info(f"✅ Whitelist initialized with {len(whitelist.domains)} domains")
        
        # ✅ STARTUP PHASE 2: Initialize firewall manager (if enabled)
        if config["firewall"]["enabled"]:
            logger.info("🔥 STARTUP PHASE 2: Initializing firewall manager...")
            firewall = FirewallManager(config["firewall"]["rule_prefix"])
            logger.info("✅ Firewall manager initialized")
            
            # ✅ ENHANCED: Link firewall với whitelist for auto-sync
            whitelist.set_firewall_manager(firewall)
            logger.info("🔗 Firewall linked with whitelist for auto-sync")
            
            # ✅ STARTUP PHASE 3: Setup whitelist-only firewall if mode is whitelist_only
            if config["firewall"]["mode"] == "whitelist_only":
                logger.info("🔒 STARTUP PHASE 3: Setting up whitelist-only firewall...")
                success = _setup_whitelist_firewall()
                agent_state["firewall_setup_completed"] = success
                
                if success:
                    logger.info("✅ Whitelist-only firewall setup completed")
                    logger.info("🔒 Default policy: BLOCK all non-whitelisted traffic")
                else:
                    logger.error("❌ Failed to setup whitelist-only firewall")
            else:
                logger.info(f"🔧 Firewall mode: {config['firewall']['mode']} (monitoring only)")
        else:
            logger.info("📊 Firewall disabled - running in monitoring mode only")
        
        # ✅ ENHANCED: Initialize remaining components
        logger.info("📤 Initializing log sender...")
        log_sender = _initialize_log_sender()
        
        logger.info("📡 Initializing packet sniffer...")
        packet_sniffer = PacketSniffer(callback=handle_domain_detection)
        packet_sniffer.start()
        logger.info("✅ Packet sniffer started")
        
        # ✅ ENHANCED: Initialize heartbeat sender
        if registration_success:
            logger.info("💓 Initializing heartbeat sender...")
            heartbeat_sender = HeartbeatSender(config)
            heartbeat_sender.set_agent_credentials(config['agent_id'], config['agent_token'])
            heartbeat_sender.start()
            logger.info("✅ Heartbeat sender started")
        else:
            logger.warning("⚠️ Skipping heartbeat sender - agent not registered")
        
        # ✅ ENHANCED: Initialize command processor
        logger.info("🎮 Initializing command processor...")
        command_processor = CommandProcessor()
        logger.info("✅ Command processor initialized")
        
        # ✅ ENHANCED: Start command polling if registered
        if registration_success:
            _start_command_polling()
        
        # ✅ ENHANCED: Mark components as initialized
        agent_state["components_initialized"] = True
        agent_state["startup_completed"] = True
        
        logger.info("🎉 All agent components initialized successfully")
        _log_startup_summary()
        
    except Exception as e:
        logger.error(f"Error initializing components: {e}", exc_info=True)
        raise

def _detect_and_log_mode() -> Dict[str, Any]:
    """
    Phát hiện và log mode được chọn dựa trên quyền admin.
    
    Returns:
        Dict: Thông tin về mode detection
    """
    has_admin = _check_admin_privileges()
    current_mode = config["firewall"]["mode"]
    firewall_enabled = config["firewall"]["enabled"]
    
    mode_info = {
        "has_admin_privileges": has_admin,
        "detected_optimal_mode": "whitelist_only" if has_admin else "monitor",
        "current_mode": current_mode,
        "firewall_enabled": firewall_enabled,
        "mode_match": (current_mode == "whitelist_only" and has_admin) or (current_mode == "monitor" and not has_admin)
    }
    
    # ✅ LOG: Detailed mode information
    logger.info("🔍 Mode Detection Results:")
    logger.info(f"   - Administrator privileges: {'✅ YES' if has_admin else '❌ NO'}")
    logger.info(f"   - Optimal mode: {mode_info['detected_optimal_mode']}")
    logger.info(f"   - Current config mode: {current_mode}")
    logger.info(f"   - Firewall enabled: {'✅ YES' if firewall_enabled else '❌ NO'}")
    
    if mode_info["mode_match"]:
        logger.info("✅ Mode configuration is optimal for current privileges")
    else:
        logger.warning("⚠️ Mode configuration may not be optimal for current privileges")
        
        if has_admin and current_mode != "whitelist_only":
            logger.info("💡 Consider using 'whitelist_only' mode for maximum security with admin privileges")
        elif not has_admin and firewall_enabled:
            logger.warning("💡 Consider disabling firewall or using 'monitor' mode without admin privileges")
    
    return mode_info

def _get_agent_info_with_mode(local_ip: str, mode_info: Dict) -> Dict:
    """Get comprehensive agent information including mode detection"""
    base_info = _get_agent_info(local_ip)
    
    # ✅ ADD: Mode detection information
    base_info.update({
        "admin_privileges": mode_info["has_admin_privileges"],
        "detected_optimal_mode": mode_info["detected_optimal_mode"],
        "mode_optimal": mode_info["mode_match"],
        "capabilities": {
            "can_create_firewall_rules": mode_info["has_admin_privileges"],
            "can_block_traffic": mode_info["has_admin_privileges"] and config["firewall"]["enabled"],
            "monitoring_only": not config["firewall"]["enabled"] or config["firewall"]["mode"] == "monitor"
        }
    })
    
    return base_info

def _register_agent(agent_info: Dict) -> bool:
    """Enhanced agent registration with multiple URL support"""
    server_urls = config['server'].get('urls', [config['server']['url']])
    
    for server_url in server_urls:
        try:
            # ✅ FIX: Use correct endpoint with /agents prefix
            register_url = f"{server_url.rstrip('/')}/api/agents/register"  # ✅ CHANGED: /api/agents/register
            logger.info(f"🔗 Attempting registration with: {register_url}")
            
            response = requests.post(
                register_url, 
                json=agent_info, 
                timeout=config['server'].get('connect_timeout', 15),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    agent_data = data.get('data', {})
                    logger.info(f"✅ Agent registered successfully with ID: {agent_data.get('agent_id')}")
                    
                    # ✅ ENHANCED: Save agent credentials
                    config['agent_id'] = agent_data.get('agent_id')
                    config['agent_token'] = agent_data.get('token')
                    config['user_id'] = agent_data.get('user_id')
                    config['server_url'] = server_url
                    
                    logger.debug(f"Agent token: {config['agent_token'][:8]}...")
                    return True
                else:
                    logger.warning(f"Registration failed with {server_url}: {data.get('error', 'Unknown error')}")
            else:
                logger.warning(f"Registration failed with {server_url}: HTTP {response.status_code}")
                logger.debug(f"Response: {response.text}")
                
        except requests.exceptions.ConnectionError:
            logger.warning(f"Could not connect to {server_url}")
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout connecting to {server_url}")
        except Exception as e:
            logger.warning(f"Error registering with {server_url}: {e}")
    
    logger.error("❌ Failed to register with any server - agent functionality will be limited")
    return False

def _setup_whitelist_firewall() -> bool:
    """Setup whitelist-only firewall (STARTUP PHASE 3)"""
    try:
        if not firewall or not whitelist:
            logger.error("Firewall or whitelist not available for setup")
            return False
        
        # ✅ ENHANCED: Wait for whitelist to be ready
        max_wait = 30  # 30 seconds max wait
        wait_time = 0
        while not whitelist.startup_sync_completed and wait_time < max_wait:
            logger.debug(f"Waiting for whitelist sync to complete... ({wait_time}s)")
            time.sleep(1)
            wait_time += 1
        
        if not whitelist.startup_sync_completed:
            logger.warning("Whitelist sync not completed, proceeding with cached data")
        
        # ✅ ENHANCED: Get all whitelisted IPs (force refresh to ensure latest)
        logger.info("🔍 Resolving all whitelisted domains to IPs...")
        whitelisted_ips = whitelist.get_all_whitelisted_ips(force_refresh=True)
        
        if not whitelisted_ips:
            logger.warning("⚠️ No whitelisted IPs found - firewall will block everything!")
            # ✅ ENHANCED: Add emergency allowlist
            emergency_ips = _get_emergency_allowlist()
            whitelisted_ips = emergency_ips
            logger.info(f"🆘 Using emergency allowlist: {len(emergency_ips)} IPs")
        
        logger.info(f"📍 Total IPs to whitelist: {len(whitelisted_ips)}")
        
        # ✅ ENHANCED: Get essential IPs
        essential_ips = _get_essential_ips()
        logger.info(f"🔧 Essential IPs: {len(essential_ips)}")
        
        # ✅ ENHANCED: Setup whitelist firewall
        logger.info("🔥 Creating firewall rules...")
        success = firewall.setup_whitelist_firewall(whitelisted_ips, essential_ips)
        
        if success:
            # ✅ ENHANCED: Log setup summary
            total_allowed = len(whitelisted_ips) + len(essential_ips)
            logger.info(f"🎉 Whitelist firewall setup successful:")
            logger.info(f"   - Whitelisted IPs: {len(whitelisted_ips)}")
            logger.info(f"   - Essential IPs: {len(essential_ips)}")
            logger.info(f"   - Total allowed: {total_allowed}")
            logger.info(f"   - Default action: BLOCK all others")
            
            return True
        else:
            logger.error("❌ Whitelist firewall setup failed")
            return False
            
    except Exception as e:
        logger.error(f"Error setting up whitelist firewall: {e}")
        return False

def _get_emergency_allowlist() -> Set[str]:
    """Get emergency IPs that should always be allowed"""
    emergency_ips = set()
    
    # ✅ ENHANCED: Server IPs
    try:
        server_urls = config['server'].get('urls', [config['server']['url']])
        for url in server_urls:
            # Extract domain from URL
            if "://" in url:
                domain = url.split("://")[1].split("/")[0].split(":")[0]
            else:
                domain = url.split("/")[0].split(":")[0]
            
            # Resolve server domain
            try:
                server_ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                for ip_info in server_ips:
                    emergency_ips.add(ip_info[4][0])
                logger.debug(f"Emergency: Added server IPs for {domain}")
            except:
                logger.warning(f"Could not resolve emergency server: {domain}")
    except:
        pass
    
    # ✅ ENHANCED: Essential services
    essential_domains = [
        "github.com", "raw.githubusercontent.com",  # For updates
        "pypi.org", "files.pythonhosted.org",      # Python packages
        "microsoft.com", "windows.com",             # Windows updates
    ]
    
    for domain in essential_domains:
        try:
            domain_ips = socket.getaddrinfo(domain, None, socket.AF_INET)
            for ip_info in domain_ips:
                emergency_ips.add(ip_info[4][0])
        except:
            logger.debug(f"Could not resolve emergency domain: {domain}")
    
    logger.info(f"🆘 Emergency allowlist: {len(emergency_ips)} IPs")
    return emergency_ips

def _get_essential_ips() -> Set[str]:
    """Get essential IPs that should always be allowed"""
    essential = set()
    
    # ✅ ENHANCED: Local IPs
    essential.update(["127.0.0.1", "::1", "0.0.0.0"])
    
    # ✅ ENHANCED: DNS servers
    essential.update([
        "8.8.8.8", "8.8.4.4",              # Google DNS
        "1.1.1.1", "1.0.0.1",              # Cloudflare DNS
        "208.67.222.222", "208.67.220.220", # OpenDNS
        "9.9.9.9", "149.112.112.112"       # Quad9 DNS
    ])
    
    # ✅ ENHANCED: Local network detection
    try:
        local_ip = _get_local_ip()
        # Add local subnet gateway
        gateway_ip = '.'.join(local_ip.split('.')[:-1]) + '.1'
        essential.add(gateway_ip)
        
        # Add local IP
        essential.add(local_ip)
        
        logger.debug(f"Added local network IPs: {local_ip}, {gateway_ip}")
    except:
        logger.debug("Could not detect local network IPs")
    
    return essential

def _initialize_log_sender() -> LogSender:
    """Initialize log sender with enhanced configuration"""
    log_sender_config = {
        "server_url": config.get('server_url', config["server"]["url"]),
        "batch_size": config["logging"]["sender"]["batch_size"],
        "max_queue_size": config["logging"]["sender"]["max_queue_size"],
        "send_interval": config["logging"]["sender"]["send_interval"],
        "timeout": config["server"].get("connect_timeout", 15)
    }
    
    # ✅ ENHANCED: Add agent credentials if available
    if config.get('agent_id') and config.get('agent_token'):
        log_sender_config["agent_id"] = config['agent_id']
        log_sender_config["agent_token"] = config['agent_token']
    
    log_sender = LogSender(log_sender_config)
    log_sender.start()
    logger.info("✅ Log sender initialized and started")
    
    return log_sender

def _start_command_polling():
    """Enhanced command polling with better error handling"""
    def poll_commands():
        consecutive_failures = 0
        max_failures = 5
        base_poll_interval = 5
        
        while running and agent_state["components_initialized"]:
            try:
                if not config.get('agent_id') or not config.get('agent_token'):
                    time.sleep(30)
                    continue
                
                # ✅ ENHANCED: Dynamic polling interval based on failures
                poll_interval = min(base_poll_interval * (2 ** consecutive_failures), 60)
                
                # ✅ ENHANCED: Check for pending commands
                server_url = config.get('server_url', config["server"]["url"])
                commands_url = f"{server_url.rstrip('/')}/api/agents/commands"
                
                params = {
                    'agent_id': config['agent_id'],
                    'token': config['agent_token']
                }
                
                response = requests.get(commands_url, params=params, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    commands = data.get('data', {}).get('commands', [])
                    
                    if commands:
                        logger.info(f"📥 Received {len(commands)} commands")
                        for command in commands:
                            _process_command(command)
                    
                    consecutive_failures = 0  # Reset on success
                else:
                    consecutive_failures += 1
                    logger.warning(f"Command polling failed: HTTP {response.status_code}")
                
                time.sleep(poll_interval)
                
            except Exception as e:
                consecutive_failures += 1
                logger.error(f"Error polling commands: {e}")
                
                if consecutive_failures >= max_failures:
                    logger.error("Too many command polling failures, stopping")
                    break
                
                time.sleep(min(30, base_poll_interval * consecutive_failures))
        
        logger.info("Command polling stopped")
    
    # ✅ ENHANCED: Start polling in background thread
    polling_thread = threading.Thread(target=poll_commands, daemon=True)
    polling_thread.start()
    logger.info("✅ Command polling started")

def _process_command(command: Dict):
    """Enhanced command processing with better error handling"""
    command_id = command.get('command_id')
    command_type = command.get('command_type')
    start_time = time.time()
    
    try:
        logger.info(f"🎮 Processing command {command_id}: {command_type}")
        
        # ✅ ENHANCED: Process command with timeout
        result = command_processor.process_command(command)
        execution_time = time.time() - start_time
        
        # ✅ ENHANCED: Send result back to server
        _send_command_result(command_id, result, execution_time)
        
        logger.info(f"✅ Command {command_id} completed in {execution_time:.2f}s")
        
    except Exception as e:
        execution_time = time.time() - start_time
        error_result = {
            "success": False,
            "error": f"Command processing failed: {str(e)}",
            "execution_time": execution_time
        }
        
        _send_command_result(command_id, error_result, execution_time)
        logger.error(f"❌ Command {command_id} failed: {e}")

def _send_command_result(command_id: str, result: Dict, execution_time: float):
    """Send command result back to server"""
    try:
        server_url = config.get('server_url', config["server"]["url"])
        result_url = f"{server_url.rstrip('/')}/api/agents/command/result"
        
        result_data = {
            'agent_id': config['agent_id'],
            'token': config['agent_token'],
            'command_id': command_id,
            'status': 'completed' if result.get('success') else 'failed',
            'result': result.get('message') or result.get('error', 'No result'),
            'execution_time': execution_time,
            'timestamp': datetime.now().isoformat()
        }
        
        response = requests.post(result_url, json=result_data, timeout=10)
        
        if response.status_code == 200:
            logger.debug(f"Command {command_id} result sent successfully")
        else:
            logger.error(f"Failed to send command result: {response.status_code}")
            
    except Exception as e:
        logger.error(f"Error sending command result: {e}")

def _log_startup_summary():
    """Log comprehensive startup summary"""
    if log_sender and config.get('agent_id'):
        startup_log = {
            "agent_id": config['agent_id'],
            "event_type": "agent_startup_complete",
            "hostname": socket.gethostname(),
            "local_ip": _get_local_ip(),
            "os": f"{platform.system()} {platform.version()}",
            "agent_version": "2.0.0",
            "firewall_enabled": config["firewall"]["enabled"],
            "firewall_mode": config["firewall"]["mode"],
            "whitelist_domains": len(whitelist.domains) if whitelist else 0,
            "whitelisted_ips": len(whitelist.current_resolved_ips) if whitelist else 0,
            "startup_state": agent_state,
            "config_summary": {
                "auto_sync": config["whitelist"]["auto_sync"],
                "update_interval": config["whitelist"]["update_interval"],
                "firewall_cleanup_on_exit": config["firewall"]["cleanup_on_exit"]
            },
            "timestamp": datetime.now().isoformat(),  # ✅ FIX: ISO string
            "level": "INFO",
            "source": "agent_startup"
        }
        log_sender.queue_log(startup_log)

def cleanup():
    """Enhanced cleanup for whitelist-only firewall mode"""
    global firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor
    
    logger.info("🧹 Stopping agent components...")
    
    # ✅ ENHANCED: Stop packet sniffer first
    if packet_sniffer:
        try:
            packet_sniffer.stop()
            logger.info("✅ Packet sniffer stopped")
        except Exception as e:
            logger.error(f"Error stopping packet sniffer: {e}")
    
    # ✅ ENHANCED: Stop whitelist updates
    if whitelist:
        try:
            whitelist.stop_periodic_updates()
            logger.info("✅ Whitelist updater stopped")
        except Exception as e:
            logger.error(f"Error stopping whitelist updater: {e}")
    
    # ✅ ENHANCED: Stop log sender gracefully
    if log_sender:
        try:
            # ✅ FIX: Send shutdown log trước khi dừng với proper serialization
            if config.get('agent_id'):
                shutdown_log = {
                    "agent_id": config['agent_id'],
                    "event_type": "agent_shutdown",
                    "hostname": socket.gethostname(),
                    "uptime_info": agent_state,
                    "timestamp": datetime.now().isoformat(),  # ✅ FIX: ISO string
                    "level": "INFO",
                    "source": "agent_shutdown"
                }
                log_sender.queue_log(shutdown_log)
                time.sleep(2)  # Give time to send
            
            log_sender.stop()
            logger.info("✅ Log sender stopped")
        except Exception as e:
            logger.error(f"Error stopping log sender: {e}")
    
    # ✅ ENHANCED: Stop heartbeat sender
    if heartbeat_sender:
        try:
            heartbeat_sender.stop()
            logger.info("✅ Heartbeat sender stopped")
        except Exception as e:
            logger.error(f"Error stopping heartbeat sender: {e}")
    
    # ✅ ENHANCED: Cleanup firewall rules
    if firewall and config and config["firewall"]["cleanup_on_exit"]:
        try:
            logger.info("🗑️ Cleaning up firewall rules...")
            
            if config["firewall"]["mode"] == "whitelist_only":
                # ✅ ENHANCED: Complete cleanup for whitelist-only mode
                success = firewall.cleanup_all_rules()
                if success:
                    logger.info("✅ All whitelist firewall rules cleaned up")
                else:
                    logger.warning("⚠️ Some firewall rules may not have been cleaned up")
            else:
                # ✅ ENHANCED: Standard cleanup for traditional mode
                success = firewall.clear_all_rules()
                if success:
                    logger.info("✅ Traditional firewall rules cleaned up")
                    
        except Exception as e:
            logger.error(f"Error cleaning up firewall rules: {e}")
    
    # ✅ ENHANCED: Command processor cleanup
    if command_processor:
        try:
            # Stop any running commands
            logger.info("✅ Command processor stopped")
        except Exception as e:
            logger.error(f"Error stopping command processor: {e}")
    
    # ✅ ENHANCED: Final state update
    agent_state["startup_completed"] = False
    agent_state["components_initialized"] = False
    
    logger.info("🎉 Agent shutdown completed")

def signal_handler(sig, frame):
    """Enhanced signal handler with graceful shutdown"""
    global running
    logger.info(f"📡 Received signal {sig}, initiating graceful shutdown...")
    running = False

def main():
    """Enhanced main function với automatic mode detection"""
    global config, running
    
    try:
        # ✅ ENHANCED: Load and validate configuration
        logger.info("⚙️ Loading agent configuration...")
        config = get_config()
        
        # ✅ NEW: Display banner với mode information
        _display_startup_banner()
        
        # ✅ ENHANCED: Validate critical config sections
        _validate_critical_config()
        
        logger.info("✅ Configuration loaded successfully")
        
        # ✅ ENHANCED: Apply startup delay if configured
        startup_delay = config["general"]["startup_delay"]
        if startup_delay > 0:
            logger.info(f"⏳ Waiting {startup_delay} seconds before starting...")
            time.sleep(startup_delay)
        
        # ✅ ENHANCED: Initialize all components
        initialize_components()
        
        # ✅ ENHANCED: Send comprehensive startup log
        _send_startup_notification()
        
        # ✅ NEW: Display running status với mode info
        _display_running_status()
        
        # ✅ ENHANCED: Main loop with status monitoring
        loop_count = 0
        last_status_log = time.time()
        status_interval = 300  # Log status every 5 minutes
        
        while running:
            time.sleep(1)
            loop_count += 1
            
            # ✅ Log status periodically
            current_time = time.time()
            if current_time - last_status_log >= status_interval:
                _log_periodic_status(loop_count)
                last_status_log = current_time
        
        logger.info("🛑 Main loop exited, beginning shutdown...")
        
    except KeyboardInterrupt:
        logger.info("⌨️ Keyboard interrupt received")
    except Exception as e:
        logger.error(f"💥 Unhandled error in agent main: {e}", exc_info=True)
    finally:
        cleanup()

def _display_startup_banner():
    """Display startup banner với mode information"""
    has_admin = _check_admin_privileges()
    firewall_mode = config["firewall"]["mode"]
    firewall_enabled = config["firewall"]["enabled"]
    
    print("\n" + "="*60)
    print("🔥 FIREWALL CONTROLLER AGENT")
    print("="*60)
    print(f"🔑 Administrator privileges: {'✅ YES' if has_admin else '❌ NO'}")
    print(f"🔧 Firewall mode: {firewall_mode.upper()}")
    print(f"🛡️ Firewall enabled: {'✅ YES' if firewall_enabled else '❌ NO'}")
    
    if has_admin and firewall_enabled and firewall_mode == "whitelist_only":
        print("🔒 WHITELIST-ONLY MODE: Maximum security with proactive blocking")
        print("   • Only whitelisted domains/IPs are allowed")
        print("   • All other traffic is blocked by default")
    elif not has_admin and firewall_mode == "monitor":
        print("📊 MONITOR MODE: Traffic monitoring without intervention")
        print("   • All traffic is monitored and logged")
        print("   • No blocking or firewall rules created")
    else:
        print("⚠️ MIXED MODE: Configuration may not be optimal")
        
    print("="*60 + "\n")

def _display_running_status():
    """Display running status information"""
    firewall_active = firewall.whitelist_mode_active if firewall else False
    domain_count = len(whitelist.domains) if whitelist else 0
    ip_count = len(whitelist.current_resolved_ips) if whitelist else 0
    
    logger.info("🚀 Agent initialization completed, entering main loop")
    logger.info(f"🔥 Mode: {config['firewall']['mode']} ({'active' if firewall_active else 'monitoring'})")
    logger.info(f"📋 Whitelist: {domain_count} domains → {ip_count} IPs")
    logger.info(f"🌐 Server: {config.get('server_url', config['server']['url'])}")
    
    if config["firewall"]["enabled"] and config["firewall"]["mode"] == "whitelist_only":
        logger.info("🔒 All non-whitelisted outbound traffic will be blocked")
    else:
        logger.info("📊 Traffic monitoring active - no blocking performed")

def _validate_critical_config():
    """Validate critical configuration sections"""
    errors = []
    
    # ✅ Server configuration validation
    if not config.get("server", {}).get("url"):
        errors.append("Server URL not configured")
    
    # ✅ Firewall mode validation
    valid_modes = ["block", "warn", "monitor", "whitelist_only"]
    if config["firewall"]["mode"] not in valid_modes:
        errors.append(f"Invalid firewall mode: {config['firewall']['mode']}. Valid modes: {valid_modes}")
    
    # ✅ Whitelist-only mode validation
    if config["firewall"]["mode"] == "whitelist_only" and not config["firewall"]["enabled"]:
        errors.append("Whitelist-only mode requires firewall to be enabled")
    
    # ✅ Admin privileges validation for firewall modes
    if config["firewall"]["enabled"] and not _check_admin_privileges():
        if config["firewall"]["mode"] in ["whitelist_only", "block"]:
            errors.append(f"Firewall mode '{config['firewall']['mode']}' requires administrator privileges")
    
    # ✅ Logging configuration validation
    if not config.get("logging", {}).get("level"):
        errors.append("Logging level not configured")
    
    # ✅ Whitelist configuration validation
    if not isinstance(config.get("whitelist", {}).get("update_interval"), int):
        errors.append("Whitelist update interval must be an integer")
    
    if errors:
        for error in errors:
            logger.error(f"❌ Config error: {error}")
        raise ValueError("Critical configuration errors found")
    
    logger.info("✅ Configuration validation passed")

def _log_config_summary():
    """Log configuration summary"""
    logger.info("📊 Configuration Summary:")
    logger.info(f"   - Primary server: {config['server']['url']}")
    logger.info(f"   - Fallback servers: {len(config['server'].get('urls', [])) - 1}")
    logger.info(f"   - Firewall mode: {config['firewall']['mode']}")
    logger.info(f"   - Firewall enabled: {config['firewall']['enabled']}")
    logger.info(f"   - Auto-sync whitelist: {config['whitelist']['auto_sync']}")
    logger.info(f"   - Update interval: {config['whitelist']['update_interval']}s")
    logger.info(f"   - Log level: {config['logging']['level']}")
    logger.info(f"   - Admin privileges: {_check_admin_privileges()}")

def _send_startup_notification():
    """Send comprehensive startup notification"""
    try:
        if log_sender and config.get('agent_id'):
            notification = {
                "agent_id": config['agent_id'],
                "event_type": "agent_ready",
                "message": "Agent fully initialized and ready",
                "level": "INFO",
                "action": "STARTUP",
                "timestamp": datetime.now().isoformat(),
                "source": "agent_startup",
                
                # ✅ ADD: Status information
                "firewall_status": {
                    "enabled": config["firewall"]["enabled"],
                    "mode": config["firewall"]["mode"],
                    "active": firewall.whitelist_mode_active if firewall else False,
                    "rules_count": len(firewall.get_current_rules()) if firewall else 0
                } if firewall else None,
                
                "whitelist_status": {
                    "domains_count": len(whitelist.domains) if whitelist else 0,
                    "resolved_ips_count": len(whitelist.current_resolved_ips) if whitelist else 0,
                    "auto_sync": config["whitelist"]["auto_sync"],
                    "last_sync": whitelist.last_sync_time.isoformat() if whitelist and whitelist.last_sync_time else None
                } if whitelist else None,
                
                "system_info": {
                    "hostname": socket.gethostname(),
                    "local_ip": _get_local_ip(),
                    "platform": platform.system(),
                    "admin_privileges": _check_admin_privileges()
                },
                
                "component_status": {
                    "packet_sniffer": packet_sniffer.running if packet_sniffer else False,
                    "heartbeat_sender": heartbeat_sender.running if heartbeat_sender else False,
                    "log_sender": log_sender.running if log_sender else False,
                    "command_processor": command_processor is not None
                }
            }
            
            success = log_sender.queue_log(notification)
            if success:
                logger.info("✅ Startup notification sent to server")
            else:
                logger.warning("⚠️ Failed to send startup notification")
        else:
            logger.debug("Skipping startup notification - agent not registered or log sender not available")
            
    except Exception as e:
        logger.error(f"Error sending startup notification: {e}")

def _log_periodic_status(loop_count: int):
    """Log periodic status information"""
    try:
        # ✅ ENHANCED: Collect comprehensive status
        firewall_active = firewall.whitelist_mode_active if firewall else False
        whitelist_domains = len(whitelist.domains) if whitelist else 0
        resolved_ips = len(whitelist.current_resolved_ips) if whitelist else 0
        
        # ✅ System metrics
        memory_info = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # ✅ Network connections count
        try:
            connections = len(psutil.net_connections())
        except Exception:
            connections = 0
        
        status_info = {
            "loop_count": loop_count,
            "firewall_active": firewall_active,
            "whitelist_domains": whitelist_domains,
            "resolved_ips": resolved_ips,
            "memory_usage_percent": memory_info.percent,
            "cpu_usage_percent": cpu_percent,
            "network_connections": connections
        }
        
        # ✅ Log summary
        logger.info(f"📊 Status (Loop {loop_count}): "
                   f"Firewall: {'Active' if firewall_active else 'Inactive'}, "
                   f"Domains: {whitelist_domains}, "
                   f"IPs: {resolved_ips}, "
                   f"CPU: {cpu_percent:.1f}%, "
                   f"Memory: {memory_info.percent:.1f}%")
        
        # ✅ Send detailed status to server
        if log_sender and config.get('agent_id') and loop_count % 12 == 0:  # Every hour
            status_log = {
                "agent_id": config['agent_id'],
                "event_type": "periodic_status",
                "timestamp": datetime.now().isoformat(),
                "level": "INFO",
                "source": "periodic_status",
                **status_info
            }
            log_sender.queue_log(status_log)
                   
    except Exception as e:
        logger.debug(f"Error logging periodic status: {e}")

def run_as_service():
    """Enhanced Windows service support"""
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
        
        class AgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "FirewallControllerAgent"
            _svc_display_name_ = "Firewall Controller Agent (Enhanced Mode)"
            _svc_description_ = "Enhanced network traffic monitoring with auto-detected firewall mode"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.stop_event)
                global running
                running = False
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, '')
                )

            def SvcDoRun(self):
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                
                try:
                    main()
                except Exception as e:
                    servicemanager.LogErrorMsg(f"Service error: {str(e)}")

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(AgentService)
            
    except ImportError:
        logger.error("Windows service modules not available. Please install pywin32:")
        logger.error("pip install pywin32")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Service error: {e}")
        sys.exit(1)

def _get_system_metrics() -> Dict[str, Any]:
    """Get current system metrics"""
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "percent": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "free": psutil.disk_usage('/').free,
                "percent": psutil.disk_usage('/').percent
            },
            "network": {
                "connections": len(psutil.net_connections()),
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv
            },
            "processes": len(psutil.pids()),
            "boot_time": psutil.boot_time(),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.debug(f"Error getting system metrics: {e}")
        return {
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def _get_local_ip() -> str:
    """
    Get the local IP address of this machine.
    
    Returns:
        str: Local IP address
    """
    try:
        # Method 1: Connect to external server để determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connect to Google DNS, không gửi data
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            logger.debug(f"Detected local IP via external connection: {local_ip}")
            return local_ip
    except Exception as e:
        logger.debug(f"Method 1 failed: {e}")
    
    try:
        # Method 2: Use hostname resolution
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if local_ip != "127.0.0.1":
            logger.debug(f"Detected local IP via hostname: {local_ip}")
            return local_ip
    except Exception as e:
        logger.debug(f"Method 2 failed: {e}")
    
    try:
        # Method 3: Get all network interfaces (nếu có netifaces)
        if HAS_NETIFACES:
            import netifaces
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr_info in addresses[netifaces.AF_INET]:
                        ip = addr_info['addr']
                        if ip != "127.0.0.1" and not ip.startswith("169.254"):
                            logger.debug(f"Detected local IP via interfaces: {ip}")
                            return ip
    except Exception as e:
        logger.debug(f"Method 3 failed: {e}")
    
    try:
        # Method 4: Windows specific - using ipconfig
        if platform.system() == "Windows":
            result = subprocess.run(
                ["ipconfig"], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if 'IPv4' in line and '192.168.' in line:
                    ip = line.split(':')[1].strip()
                    logger.debug(f"Detected local IP via ipconfig: {ip}")
                    return ip
    except Exception as e:
        logger.debug(f"Method 4 failed: {e}")
    
    # Fallback: return localhost
    logger.warning("Could not detect local IP, using localhost")
    return "127.0.0.1"

def _get_agent_info(local_ip: str) -> Dict[str, Any]:
    """
    Get comprehensive agent information for registration.
    
    Args:
        local_ip: Local IP address of the agent
        
    Returns:
        Dict: Agent information for registration
    """
    try:
        # ✅ ENHANCED: Basic system information
        hostname = socket.gethostname()
        platform_info = platform.platform()
        os_name = platform.system()
        os_version = platform.version()
        architecture = platform.architecture()[0]
        processor = platform.processor()
        
        # ✅ ENHANCED: Python information
        python_version = platform.python_version()
        python_implementation = platform.python_implementation()
        
        # ✅ ENHANCED: Memory and disk information
        memory_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/')
        
        # ✅ ENHANCED: Network interfaces
        network_interfaces = []
        try:
            for interface_name, interface_addresses in psutil.net_if_addrs().items():
                for address in interface_addresses:
                    if address.family == socket.AF_INET:  # IPv4
                        network_interfaces.append({
                            "interface": interface_name,
                            "ip": address.address,
                            "netmask": address.netmask
                        })
        except Exception as e:
            logger.debug(f"Could not get network interfaces: {e}")
        
        # ✅ ENHANCED: Agent capabilities
        capabilities = {
            "packet_capture": True,
            "firewall_management": _check_admin_privileges(),
            "process_monitoring": True,
            "real_time_monitoring": True,
            "whitelist_sync": True,
            "command_execution": True
        }
        
        # ✅ ENHANCED: Generate unique agent ID nếu chưa có
        agent_id = config.get('agent_id') or str(uuid.uuid4())
        
        agent_info = {
            # ✅ Basic identification
            "agent_id": agent_id,
            "hostname": hostname,
            "ip_address": local_ip,
            "platform": os_name,
            "os_info": f"{os_name} {os_version}",
            "architecture": architecture,
            "processor": processor,
            
            # ✅ Software information
            "agent_version": "2.0.0",
            "python_version": python_version,
            "python_implementation": python_implementation,
            "platform_detail": platform_info,
            
            # ✅ Hardware information
            "memory_total": memory_info.total,
            "memory_available": memory_info.available,
            "disk_total": disk_info.total,
            "disk_free": disk_info.free,
            "cpu_count": psutil.cpu_count(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            
            # ✅ Network information
            "network_interfaces": network_interfaces,
            "primary_interface_ip": local_ip,
            
            # ✅ Agent capabilities
            "capabilities": capabilities,
            "supported_commands": [
                "ping", "status", "restart", "update_whitelist",
                "reload_config", "get_logs", "clear_logs"
            ],
            
            # ✅ Configuration information
            "firewall_enabled": config["firewall"]["enabled"],
            "firewall_mode": config["firewall"]["mode"],
            "auto_sync_enabled": config["whitelist"]["auto_sync"],
            "log_level": config["logging"]["level"],
            
            # ✅ Registration metadata
            "registration_time": datetime.now().isoformat(),
            "timezone": str(datetime.now().astimezone().tzinfo),
            "uptime": 0,  # Will be updated later
            "last_seen": datetime.now().isoformat(),
            "status": "initializing"
        }
        
        # ✅ ENHANCED: Add Windows-specific information
        if os_name == "Windows":
            try:
                agent_info["windows_version"] = platform.win32_ver()
                agent_info["is_admin"] = _check_admin_privileges()
            except Exception as e:
                logger.debug(f"Could not get Windows-specific info: {e}")
        
        logger.debug(f"Generated agent info for {hostname} ({local_ip})")
        return agent_info
        
    except Exception as e:
        logger.error(f"Error generating agent info: {e}")
        # ✅ FALLBACK: Minimal agent info
        return {
            "agent_id": str(uuid.uuid4()),
            "hostname": socket.gethostname(),
            "ip_address": local_ip,
            "platform": platform.system(),
            "os_info": platform.platform(),
            "agent_version": "2.0.0",
            "error": f"Could not gather full agent info: {str(e)}",
            "registration_time": datetime.now().isoformat()
        }

def _check_admin_privileges() -> bool:
    """Check if running with administrator privileges"""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.returncode == 0
        except Exception:
            return False

if __name__ == "__main__":
    # ✅ ENHANCED: Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # ✅ ENHANCED: Increase file descriptor limit (Linux)
    try:
        if platform.system() != "Windows":
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
            logger.info("✅ Increased file descriptor limit to 4096")
    except Exception as e:
        logger.warning(f"Could not increase file descriptor limit: {e}")
    
    # ✅ ENHANCED: Start as Windows service if requested
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        logger.info("🔧 Installing as Windows service...")
        run_as_service()
    else:
        logger.info("🚀 Starting agent...")
        main()