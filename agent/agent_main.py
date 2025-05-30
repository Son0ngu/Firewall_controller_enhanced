"""
Firewall Controller Agent - Module Chính (Enhanced for Auto-Detection Mode)

Enhanced agent với auto-detection firewall mode:
- ADMIN PRIVILEGES: whitelist-only mode với proactive blocking
- NO ADMIN PRIVILEGES: monitor mode với passive monitoring
- AUTO-DETECTION: Tự động chọn mode tối ưu cho privileges
"""

# Import các thư viện cần thiết
import sys
import logging
import signal
import socket
import threading
import time
import platform
import subprocess
import re
import json
import os
import requests
import psutil
import uuid
import ctypes
from datetime import datetime, timedelta  # ✅ FIX: Import datetime class correctly
from typing import Dict, Any, Set
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

# ✅ FIX: Setup logging BEFORE other imports to avoid undefined logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# ✅ FIX: Import all required modules
from config import get_config
from firewall_manager import FirewallManager
from log_sender import LogSender
from packet_sniffer import PacketSniffer
from whitelist import WhitelistManager
from heartbeat_sender import HeartbeatSender
from command_processor import CommandProcessor

logger = logging.getLogger("agent_main")

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

# ✅ FIX: Complete handle_domain_detection method
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
        
        # ✅ ENHANCED: Enhanced record with mode information
        enhanced_record = {
            "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
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
                "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
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

def _check_admin_privileges() -> bool:
    """Check if running with administrator privileges"""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def _get_local_ip() -> str:
    """Get the local IP address of this machine"""
    try:
        # Method 1: Connect to external server to determine local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        logger.debug(f"Method 1 failed: {e}")
    
    try:
        # Method 2: Use hostname resolution
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        if local_ip != "127.0.0.1":
            return local_ip
    except Exception as e:
        logger.debug(f"Method 2 failed: {e}")
    
    try:
        # Method 3: Get all network interfaces (if available)
        if HAS_NETIFACES:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.') and not ip.startswith('169.254.'):
                            return ip
    except Exception as e:
        logger.debug(f"Method 3 failed: {e}")
    
    try:
        # Method 4: Use platform-specific commands
        if platform.system() == "Windows":
            import subprocess
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            for line in lines:
                if 'IPv4 Address' in line and ':' in line:
                    ip = line.split(':')[1].strip()
                    if not ip.startswith('127.') and not ip.startswith('169.254.'):
                        return ip
    except Exception as e:
        logger.debug(f"Method 4 failed: {e}")
    
    # Fallback: return localhost
    logger.warning("Could not detect local IP, using localhost")
    return "127.0.0.1"

def _get_agent_info(local_ip: str) -> Dict[str, Any]:
    """Get comprehensive agent information for registration"""
    try:
        hostname = socket.gethostname()
        platform_info = platform.platform()
        os_name = platform.system()
        os_version = platform.version()
        
        # Basic agent info
        agent_info = {
            "agent_id": str(uuid.uuid4()),
            "hostname": hostname,
            "ip_address": local_ip,
            "platform": os_name,
            "os_info": f"{os_name} {os_version}",
            "agent_version": "2.0.0",
            "python_version": platform.python_version(),
            "platform_detail": platform_info,
            "registration_time": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
            "capabilities": {
                "packet_capture": True,
                "firewall_management": _check_admin_privileges(),
                "process_monitoring": True,
                "real_time_monitoring": True,
                "whitelist_sync": True,
                "command_execution": True
            },
            "firewall_enabled": config["firewall"]["enabled"],
            "firewall_mode": config["firewall"]["mode"],
            "auto_sync_enabled": config["whitelist"]["auto_sync"],
            "log_level": config["logging"]["level"],
            "status": "initializing"
        }
        
        # Add system info if psutil available
        try:
            memory_info = psutil.virtual_memory()
            disk_info = psutil.disk_usage('/')
            
            agent_info.update({
                "memory_total": memory_info.total,
                "memory_available": memory_info.available,
                "disk_total": disk_info.total,
                "disk_free": disk_info.free,
                "cpu_count": psutil.cpu_count(),
                "cpu_count_logical": psutil.cpu_count(logical=True)
            })
        except Exception as e:
            logger.debug(f"Could not get system info: {e}")
        
        return agent_info
        
    except Exception as e:
        logger.error(f"Error generating agent info: {e}")
        return {
            "agent_id": str(uuid.uuid4()),
            "hostname": socket.gethostname(),
            "ip_address": local_ip,
            "platform": platform.system(),
            "agent_version": "2.0.0",
            "error": f"Could not gather full agent info: {str(e)}",
            "registration_time": datetime.now().isoformat()  # ✅ FIX: Use datetime.now() correctly
        }

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
    """Phát hiện và log mode được chọn dựa trên quyền admin"""
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
            # ✅ FIX: Use correct endpoint
            register_url = f"{server_url.rstrip('/')}/api/agents/register"
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
    """Setup whitelist-only firewall (STARTUP PHASE 3) - ENHANCED"""
    try:
        if not firewall or not whitelist:
            logger.error("Firewall or whitelist not available for setup")
            return False
        
        # ✅ ENHANCED: Wait for whitelist to be ready với extended timeout
        max_wait = 90  # 90 seconds max wait (increased)
        wait_time = 0
        sync_check_interval = 3  # Check every 3 seconds
        
        logger.info("⏳ Waiting for whitelist sync to complete...")
        
        while not whitelist.startup_sync_completed and wait_time < max_wait:
            logger.info(f"   Waiting for whitelist sync... ({wait_time}s/{max_wait}s)")
            time.sleep(sync_check_interval)
            wait_time += sync_check_interval
            
            # ✅ ADD: Show progress
            if wait_time % 15 == 0:  # Every 15 seconds
                domain_count = len(whitelist.domains)
                ip_count = len(whitelist.current_resolved_ips)
                logger.info(f"   Current: {domain_count} domains → {ip_count} IPs")
        
        if not whitelist.startup_sync_completed:
            logger.warning("⚠️ Whitelist sync not completed within timeout")
            logger.info(f"   Proceeding with {len(whitelist.domains)} cached domains")
        else:
            logger.info(f"✅ Whitelist sync completed with {len(whitelist.domains)} domains")
        
        # ✅ ENHANCED: Ensure we have some domains before proceeding
        if len(whitelist.domains) == 0:
            logger.warning("⚠️ No domains in whitelist - adding emergency domains")
            emergency_domains = {
                "github.com",
                "raw.githubusercontent.com", 
                "google.com",
                "microsoft.com",
                config['server']['url'].replace('https://', '').replace('http://', '').split('/')[0]
            }
            whitelist.domains.update(emergency_domains)
            logger.info(f"✅ Added {len(emergency_domains)} emergency domains")
        
        # ✅ ENHANCED: Force comprehensive IP resolution with multiple attempts
        logger.info("🔍 Performing comprehensive IP resolution...")
        max_resolution_attempts = 5  # Increased attempts
        resolution_attempt = 0
        best_ip_count = 0
        
        while resolution_attempt < max_resolution_attempts:
            resolution_attempt += 1
            logger.info(f"   Resolution attempt {resolution_attempt}/{max_resolution_attempts}")
            
            # ✅ ENHANCED: Clear cache on subsequent attempts
            if resolution_attempt > 1:
                logger.info("   Clearing IP cache for fresh resolution...")
                whitelist.ip_cache.clear()
                whitelist.ip_cache_timestamps.clear()
            
            # Force refresh all domain IPs
            success = whitelist._resolve_all_domain_ips(force_refresh=True)
            
            resolved_ips = whitelist.get_all_whitelisted_ips(force_refresh=True)
            current_count = len(resolved_ips)
            
            logger.info(f"   Attempt {resolution_attempt}: {current_count} IPs from {len(whitelist.domains)} domains")
            
            # ✅ ENHANCED: Track best result
            if current_count > best_ip_count:
                best_ip_count = current_count
            
            # ✅ ENHANCED: Success criteria - we need reasonable number of IPs
            min_expected_ips = len(whitelist.domains) * 1  # At least 1 IP per domain
            if current_count >= min_expected_ips:
                logger.info(f"✅ Sufficient IPs resolved: {current_count} >= {min_expected_ips}")
                break
            
            if resolution_attempt < max_resolution_attempts:
                logger.warning(f"   Only {current_count} IPs resolved, retrying in 10 seconds...")
                time.sleep(10)
        
        # ✅ ENHANCED: Get final whitelisted IPs
        whitelisted_ips = whitelist.get_all_whitelisted_ips(force_refresh=True)
        
        if not whitelisted_ips:
            logger.error("❌ No whitelisted IPs found after all resolution attempts!")
            # ✅ ENHANCED: Add emergency allowlist
            emergency_ips = _get_emergency_allowlist()
            whitelisted_ips = emergency_ips
            logger.info(f"🆘 Using emergency allowlist: {len(emergency_ips)} IPs")
        
        logger.info(f"📍 Final IPs to whitelist: {len(whitelisted_ips)}")
        
        # ✅ DEBUG: Log detailed IP breakdown
        sample_ips = list(whitelisted_ips)[:8]
        logger.info(f"   Sample IPs: {sample_ips}")
        
        # ✅ ENHANCED: Get essential IPs
        essential_ips = _get_essential_ips()
        logger.info(f"🔧 Essential IPs: {len(essential_ips)}")
        logger.info(f"   Essential sample: {list(essential_ips)[:5]}")
        
        # ✅ ENHANCED: Final verification
        total_allowed = len(whitelisted_ips) + len(essential_ips)
        logger.info(f"📊 Total IPs to be allowed: {total_allowed}")
        
        if total_allowed < 10:
            logger.warning(f"⚠️ Very few IPs to allow ({total_allowed}) - this may block too much traffic")
        
        # ✅ ENHANCED: Setup whitelist firewall with comprehensive logging
        logger.info("🔥 Creating firewall rules...")
        logger.info(f"   Creating allow rules for {len(whitelisted_ips)} whitelisted IPs")
        logger.info(f"   Creating allow rules for {len(essential_ips)} essential IPs")
        logger.info("⚠️ WARNING: This will block ALL other outbound traffic!")
        
        success = firewall.setup_whitelist_firewall(whitelisted_ips, essential_ips)
        
        if success:
            logger.info("✅ Whitelist-only firewall setup completed successfully")
            logger.info("🔒 Default policy: BLOCK all non-whitelisted traffic")
            logger.info(f"✅ Total allowed IPs: {total_allowed}")
            
            # ✅ ENHANCED: Verify firewall status
            status = firewall.get_whitelist_status()
            logger.info(f"🔍 Firewall status: {status}")
            
            return True
        else:
            logger.error("❌ Failed to setup whitelist-only firewall")
            return False
            
    except Exception as e:
        logger.error(f"Error setting up whitelist firewall: {e}")
        import traceback
        traceback.print_exc()
        return False

def _get_emergency_allowlist() -> set:
    """Get emergency IPs that should always be allowed"""
    emergency_ips = set()
    
    # ✅ ENHANCED: Server IPs - resolve all configured servers
    try:
        server_urls = config['server'].get('urls', [config['server']['url']])
        for url in server_urls:
            # Extract hostname from URL
            hostname = url.replace('https://', '').replace('http://', '').split('/')[0]
            try:
                server_ips = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                for ip_info in server_ips:
                    emergency_ips.add(ip_info[4][0])
                logger.info(f"🆘 Added server IPs for {hostname}")
            except Exception as e:
                logger.warning(f"Could not resolve emergency server {hostname}: {e}")
    except Exception as e:
        logger.warning(f"Error resolving emergency server IPs: {e}")
    
    # ✅ ENHANCED: Essential services domains
    essential_domains = [
        "github.com", "raw.githubusercontent.com",        # Git/GitHub
        "pypi.org", "files.pythonhosted.org",           # Python packages
        "microsoft.com", "windows.com", "live.com",     # Microsoft services
        "google.com", "googleapis.com",                 # Google services
        "cloudflare.com", "1.1.1.1"                    # DNS/CDN
    ]
    
    for domain in essential_domains:
        try:
            domain_ips = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            for ip_info in domain_ips:
                emergency_ips.add(ip_info[4][0])
            logger.debug(f"🆘 Added emergency IPs for {domain}")
        except Exception as e:
            logger.debug(f"Could not resolve emergency domain {domain}: {e}")
    
    logger.info(f"🆘 Emergency allowlist compiled: {len(emergency_ips)} IPs")
    return emergency_ips

def _get_essential_ips() -> set:
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
    """Start command polling thread"""
    def polling_loop():
        logger.info("🎮 Command polling started")
        
        while running:
            try:
                if not config.get('agent_id'):
                    time.sleep(5)
                    continue
                
                # Poll for commands from server
                server_urls = config['server'].get('urls', [config['server']['url']])
                
                for server_url in server_urls:
                    try:
                        commands_url = f"{server_url.rstrip('/')}/api/agents/{config['agent_id']}/commands"
                        
                        response = requests.get(
                            commands_url,
                            timeout=config['server'].get('connect_timeout', 15),
                            headers={'Content-Type': 'application/json'}
                        )
                        
                        if response.status_code == 200:
                            data = response.json()
                            commands = data.get('commands', [])
                            
                            for command in commands:
                                _process_command(command)
                            
                            break  # Success, break out of server loop
                            
                    except Exception as e:
                        logger.debug(f"Command polling failed for {server_url}: {e}")
                        continue
                
                time.sleep(30)  # Poll every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in command polling: {e}")
                time.sleep(60)  # Wait longer on error
    
    if command_processor:
        polling_thread = threading.Thread(target=polling_loop, daemon=True)
        polling_thread.start()
        logger.info("✅ Command polling thread started")

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
            'timestamp': datetime.now().isoformat()  # ✅ FIX: Use datetime.now() correctly
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
            "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
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
            # ✅ FIX: Send shutdown log before stopping
            if config.get('agent_id'):
                shutdown_log = {
                    "agent_id": config['agent_id'],
                    "event_type": "agent_shutdown",
                    "hostname": socket.gethostname(),
                    "uptime_info": agent_state,
                    "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
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
    """Enhanced main function with automatic mode detection"""
    global config, running
    
    try:
        # ✅ ENHANCED: Load and validate configuration
        logger.info("⚙️ Loading agent configuration...")
        config = get_config()
        
        # ✅ NEW: Display banner with mode information
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
        
        # ✅ NEW: Display running status with mode info
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

# ✅ FIX: Add all missing helper methods
def _display_startup_banner():
    """Display startup banner with mode information"""
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
        print("⚠️ MIXED MODE: Configuration may không be optimal")
        
    print("="*60 + "\n")

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
            errors.append("Firewall blocking modes require administrator privileges")
    
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

def _send_startup_notification():
    """Send comprehensive startup notification"""
    try:
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
                "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
                "level": "INFO",
                "source": "agent_startup"
            }
            log_sender.queue_log(startup_log)
        else:
            logger.debug("No log sender or agent ID available for startup notification")
            
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
        try:
            memory_info = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            connections = len(psutil.net_connections())
        except Exception:
            memory_info = None
            cpu_percent = 0
            connections = 0
        
        status_info = {
            "loop_count": loop_count,
            "firewall_active": firewall_active,
            "whitelist_domains": whitelist_domains,
            "resolved_ips": resolved_ips,
            "memory_usage_percent": memory_info.percent if memory_info else 0,
            "cpu_usage_percent": cpu_percent,
            "network_connections": connections
        }
        
        # ✅ Log summary
        logger.info(f"📊 Status (Loop {loop_count}): "
                   f"Firewall: {'Active' if firewall_active else 'Inactive'}, "
                   f"Domains: {whitelist_domains}, "
                   f"IPs: {resolved_ips}, "
                   f"CPU: {cpu_percent:.1f}%, "
                   f"Memory: {memory_info.percent:.1f}%" if memory_info else "Memory: N/A")
        
        # ✅ Send detailed status to server
        if log_sender and config.get('agent_id') and loop_count % 12 == 0:  # Every hour
            status_log = {
                "agent_id": config['agent_id'],
                "event_type": "agent_status_report",
                "status_info": status_info,
                "timestamp": datetime.now().isoformat(),  # ✅ FIX: Use datetime.now() correctly
                "level": "INFO",
                "source": "agent_status"
            }
            log_sender.queue_log(status_log)
                   
    except Exception as e:
        logger.debug(f"Error logging periodic status: {e}")

# ✅ FIX: Add signal handlers
def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown"""
    if platform.system() != "Windows":
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
    else:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

# ✅ ENTRY POINT
if __name__ == "__main__":
    try:
        # ✅ Setup signal handlers
        setup_signal_handlers()
        
        # ✅ Check if running as service
        if len(sys.argv) > 1 and sys.argv[1] in ['install', 'remove', 'start', 'stop', 'restart']:
            run_as_service()
        else:
            # ✅ Run normally
            main()
            
    except KeyboardInterrupt:
        logger.info("Application terminated by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)