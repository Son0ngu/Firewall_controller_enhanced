"""
Firewall Controller Agent - Module Chính (Refactored)

Đây là điểm khởi đầu cho ứng dụng agent được tối ưu hóa và làm sạch:
- Configuration validation at startup
- Consolidated IP detection logic
- Enhanced error handling in critical paths
- Streamlined component initialization
- UTC ONLY - No timezone confusion
"""

# ========================================
# IMPORTS - UTC ONLY
# ========================================

# Core system libraries
import logging
import signal
import sys
import threading
import json
from typing import Dict, Optional, Set, List

# Network & system utilities
import socket
import platform
import requests
import psutil
import netifaces 

# Custom modules
from config import get_config
from firewall_manager import FirewallManager
from whitelist import WhitelistManager
from packet_sniffer import PacketSniffer
from log_sender import LogSender
from heartbeat_sender import HeartbeatSender
from command_processor import CommandProcessor

# UPDATED: Clean time utilities - UTC only
from time_utils import (
    now, now_iso, now_server_compatible,
    uptime, uptime_string, sleep,
    is_cache_valid, cache_age,
    debug_time_info 
)

# ========================================
# LOGGING CONFIGURATION
# ========================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("agent_main")

# ========================================
# GLOBAL VARIABLES & STATE
# ========================================

# Component instances - được khởi tạo trong initialize_components()
config = None
firewall = None
whitelist = None
log_sender = None
packet_sniffer = None
heartbeat_sender = None
command_processor = None

# Agent state tracking
running = True
agent_state = {
    "startup_completed": False,
    "registration_completed": False,
    "components_initialized": False,
    "admin_privileges": False,
    "local_ip": None,
    "agent_id": None
}

# ========================================
# CONFIGURATION VALIDATION
# ========================================

def validate_configuration(config: Dict) -> bool:
    """
    REQUIRED: Validate configuration at startup
    
    Kiểm tra tính hợp lệ của cấu hình trước khi khởi động agent.
    Bao gồm kiểm tra server URLs, firewall mode, logging settings, v.v.
    
    Args:
        config: Dictionary cấu hình cần kiểm tra
        
    Returns:
        bool: True nếu cấu hình hợp lệ, False nếu có lỗi critical
    """
    logger.info("Validating configuration...")
    errors = []     # Lỗi critical - Agent sẽ không khởi động nếu có lỗi này
    warnings = []   # Agent vẫn chạy được nhưng có thể hoạt động không tối ưu
    
    try:
        # 1. Server configuration validation
        server_config = config.get("server", {})
        if not server_config.get("url") and not server_config.get("urls"):
            errors.append("Server URL is required (either 'url' or 'urls')")
        
        # Validate URLs format
        urls_to_check = server_config.get("urls", [])
        if server_config.get("url"):
            urls_to_check.append(server_config["url"])
        
        for url in urls_to_check:
            if not url.startswith(("http://", "https://")):
                warnings.append(f"URL should start with http:// or https://: {url}")
        
        # 2. Firewall mode validation
        firewall_config = config.get("firewall", {})
        valid_modes = ["block", "warn", "monitor", "whitelist_only"]
        current_mode = firewall_config.get("mode", "monitor")
        
        if current_mode not in valid_modes:
            errors.append(f"Invalid firewall mode: {current_mode}. Valid modes: {valid_modes}")
        
        # 3. Admin privileges check for firewall modes
        admin_required_modes = ["block", "whitelist_only"]
        if current_mode in admin_required_modes:
            if not check_admin_privileges():
                warnings.append(f"Mode '{current_mode}' requires admin privileges - will auto-switch to 'monitor'")
        
        # 4. Logging configuration validation
        logging_config = config.get("logging", {})
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        log_level = logging_config.get("level", "INFO")
        
        if log_level not in valid_levels:
            warnings.append(f"Invalid log level: {log_level}. Using INFO instead")
            config["logging"]["level"] = "INFO"
        
        # 5. Whitelist configuration validation
        whitelist_config = config.get("whitelist", {})
        if whitelist_config.get("update_interval", 0) < 30:
            warnings.append("Whitelist update interval too low (<30s) - may cause server overload")
        
        # 6. Heartbeat configuration validation
        heartbeat_config = config.get("heartbeat", {})
        if heartbeat_config.get("interval", 0) < 10:
            warnings.append("Heartbeat interval too low (<10s) - may cause server overload")
        
        # Log validation results
        if errors:
            logger.error("Configuration validation failed:")
            for error in errors:
                logger.error(f"   - {error}")
            return False
        
        if warnings:
            logger.warning("Configuration warnings:")
            for warning in warnings:
                logger.warning(f"   - {warning}")
        
        logger.info("Configuration validation passed")
        return True
        
    except Exception as e:
        logger.error(f"Error during configuration validation: {e}")
        return False

# ========================================
# IP DETECTION LOGIC - UTC ONLY
# ========================================

class IPDetector:
    """
    UPDATED: IP detection với UTC only
    """
    
    def __init__(self):
        self._cached_local_ip = None
        self._cached_admin_status = None
        self._last_ip_check = 0
        self._ip_cache_ttl = 300  # 5 minutes

    def get_local_ip(self, force_refresh: bool = False) -> str:
       
        current_time = now()  # UTC timestamp
        
        # Use cache validation from time_utils
        if (not force_refresh and 
            self._cached_local_ip and 
            is_cache_valid(self._last_ip_check, self._ip_cache_ttl)):
            
            age = cache_age(self._last_ip_check)
            logger.debug(f"IP cache hit: {self._cached_local_ip} (age: {age:.1f}s)")
            return self._cached_local_ip
        
        # Log cache miss reason
        if force_refresh:
            logger.debug("IP cache miss: force refresh requested")
        elif not self._cached_local_ip:
            logger.debug("IP cache miss: no cached value")
        else:
            age = cache_age(self._last_ip_check)
            logger.debug(f"IP cache miss: expired (age: {age:.1f}s > {self._ip_cache_ttl}s)")
        
        try:
            # Method 1: Connect to external server (most reliable)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                
                if local_ip and local_ip != "127.0.0.1":
                    self._cached_local_ip = local_ip
                    self._last_ip_check = current_time
                    logger.debug(f"Detected local IP (method 1): {local_ip} at {now_iso()}")
                    return local_ip
        except Exception as e:
            logger.debug(f"Method 1 failed: {e}")
        
        try:
            # Method 2: Hostname resolution
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            if local_ip and local_ip != "127.0.0.1":
                self._cached_local_ip = local_ip
                self._last_ip_check = current_time
                logger.debug(f"Detected local IP (method 2): {local_ip} at {now_iso()}")
                return local_ip
        except Exception as e:
            logger.debug(f"Method 2 failed: {e}")
        
        try:
            # Method 3: Network interfaces với netifaces
            for interface in netifaces.interfaces():
                addresses = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        ip = addr['addr']
                        # Skip loopback và link-local addresses
                        if not ip.startswith(('127.', '169.254.')):
                            self._cached_local_ip = ip
                            self._last_ip_check = current_time
                            logger.debug(f"Detected local IP (method 3): {ip} at {now_iso()}")
                            return ip
        except Exception as e:
            logger.debug(f"Method 3 failed: {e}")
        
        # Fallback
        logger.warning("Could not detect local IP, using localhost")
        self._cached_local_ip = "127.0.0.1"
        self._last_ip_check = current_time
        return "127.0.0.1"
    
    def get_cache_debug_info(self) -> Dict:
        """
        Get cache debug info using UTC time_utils
        """
        return {
            "cached_ip": self._cached_local_ip,
            "last_check_timestamp": self._last_ip_check,
            "last_check_iso": now_server_compatible(self._last_ip_check) if self._last_ip_check > 0 else "never",
            "cache_age": cache_age(self._last_ip_check) if self._last_ip_check > 0 else -1,
            "ttl": self._ip_cache_ttl,
            "cache_valid": is_cache_valid(self._last_ip_check, self._ip_cache_ttl)
        }
    
    def get_admin_status(self, force_refresh: bool = False) -> bool:
        """
        Admin status checking (unchanged logic)
        """
        if not force_refresh and self._cached_admin_status is not None:
            return self._cached_admin_status
        
        try:
            if platform.system() == "Windows":
                import ctypes
                admin_status = bool(ctypes.windll.shell32.IsUserAnAdmin())
            else:
                import os
                admin_status = os.geteuid() == 0
            
            self._cached_admin_status = admin_status
            logger.debug(f"Admin privileges: {admin_status}")
            return admin_status
            
        except Exception as e:
            logger.warning(f"Could not check admin privileges: {e}")
            self._cached_admin_status = False
            return False

# Global IP detector instance
ip_detector = IPDetector()

def check_admin_privileges() -> bool:
    """Helper function để maintain backward compatibility"""
    return ip_detector.get_admin_status()

def get_local_ip() -> str:
    """Helper function để maintain backward compatibility"""
    return ip_detector.get_local_ip()

# ========================================
# CRITICAL ERROR HANDLING
# ========================================

class CriticalErrorHandler:
    """
    Proper error handling in critical paths
    """
    
    @staticmethod
    def safe_execute(func, *args, error_msg="Operation failed", 
                    return_on_error=None, log_traceback=True, **kwargs):
        """
        Thực thi function một cách an toàn với error handling.
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if log_traceback:
                logger.error(f"{error_msg}: {e}", exc_info=True)
            else:
                logger.error(f"{error_msg}: {e}")
            return return_on_error
    
    @staticmethod
    def critical_operation(operation_name: str):
        """Decorator cho critical operations"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                logger.info(f"Starting critical operation: {operation_name}")
                try:
                    result = func(*args, **kwargs)
                    logger.info(f"Critical operation completed: {operation_name}")
                    return result
                except Exception as e:
                    logger.error(f"Critical operation failed: {operation_name} - {e}", exc_info=True)
                    raise
            return wrapper
        return decorator

# ========================================
# AGENT REGISTRATION - UTC ONLY
# ========================================

@CriticalErrorHandler.critical_operation("Agent Registration")
def register_agent() -> bool:
    """
    UPDATED: Registration với UTC timestamps
    """
    try:
        # Collect agent information
        local_ip = get_local_ip()
        admin_status = check_admin_privileges()
        
        agent_info = {
            "hostname": socket.gethostname(),
            "ip_address": local_ip,
            "platform": platform.system(),
            "os_info": f"{platform.system()} {platform.release()}",
            "agent_version": "1.0.0",
            "python_version": platform.python_version(),
            "admin_privileges": admin_status,
            "capabilities": {
                "packet_capture": True,
                "firewall_management": admin_status,
                "whitelist_sync": True
            },
            "registration_time": now_iso(),  # UTC ISO
            "registration_timestamp": now()  # UTC Unix timestamp
        }
        
        # Try registration với multiple servers
        server_urls = config['server'].get('urls', [config['server']['url']])
        
        for server_url in server_urls:
            if try_register_with_server(server_url, agent_info):
                return True
        
        logger.error("Failed to register with any server")
        return False
        
    except Exception as e:
        logger.error(f"Error in agent registration: {e}")
        return False

def try_register_with_server(server_url: str, agent_info: Dict) -> bool:
    """
    Thử đăng ký với một server cụ thể.
    """
    try:
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
                
                # Save credentials globally
                config['agent_id'] = agent_data.get('agent_id')
                config['agent_token'] = agent_data.get('token')
                config['user_id'] = agent_data.get('user_id')
                config['server_url'] = server_url
                
                # Update agent state
                agent_state['agent_id'] = config['agent_id']
                agent_state['registration_completed'] = True
                
                logger.info(f"Registration successful - Agent ID: {config['agent_id']}")
                return True
            else:
                logger.warning(f"Registration rejected: {data.get('error')}")
                return False
        else:
            logger.warning(f"Registration failed: HTTP {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        logger.warning(f"Connection failed to {server_url}")
        return False
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout connecting to {server_url}")
        return False
    except Exception as e:
        logger.error(f"Error registering with {server_url}: {e}")
        return False

# ========================================
# PACKET DETECTION HANDLER - UTC ONLY
# ========================================

def handle_domain_detection(record: Dict):
    """
    UPDATED: Handler với UTC timestamps only
    """
    try:
        # Extract packet information
        domain = record.get("domain")
        dest_ip = record.get("dest_ip")
        src_ip = record.get("src_ip", "unknown")
        protocol = record.get("protocol", "TCP")
        port = record.get("port", "unknown")
        
        # Use consolidated IP detection nếu src_ip không có
        if src_ip == "unknown" or not src_ip:
            src_ip = get_local_ip()
        
        # Enhanced protocol detection
        if port != "unknown":
            if str(port) == "443":
                protocol = "HTTPS"
            elif str(port) == "80":
                protocol = "HTTP"
            elif str(port) == "53":
                protocol = "DNS"
        
        # Whitelist checking với error handling
        domain_allowed = False
        ip_allowed = False
        
        if domain and whitelist:
            domain_allowed = CriticalErrorHandler.safe_execute(
                whitelist.is_allowed, 
                domain,
                error_msg=f"Error checking domain {domain}",
                return_on_error=False
            )
        
        if dest_ip and whitelist:
            ip_allowed = CriticalErrorHandler.safe_execute(
                whitelist.is_ip_allowed,
                dest_ip,
                error_msg=f"Error checking IP {dest_ip}",
                return_on_error=False
            )
        
        # Determine action based on firewall mode
        firewall_mode = config["firewall"]["mode"]
        firewall_enabled = config["firewall"]["enabled"]
        
        if firewall_enabled and firewall_mode == "whitelist_only":
            action = "ALLOWED" if (domain_allowed or ip_allowed) else "BLOCKED"
            level = "INFO" if action == "ALLOWED" else "WARNING"
        elif firewall_enabled and firewall_mode == "block":
            action = "BLOCKED" if not (domain_allowed or ip_allowed) else "ALLOWED"
            level = "WARNING" if action == "BLOCKED" else "INFO"
        else:
            action = "MONITORED"
            level = "INFO"
        
        #Create enhanced log record với UTC timestamps
        enhanced_record = {
            "timestamp": now_iso(),  # UTC ISO timestamp
            "timestamp_unix": now(),  # UTC Unix timestamp
            "agent_id": config.get("agent_id", "unknown"),
            "level": level,
            "action": action,
            "domain": domain or "unknown",
            "destination": domain or dest_ip or "unknown",
            "source_ip": src_ip,
            "dest_ip": dest_ip or "unknown",
            "protocol": protocol,
            "port": str(port),
            "firewall_mode": firewall_mode,
            "firewall_enabled": firewall_enabled,
            "admin_privileges": check_admin_privileges(),
            "domain_allowed": domain_allowed,
            "ip_allowed": ip_allowed,
            "source": "domain_detection",
            "agent_uptime": uptime_string()
        }
        
        # Queue log với error handling
        if log_sender:
            success = CriticalErrorHandler.safe_execute(
                log_sender.queue_log,
                enhanced_record,
                error_msg="Failed to queue detection log",
                return_on_error=False
            )
            
            if not success:
                logger.warning(f"Failed to queue log for {domain or dest_ip}")
        
        # Local logging
        log_message = f"{action}: {domain or dest_ip} -> {dest_ip} ({protocol}:{port})"
        if level == "WARNING":
            logger.warning(f"{log_message}")
        else:
            logger.info(f"{log_message}")
    
    except Exception as e:
        logger.error(f"Error in domain detection handler: {e}", exc_info=True)

# ========================================
# COMPONENT INITIALIZATION
# ========================================

@CriticalErrorHandler.critical_operation("Component Initialization")
def initialize_components():
    """
    ENHANCED: Khởi tạo tất cả components với proper error handling
    """
    global firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender, command_processor
    
    try:
        logger.info("Initializing agent components...")
        
        # Update agent state với local IP
        agent_state['local_ip'] = get_local_ip()
        agent_state['admin_privileges'] = check_admin_privileges()
        
        # 1. Register agent first (critical for other components)
        registration_success = register_agent()
        
        # 2. Initialize WhitelistManager
        logger.info("Initializing whitelist manager...")
        whitelist = WhitelistManager(config)
        logger.info("Whitelist manager initialized")
        
        # 3. Initialize FirewallManager (if enabled and has admin)
        if config["firewall"]["enabled"] and check_admin_privileges():
            logger.info(" Initializing firewall manager...")
            firewall = FirewallManager(config["firewall"]["rule_prefix"])
            
            # Link whitelist với firewall
            whitelist.set_firewall_manager(firewall)
            logger.info("Firewall manager initialized and linked")
        else:
            logger.info("Firewall disabled or no admin privileges")
        
        # 4. Initialize LogSender
        logger.info("Initializing log sender...")
        log_sender_config = {
            "server_url": config.get('server_url', config["server"]["url"]),
            "batch_size": config["logging"]["sender"]["batch_size"],
            "max_queue_size": config["logging"]["sender"]["max_queue_size"],
            "send_interval": config["logging"]["sender"]["send_interval"],
            "agent_id": config.get('agent_id'),
            "agent_token": config.get('agent_token')
        }
        log_sender = LogSender(log_sender_config)
        log_sender.start()
        logger.info("Log sender initialized")
        
        # 5. Initialize PacketSniffer
        logger.info("Initializing packet sniffer...")
        packet_sniffer = PacketSniffer(callback=handle_domain_detection)
        packet_sniffer.start()
        logger.info("Packet sniffer initialized")
        
        # 6. Initialize HeartbeatSender (if registered)
        if registration_success:
            logger.info("Initializing heartbeat sender...")
            heartbeat_sender = HeartbeatSender(config)
            heartbeat_sender.set_agent_credentials(config['agent_id'], config['agent_token'])
            heartbeat_sender.start()
            logger.info("Heartbeat sender initialized")
        
        # 7. Initialize CommandProcessor
        logger.info("Initializing command processor...")
        command_processor = CommandProcessor()
        
        # Start command polling if registered
        if registration_success:
            start_command_polling()
        
        logger.info("Command processor initialized")
        
        # Update agent state
        agent_state['components_initialized'] = True
        logger.info("All components initialized successfully")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        return False

# ========================================
# COMMAND POLLING
# ========================================

def start_command_polling():
    """Khởi động command polling thread"""
    def polling_loop():
        logger.info("Command polling started")
        
        while running:
            try:
                if not config.get('agent_id'):
                    sleep(30)
                    continue
                
                # Poll commands từ server
                server_url = config.get('server_url', config["server"]["url"])
                commands_url = f"{server_url.rstrip('/')}/api/agents/{config['agent_id']}/commands"
                
                response = requests.get(commands_url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    commands = data.get('commands', [])
                    
                    for command in commands:
                        process_command(command)
                
                sleep(30)  # Poll every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in command polling: {e}")
                sleep(60)
    
    polling_thread = threading.Thread(target=polling_loop, daemon=True)
    polling_thread.start()

def process_command(command: Dict):
    """Process command từ server"""
    try:
        command_id = command.get('command_id')
        logger.info(f"Processing command {command_id}: {command.get('command_type')}")
        
        result = command_processor.process_command(command)
        logger.info(f"Command {command_id} completed")
        
    except Exception as e:
        logger.error(f"Error processing command: {e}")

# ========================================
# CLEANUP - UTC ONLY
# ========================================

def cleanup():
    """
    UPDATED: Cleanup với firewall policy restore
    """
    global firewall, whitelist, log_sender, packet_sniffer, heartbeat_sender
    
    logger.info("Starting agent cleanup...")
    
    # Stop packet capture first
    if packet_sniffer:
        CriticalErrorHandler.safe_execute(
            packet_sniffer.stop,
            error_msg="Error stopping packet sniffer"
        )
        logger.info("Packet sniffer stopped")

    # Stop whitelist updates
    if whitelist:
        CriticalErrorHandler.safe_execute(
            whitelist.stop_periodic_updates,
            error_msg="Error stopping whitelist updates"
        )
        logger.info("Whitelist updates stopped")
    
    # Send final logs
    if log_sender and config.get('agent_id'):
        shutdown_log = {
            "agent_id": config['agent_id'],
            "event_type": "agent_shutdown",
            "timestamp": now_iso(),
            "timestamp_unix": now(),
            "uptime_seconds": uptime(),
            "uptime_string": uptime_string(),
            "uptime_info": agent_state
        }
        CriticalErrorHandler.safe_execute(
            log_sender.queue_log,
            shutdown_log,
            error_msg="Error sending shutdown log"
        )
        sleep(2)
        
        CriticalErrorHandler.safe_execute(
            log_sender.stop,
            error_msg="Error stopping log sender"
        )
        logger.info("Log sender stopped")
    
    # Stop heartbeat
    if heartbeat_sender:
        CriticalErrorHandler.safe_execute(
            heartbeat_sender.stop,
            error_msg="Error stopping heartbeat sender"
        )
        logger.info("Heartbeat sender stopped")
    
    #  FIX: Complete firewall cleanup with policy restore
    if firewall:
        cleanup_enabled = config and config["firewall"].get("cleanup_on_exit", True)
        
        if cleanup_enabled:
            logger.info(" Performing complete firewall cleanup...")
            
            #  Use complete cleanup method that restores policy
            success = CriticalErrorHandler.safe_execute(
                firewall.cleanup_whitelist_firewall,  # ← This restores policy
                error_msg="Error in complete firewall cleanup",
                return_on_error=False
            )
            
            if success:
                logger.info(" Firewall completely cleaned up and policy restored")
            else:
                logger.warning(" Some firewall cleanup operations failed")
                
                #  Fallback: try individual operations
                logger.info(" Attempting fallback cleanup...")
                
                # Clear rules
                CriticalErrorHandler.safe_execute(
                    firewall.clear_all_rules,
                    error_msg="Error clearing firewall rules"
                )
                
                # Restore policy
                success = CriticalErrorHandler.safe_execute(
                    firewall._restore_original_policy,
                    error_msg="Error restoring original firewall policy",
                    return_on_error=False
                )
                
                if not success:
                    # Final fallback: restore default policy
                    CriticalErrorHandler.safe_execute(
                        firewall._restore_default_policy,
                        error_msg="Error restoring default firewall policy"
                    )
                    logger.info(" Restored firewall to Windows defaults")
        else:
            logger.info(" Firewall cleanup disabled by configuration")
    
    # Update final state
    agent_state['startup_completed'] = False
    agent_state['components_initialized'] = False
    
    logger.info(f"Agent cleanup completed (total uptime: {uptime_string()})")

# ========================================
# SIGNAL HANDLERS
# ========================================

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    global running
    logger.info(f"Received signal {sig}, shutting down...")
    running = False

# ========================================
# MAIN FUNCTION - UTC ONLY
# ========================================

def main():
    """
    UPDATED: Main function với UTC timestamps only
    """
    global config, running
    
    try:
        logger.info("Starting Secure Firewall Controller Agent...")
        
        # Debug time info in debug mode
        if logger.isEnabledFor(logging.DEBUG):
            debug_info = debug_time_info()
            logger.debug(f"Time info: {debug_info}")
        
        # Load and validate configuration
        logger.info("Loading configuration...")
        config = get_config()
        
        if not validate_configuration(config):
            logger.error("Configuration validation failed")
            sys.exit(1)
        
        logger.info("Configuration loaded and validated")
        
        # Auto-adjust configuration based on privileges
        admin_status = check_admin_privileges()
        if config["firewall"]["enabled"] and not admin_status:
            if config["firewall"]["mode"] in ["block", "whitelist_only"]:
                logger.warning("No admin privileges - switching to monitor mode")
                config["firewall"]["enabled"] = False
                config["firewall"]["mode"] = "monitor"
        
        # Apply startup delay if configured
        startup_delay = config["general"]["startup_delay"]
        if startup_delay > 0:
            logger.info(f"Applying startup delay: {startup_delay} seconds...")
            sleep(startup_delay)
        
        # Initialize all components
        if not initialize_components():
            logger.error("Component initialization failed - cannot start agent")
            sys.exit(1)
        
        # Send startup notification
        if log_sender and config.get('agent_id'):
            startup_log = {
                "agent_id": config['agent_id'],
                "event_type": "agent_startup",
                "hostname": socket.gethostname(),
                "local_ip": get_local_ip(),
                "admin_privileges": check_admin_privileges(),
                "firewall_enabled": config["firewall"]["enabled"],
                "firewall_mode": config["firewall"]["mode"],
                "timestamp": now_iso(),  # UTC ISO
                "timestamp_unix": now(),  # UTC Unix timestamp
            }
            log_sender.queue_log(startup_log)
        
        # Mark startup as completed
        agent_state['startup_completed'] = True
        logger.info(f"🎉 Agent startup completed successfully (startup time: {uptime_string()})")
        
        # Main loop với UTC timestamps
        loop_count = 0
        last_status_log = now()  # UTC timestamp
        
        while running:
            sleep(1)
            loop_count += 1
            
            # Log status every 5 minutes
            if now() - last_status_log >= 300:
                logger.info(f"Agent running - Loop: {loop_count}, Uptime: {uptime_string()}")
                
                # Debug cache info in debug mode
                if logger.isEnabledFor(logging.DEBUG):
                    cache_info = ip_detector.get_cache_debug_info()
                    logger.debug(f"IP Cache: {cache_info}")
                
                last_status_log = now()
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Unhandled error in main: {e}", exc_info=True)
    finally:
        cleanup()

# ===============
# SERVICE RUNNER
# ===============

def run_as_service():
    """Enhanced Windows Service implementation"""
    try:
        import servicemanager # type: ignore
        import win32event # type: ignore
        import win32service # type: ignore
        import win32serviceutil # type: ignore
        
        class AgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "FirewallControllerAgent"
            _svc_display_name_ = "Firewall Controller Agent"
            _svc_description_ = "Network traffic monitoring and domain whitelist enforcement"
            
            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)
                self.running = True
            
            def SvcStop(self):
                """Stop the service"""
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.stop_event)
                self.running = False
                
                global running
                running = False
                
                # Cleanup components
                try:
                    cleanup()
                except Exception as e:
                    servicemanager.LogErrorMsg(f"Error during service cleanup: {e}")
            
            def SvcDoRun(self):
                """Main service execution"""
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                
                try:
                    main()
                except Exception as e:
                    servicemanager.LogErrorMsg(f"Service error: {e}")
                    self.SvcStop()
                
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STOPPED,
                    (self._svc_name_, '')
                )
        
        # Enhanced command line handling
        if len(sys.argv) == 1:
            # No arguments - run as service
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            # Handle service commands
            if sys.argv[1] == 'install':
                win32serviceutil.InstallService(
                    pythonClassString=f"{__name__}.AgentService",
                    serviceName=AgentService._svc_name_,
                    displayName=AgentService._svc_display_name_,
                    description=AgentService._svc_description_,
                    startType=win32service.SERVICE_AUTO_START
                )
                print(f"Service '{AgentService._svc_display_name_}' installed successfully")
                
            elif sys.argv[1] == 'remove':
                win32serviceutil.RemoveService(AgentService._svc_name_)
                print(f"Service '{AgentService._svc_display_name_}' removed successfully")
                
            elif sys.argv[1] == 'start':
                win32serviceutil.StartService(AgentService._svc_name_)
                print(f"Service '{AgentService._svc_display_name_}' started")
                
            elif sys.argv[1] == 'stop':
                win32serviceutil.StopService(AgentService._svc_name_)
                print(f"Service '{AgentService._svc_display_name_}' stopped")
                
            elif sys.argv[1] == 'restart':
                try:
                    win32serviceutil.StopService(AgentService._svc_name_)
                    sleep(2)
                    win32serviceutil.StartService(AgentService._svc_name_)
                    print(f"Service '{AgentService._svc_display_name_}' restarted")
                except Exception as e:
                    print(f"Error restarting service: {e}")
                    
            elif sys.argv[1] == 'status':
                try:
                    status = win32serviceutil.QueryServiceStatus(AgentService._svc_name_)
                    status_map = {
                        win32service.SERVICE_STOPPED: "STOPPED",
                        win32service.SERVICE_START_PENDING: "START_PENDING", 
                        win32service.SERVICE_STOP_PENDING: "STOP_PENDING",
                        win32service.SERVICE_RUNNING: "RUNNING",
                        win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
                        win32service.SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
                        win32service.SERVICE_PAUSED: "PAUSED"
                    }
                    print(f"Service Status: {status_map.get(status[1], 'UNKNOWN')}")
                except Exception as e:
                    print(f"Error checking service status: {e}")
            else:
                win32serviceutil.HandleCommandLine(AgentService)
            
    except ImportError as e:
        logger.error("Windows service modules not available. Install pywin32:")
        logger.error("   pip install pywin32")
        logger.error("   python Scripts/pywin32_postinstall.py -install")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Service error: {e}")
        sys.exit(1)

# ========================================
# ENTRY POINT
# ========================================

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check if running as service
    if len(sys.argv) > 1 and sys.argv[1] in ['--service', 'install', 'remove', 'start', 'stop']:
        run_as_service()
    else:
        main()