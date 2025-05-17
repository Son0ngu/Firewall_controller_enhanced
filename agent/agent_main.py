"""
Firewall Controller Agent - Main Module

This is the entry point for the agent application. It initializes and manages all components:
- Packet capturing and inspection
- Domain whitelist management
- Firewall control
- Log collection and sending

The agent can be run as a normal process or registered as a Windows service.
"""

import logging
import signal
import sys
import time
from typing import Dict

from agent.config import get_config
from agent.firewall_manager import FirewallManager
from agent.log_sender import LogSender
from agent.packet_sniffer import PacketSniffer
from agent.whitelist import WhitelistManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("agent_main")

# Global component variables
config = None
firewall = None
whitelist = None
log_sender = None
packet_sniffer = None
running = True

def handle_domain_detection(record: Dict):
    """
    Callback function for when a domain is detected in network traffic.
    Checks the domain against whitelist and takes appropriate action.
    
    Args:
        record: Dictionary with network connection details (domain, IP, etc.)
    """
    try:
        domain = record.get("domain")
        dest_ip = record.get("dest_ip")
        
        if not domain or not dest_ip:
            logger.warning("Incomplete connection record received")
            return
        
        # Check if domain is in whitelist
        allowed = whitelist.is_allowed(domain)
        
        # Add action to the record
        record["action"] = "allow" if allowed else "block"
        
        # Queue log for sending to server
        log_sender.queue_log(record)
        
        # Take action based on configuration and whitelist result
        if not allowed:
            if firewall and config["firewall"]["enabled"] and config["firewall"]["mode"] == "block":
                firewall.block_ip(dest_ip, domain)
                logger.info(f"Blocked connection to {domain} ({dest_ip})")
            else:
                # Just log warning if in monitor mode
                logger.warning(f"Detected connection to non-whitelisted domain: {domain} ({dest_ip})")
    
    except Exception as e:
        logger.error(f"Error in domain detection handler: {str(e)}", exc_info=True)

def initialize_components():
    """Initialize all agent components based on configuration."""
    global config, firewall, whitelist, log_sender, packet_sniffer
    
    try:
        logger.info("Initializing agent components...")
        
        # Initialize whitelist manager
        whitelist_config = {
            "server_url": config["server"]["url"],
            "api_key": config["auth"]["api_key"],
            "whitelist_source": config["whitelist"]["source"],
            "whitelist_file": config["whitelist"]["file"],
            "update_interval": config["whitelist"]["update_interval"]
        }
        whitelist = WhitelistManager(whitelist_config)
        whitelist.start_periodic_updates()
        logger.info(f"Whitelist initialized with {len(whitelist.domains)} domains")
        
        # Initialize firewall manager if enabled
        if config["firewall"]["enabled"]:
            firewall = FirewallManager(config["firewall"]["rule_prefix"])
            logger.info(f"Firewall manager initialized with {len(firewall.blocked_ips)} existing blocks")
        else:
            logger.info("Firewall functionality is disabled in configuration")
        
        # Initialize log sender
        log_sender_config = {
            "server_url": config["server"]["url"],
            "api_key": config["auth"]["api_key"],
            "batch_size": config["logging"]["sender"]["batch_size"],
            "max_queue_size": config["logging"]["sender"]["max_queue_size"],
            "retry_interval": config["server"]["retry_interval"],
            "max_retries": config["server"]["max_retries"]
        }
        log_sender = LogSender(log_sender_config)
        log_sender.start()
        logger.info("Log sender initialized and started")
        
        # Initialize packet sniffer
        packet_sniffer = PacketSniffer(callback=handle_domain_detection)
        packet_sniffer.start()
        logger.info("Packet sniffer initialized and started")
        
        logger.info("All agent components initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing components: {str(e)}", exc_info=True)
        raise

def cleanup():
    """Gracefully stop all components."""
    global firewall, whitelist, log_sender, packet_sniffer
    
    logger.info("Stopping agent components...")
    
    # Stop packet sniffer
    if packet_sniffer:
        try:
            packet_sniffer.stop()
            logger.info("Packet sniffer stopped")
        except Exception as e:
            logger.error(f"Error stopping packet sniffer: {str(e)}")
    
    # Stop whitelist updates
    if whitelist:
        try:
            whitelist.stop_periodic_updates()
            logger.info("Whitelist updater stopped")
        except Exception as e:
            logger.error(f"Error stopping whitelist updater: {str(e)}")
    
    # Stop log sender and flush logs
    if log_sender:
        try:
            log_sender.stop()
            logger.info("Log sender stopped")
        except Exception as e:
            logger.error(f"Error stopping log sender: {str(e)}")
    
    # Clean up firewall rules if configured to do so
    if firewall and config and config["firewall"]["cleanup_on_exit"]:
        try:
            logger.info("Clearing firewall rules...")
            firewall.clear_all_rules()
            logger.info("Firewall rules cleared")
        except Exception as e:
            logger.error(f"Error clearing firewall rules: {str(e)}")
    
    logger.info("Agent shutdown complete")

def signal_handler(sig, frame):
    """Handle termination signals."""
    global running
    logger.info(f"Signal {sig} received, stopping agent...")
    running = False

def main():
    """Main entry point for the agent."""
    global config, running
    
    try:
        # Load configuration
        config = get_config()
        
        # Apply startup delay if configured
        startup_delay = config["general"]["startup_delay"]
        if startup_delay > 0:
            logger.info(f"Applying startup delay of {startup_delay} seconds...")
            time.sleep(startup_delay)
        
        # Check for admin privileges if required
        if config["general"]["check_admin"] and config["firewall"]["enabled"]:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.error("Firewall operations require administrator privileges. Please run as administrator.")
                if config["firewall"]["enabled"]:
                    logger.warning("Continuing without firewall capabilities...")
                    config["firewall"]["enabled"] = False
        
        # Initialize all components
        initialize_components()
        
        # Send startup log
        if log_sender:
            import socket
            import platform
            startup_log = {
                "event_type": "agent_startup",
                "hostname": socket.gethostname(),
                "os": f"{platform.system()} {platform.version()}",
                "firewall_enabled": config["firewall"]["enabled"],
                "firewall_mode": config["firewall"]["mode"]
            }
            log_sender.queue_log(startup_log)
        
        logger.info("Agent initialization complete, entering main loop")
        
        # Main loop - just keep the process alive
        # The actual work is done in background threads
        while running:
            time.sleep(1)
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Unhandled error in agent main: {str(e)}", exc_info=True)
    finally:
        cleanup()

def run_as_service():
    """Run the agent as a Windows service."""
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
        
        class AgentService(win32serviceutil.ServiceFramework):
            _svc_name_ = "FirewallControllerAgent"
            _svc_display_name_ = "Firewall Controller Agent"
            _svc_description_ = "Monitors network traffic and enforces domain whitelist policy"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self.stop_event = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self.stop_event)
                global running
                running = False

            def SvcDoRun(self):
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, '')
                )
                
                main()  # Run the main agent function

        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(AgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            win32serviceutil.HandleCommandLine(AgentService)
            
    except ImportError:
        logger.error("Required Windows service modules not installed. Please install pywin32.")
        sys.exit(1)

if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Check if running as service
    if len(sys.argv) > 1 and sys.argv[1] in ['--service', 'install', 'remove', 'start', 'stop', 'update']:
        run_as_service()
    else:
        # Run as normal process
        main()