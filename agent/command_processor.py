"""
Command Processor - Handles commands from server

✅ UPDATED: Sử dụng time_utils cho consistent time management
"""

import logging
import platform
import subprocess
from typing import Dict, Any

# ✅ Import time_utils thay vì time và datetime
from time_utils import (
    now, now_iso, now_server_compatible, uptime_string, sleep
)

class CommandProcessor:
    """Process commands received from server"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self._creation_time = now()  # ✅ Use time_utils
        
        # Command handlers
        self.handlers = {
            "ping": self.handle_ping,
            "system_info": self.handle_system_info,
            "restart": self.handle_restart,
            "status": self.handle_status,              # ✅ NEW: Agent status
            "config_reload": self.handle_config_reload,  # ✅ NEW: Reload config
            # Add more command types as needed
        }
        
        # Simple command statistics
        self._total_commands = 0
        self._successful_commands = 0
    
    def process_command(self, command: Dict) -> Dict:
        """
        ✅ UPDATED: Process command với time_utils timestamps
        """
        command_start_time = now()  # ✅ Use time_utils
        
        try:
            command_type = command.get("command_type")
            command_id = command.get("command_id", "unknown")
            parameters = command.get("parameters", {})
            
            self.logger.info(f"📨 Processing command: {command_type} (ID: {command_id})")
            
            # Update statistics
            self._total_commands += 1
            
            if command_type not in self.handlers:
                return {
                    "success": False,
                    "error": f"Unknown command type: {command_type}",
                    "command_id": command_id,
                    "timestamp": now_iso(),  # ✅ Use time_utils
                    "execution_time": 0
                }
            
            # Execute command handler
            result = self.handlers[command_type](parameters)
            
            # Calculate execution time
            execution_time = now() - command_start_time  # ✅ Use time_utils
            
            # Build result
            result.update({
                "command_id": command_id,
                "command_type": command_type,
                "timestamp": now_iso(),  # ✅ Use time_utils
                "execution_time": round(execution_time, 3),
            })
            
            # Update success statistics
            if result.get("success", True):
                self._successful_commands += 1
            
            self.logger.info(f"✅ Command {command_type} completed in {execution_time:.3f}s")
            return result
            
        except Exception as e:
            execution_time = now() - command_start_time  # ✅ Use time_utils
            
            self.logger.error(f"💥 Error processing command {command.get('command_type')}: {e}")
            
            return {
                "success": False,
                "error": str(e),
                "command_id": command.get("command_id", "unknown"),
                "command_type": command.get("command_type", "unknown"),
                "timestamp": now_iso(),  # ✅ Use time_utils
                "execution_time": round(execution_time, 3)
            }
    
    def handle_ping(self, parameters: Dict) -> Dict:
        """
        ✅ UPDATED: Handle ping command với time_utils
        """
        try:
            # Build ping response
            response_data = {
                "success": True,
                "message": "Pong! Agent is responsive",
                "agent_info": {
                    "hostname": platform.node(),
                    "platform": platform.system(),
                    "python_version": platform.python_version(),
                    "uptime": uptime_string(),           # ✅ Use time_utils
                    "local_time": now_server_compatible(),        # ✅ Use time_utils
                    "processor_uptime": self._get_processor_uptime()
                },
                "parameters_received": parameters
            }
            
            self.logger.info("🏓 Ping command successful")
            return response_data
            
        except Exception as e:
            self.logger.error(f"❌ Ping command failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def handle_system_info(self, parameters: Dict) -> Dict:
        """
        ✅ UPDATED: Handle system info với time_utils
        """
        try:
            system_info = {
                "success": True,
                "collection_time": now_iso(),  # ✅ Use time_utils
                "system": {
                    "hostname": platform.node(),
                    "platform": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "architecture": platform.architecture(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version()
                },
                "agent": {
                    "uptime": uptime_string(),           # ✅ Use time_utils
                    "processor_uptime": self._get_processor_uptime(),
                    "commands_processed": self._total_commands,
                    "success_rate": self._get_success_rate()
                }
            }
            
            # ✅ Add resource info if psutil available
            try:
                import psutil
                system_info["resources"] = {
                    "cpu_percent": psutil.cpu_percent(interval=1),
                    "memory": {
                        "total": psutil.virtual_memory().total,
                        "available": psutil.virtual_memory().available,
                        "percent": psutil.virtual_memory().percent
                    },
                    "disk": self._get_disk_usage()
                }
            except ImportError:
                system_info["resources"] = {
                    "note": "psutil not available - limited resource info"
                }
            
            return system_info
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": now_iso()  # ✅ Use time_utils
            }
    
    def handle_restart(self, parameters: Dict) -> Dict:
        """
        ✅ UPDATED: Handle restart command với time_utils
        """
        try:
            delay = parameters.get("delay", 5)  # seconds
            reason = parameters.get("reason", "Remote restart command")
            
            self.logger.info(f"🔄 Restart command received: {reason}")
            self.logger.info(f"🔄 Agent will restart in {delay} seconds...")
            
            # Schedule restart
            import threading
            def delayed_restart():
                sleep(delay)  # ✅ Use time_utils sleep
                self.logger.info(f"🔄 Restarting agent now (uptime was: {uptime_string()})")
                
                import sys
                import os
                # Restart the current script
                os.execv(sys.executable, ['python'] + sys.argv)
            
            restart_thread = threading.Thread(target=delayed_restart)
            restart_thread.daemon = True
            restart_thread.start()
            
            return {
                "success": True,
                "message": f"Agent will restart in {delay} seconds",
                "restart_scheduled": now_iso(),  # ✅ Use time_utils
                "delay": delay,
                "reason": reason
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": now_iso()  # ✅ Use time_utils
            }
    
    def handle_status(self, parameters: Dict) -> Dict:
        """
        ✅ NEW: Handle status command - basic agent status
        """
        try:
            status_info = {
                "success": True,
                "status": "running",
                "timestamp": now_iso(),              # ✅ Use time_utils
                "uptime": uptime_string(),           # ✅ Use time_utils
                "processor_uptime": self._get_processor_uptime(),
                "commands": {
                    "total": self._total_commands,
                    "successful": self._successful_commands,
                    "success_rate": self._get_success_rate()
                },
                "system": {
                    "hostname": platform.node(),
                    "platform": platform.system()
                }
            }
            
            # ✅ Add basic resource info if available
            try:
                import psutil
                status_info["resources"] = {
                    "cpu_percent": psutil.cpu_percent(),
                    "memory_percent": psutil.virtual_memory().percent
                }
            except ImportError:
                pass
            
            return status_info
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": now_iso()
            }
    
    def handle_config_reload(self, parameters: Dict) -> Dict:
        """
        ✅ NEW: Handle config reload command
        """
        try:
            self.logger.info("🔄 Config reload requested")
            
            # Note: Actual config reload would be handled by main agent
            # This command just signals the request and provides confirmation
            
            return {
                "success": True,
                "message": "Config reload request received",
                "timestamp": now_iso(),  # ✅ Use time_utils
                "note": "Actual reload handled by main agent process"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "timestamp": now_iso()
            }
    
    # ========================================
    # HELPER METHODS
    # ========================================
    
    def _get_processor_uptime(self) -> str:
        """Get command processor uptime"""
        processor_uptime_seconds = now() - self._creation_time  # ✅ Use time_utils
        return self._format_duration(processor_uptime_seconds)
    
    def _get_success_rate(self) -> float:
        """Get command success rate percentage"""
        if self._total_commands == 0:
            return 100.0
        return round((self._successful_commands / self._total_commands) * 100, 1)
    
    def _get_disk_usage(self) -> Dict:
        """Get cross-platform disk usage"""
        try:
            import psutil
            
            if platform.system() == "Windows":
                disk_path = 'C:\\'
            else:
                disk_path = '/'
            
            disk_usage = psutil.disk_usage(disk_path)
            
            return {
                "path": disk_path,
                "total": disk_usage.total,
                "free": disk_usage.free,
                "used": disk_usage.used,
                "percent": round((disk_usage.used / disk_usage.total) * 100, 1)
            }
        except Exception as e:
            return {
                "error": str(e),
                "path": "unknown"
            }
    
    def _format_duration(self, duration_seconds: float) -> str:
        """Format duration in human-readable format"""
        hours = int(duration_seconds // 3600)
        minutes = int((duration_seconds % 3600) // 60)
        seconds = int(duration_seconds % 60)
        
        if hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    
    def get_available_commands(self) -> list:
        """Get list of available commands"""
        return list(self.handlers.keys())
    
    def get_processor_stats(self) -> Dict:
        """
        ✅ NEW: Get basic processor statistics
        """
        return {
            "creation_time": now_server_compatible(self._creation_time),  # ✅ Use time_utils
            "uptime": self._get_processor_uptime(),
            "total_commands": self._total_commands,
            "successful_commands": self._successful_commands,
            "success_rate": self._get_success_rate(),
            "available_commands": self.get_available_commands(),
            "current_time": now_server_compatible()  # ✅ Use time_utils
        }