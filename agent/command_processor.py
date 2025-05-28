# Add this file if it doesn't exist

"""
Command Processor - Handles commands from server
"""

import logging
import time
import platform
import subprocess
from typing import Dict, Any
from datetime import datetime

class CommandProcessor:
    """Process commands received from server"""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Command handlers
        self.handlers = {
            "ping": self.handle_ping,
            "system_info": self.handle_system_info,
            "restart": self.handle_restart,
            # Add more command types as needed
        }
    
    def process_command(self, command: Dict) -> Dict:
        """Process a command and return result"""
        try:
            command_type = command.get("command_type")
            parameters = command.get("parameters", {})
            
            self.logger.info(f"Processing command: {command_type}")
            
            if command_type not in self.handlers:
                return {
                    "success": False,
                    "error": f"Unknown command type: {command_type}",
                    "execution_time": 0
                }
            
            start_time = time.time()
            
            # Execute command handler
            result = self.handlers[command_type](parameters)
            
            execution_time = time.time() - start_time
            result["execution_time"] = round(execution_time, 3)
            
            self.logger.info(f"Command {command_type} completed in {execution_time:.3f}s")
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing command {command.get('command_type')}: {e}")
            return {
                "success": False,
                "error": str(e),
                "execution_time": time.time() - start_time if 'start_time' in locals() else 0
            }
    
    def handle_ping(self, parameters: Dict) -> Dict:
        """Handle ping command"""
        try:
            timeout = parameters.get("timeout", 30)
            
            # Simple ping response
            response_data = {
                "success": True,
                "message": "Pong! Agent is responsive",
                "agent_info": {
                    "hostname": platform.node(),
                    "platform": platform.system(),
                    "python_version": platform.python_version(),
                    "uptime": self._get_uptime(),
                    "local_time": datetime.now().isoformat()
                },
                "parameters_received": parameters
            }
            
            self.logger.info("✅ Ping command successful")
            return response_data
            
        except Exception as e:
            self.logger.error(f"Ping command failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def handle_system_info(self, parameters: Dict) -> Dict:
        """Handle system info command"""
        try:
            import psutil
            
            system_info = {
                "success": True,
                "system": {
                    "hostname": platform.node(),
                    "platform": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "architecture": platform.architecture(),
                    "processor": platform.processor(),
                    "python_version": platform.python_version()
                },
                "resources": {
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
                    } if platform.system() != "Windows" else {
                        "total": psutil.disk_usage('C:').total,
                        "free": psutil.disk_usage('C:').free,
                        "percent": psutil.disk_usage('C:').percent
                    }
                }
            }
            
            return system_info
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def handle_restart(self, parameters: Dict) -> Dict:
        """Handle restart command"""
        try:
            delay = parameters.get("delay", 5)  # seconds
            
            self.logger.info(f"Restart command received, restarting in {delay} seconds...")
            
            # Schedule restart
            import threading
            def delayed_restart():
                time.sleep(delay)
                import sys
                import os
                # Restart the current script
                os.execv(sys.executable, ['python'] + sys.argv)
            
            restart_thread = threading.Thread(target=delayed_restart)
            restart_thread.daemon = True
            restart_thread.start()
            
            return {
                "success": True,
                "message": f"Agent will restart in {delay} seconds"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_uptime(self) -> float:
        """Get system uptime in seconds"""
        try:
            if platform.system() == "Windows":
                import subprocess
                result = subprocess.run(['wmic', 'os', 'get', 'lastbootuptime'], 
                                      capture_output=True, text=True)
                # Parse Windows uptime (simplified)
                return 0  # Placeholder
            else:
                with open('/proc/uptime', 'r') as f:
                    return float(f.readline().split()[0])
        except:
            return 0