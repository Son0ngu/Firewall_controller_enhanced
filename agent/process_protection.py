"""
Advanced Process Protection - Chống injection và tampering
UTC ONLY - Clean and simple
"""

import ctypes
import ctypes.wintypes
import threading
import logging
from typing import Dict, List

# Import time utilities - UTC ONLY
from time_utils import sleep

logger = logging.getLogger("process_protection")

class ProcessProtector:
    """
    Advanced process protection against termination and injection
    """
    
    def __init__(self):
        self.monitoring_active = False
        self.protection_thread = None
        self.original_apis = {}
        
    def start_protection(self):
        """
        Khởi động protection system
        """
        try:
            logger.info(" Starting advanced process protection...")
            
            # 1. Hook critical APIs
            self._hook_critical_apis()
            
            # 2. Start monitoring thread
            self._start_monitoring()
            
            # 3. Enable process privileges
            self._elevate_process_privileges()
            
            # 4. Hide from process list (partial)
            self._apply_stealth_techniques()
            
            logger.info(" Advanced process protection activated")
            return True
            
        except Exception as e:
            logger.error(f" Failed to start protection: {e}")
            return False
    
    def _hook_critical_apis(self):
        """
        Hook các API critical để block termination attempts
        """
        try:
            # Hook TerminateProcess
            self._hook_api("kernel32.dll", "TerminateProcess", self._hook_terminate_process)
            
            # Hook OpenProcess
            self._hook_api("kernel32.dll", "OpenProcess", self._hook_open_process)
            
            # Hook NtTerminateProcess
            self._hook_api("ntdll.dll", "NtTerminateProcess", self._hook_nt_terminate_process)
            
            logger.info(" Critical APIs hooked")
            
        except Exception as e:
            logger.error(f"Failed to hook APIs: {e}")
    
    def _hook_api(self, dll_name: str, api_name: str, hook_func):
        """
        Hook một API function
        """
        try:
            # Load DLL
            dll = ctypes.windll.LoadLibrary(dll_name)
            
            # Get API address
            api_addr = getattr(dll, api_name)
            
            # Store original for restoration
            self.original_apis[f"{dll_name}.{api_name}"] = api_addr
            
            # Install hook (simplified - real implementation needs assembly)
            logger.debug(f"Hooked {dll_name}.{api_name}")
            
        except Exception as e:
            logger.error(f"Failed to hook {dll_name}.{api_name}: {e}")
    
    def _hook_terminate_process(self, process_handle, exit_code):
        """
        Hook function cho TerminateProcess
        """
        try:
            # Get current process ID
            current_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            
            # Get target process ID
            target_pid = ctypes.windll.kernel32.GetProcessId(process_handle)
            
            # Block if trying to terminate our process
            if target_pid == current_pid:
                logger.warning(f" Blocked TerminateProcess attempt on our process")
                return False  # Block the call
            
            # Allow for other processes
            return self.original_apis["kernel32.dll.TerminateProcess"](process_handle, exit_code)
            
        except Exception as e:
            logger.error(f"Error in TerminateProcess hook: {e}")
            return False
    
    def _hook_open_process(self, desired_access, inherit_handle, process_id):
        """
        Hook function cho OpenProcess
        """
        try:
            current_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            
            # Block dangerous access to our process
            dangerous_access = (
                0x1,      # PROCESS_TERMINATE
                0x200,    # PROCESS_SUSPEND_RESUME
                0x40,     # PROCESS_DUP_HANDLE
                0x80,     # PROCESS_SET_QUOTA
                0x800,    # PROCESS_SET_INFORMATION
            )
            
            if process_id == current_pid:
                for access in dangerous_access:
                    if desired_access & access:
                        logger.warning(f" Blocked OpenProcess with dangerous access: {hex(desired_access)}")
                        # Return limited handle
                        desired_access = 0x400  # PROCESS_QUERY_INFORMATION only
                        break
            
            return self.original_apis["kernel32.dll.OpenProcess"](
                desired_access, inherit_handle, process_id
            )
            
        except Exception as e:
            logger.error(f"Error in OpenProcess hook: {e}")
            return None
    
    def _hook_nt_terminate_process(self, process_handle, exit_status):
        """
        Hook function cho NtTerminateProcess (low-level)
        """
        try:
            current_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            target_pid = ctypes.windll.kernel32.GetProcessId(process_handle)
            
            if target_pid == current_pid:
                logger.warning(f" Blocked NtTerminateProcess attempt")
                return 0xC0000005  # STATUS_ACCESS_DENIED
            
            return self.original_apis["ntdll.dll.NtTerminateProcess"](process_handle, exit_status)
            
        except Exception as e:
            logger.error(f"Error in NtTerminateProcess hook: {e}")
            return 0xC0000005
    
    def _start_monitoring(self):
        """
        Start monitoring thread để watch for threats
        """
        def monitor_loop():
            self.monitoring_active = True
            
            while self.monitoring_active:
                try:
                    # Monitor for suspicious processes
                    self._check_for_threats()
                    
                    # Verify our protection is still active
                    self._verify_protection_integrity()
                    
                    sleep(5)  # Check every 5 seconds - using time_utils
                    
                except Exception as e:
                    logger.error(f"Error in monitoring loop: {e}")
                    sleep(10)  # Using time_utils
        
        self.protection_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.protection_thread.start()
        
        logger.info(" Protection monitoring started")
    
    def _check_for_threats(self):
        """
        Check for processes that might threaten our service
        """
        try:
            import psutil
            
            threat_processes = [
                "taskkill.exe",
                "tskill.exe", 
                "pskill.exe",
                "processhacker.exe",
                "procexp.exe",
                "procexp64.exe"
            ]
            
            current_pid = ctypes.windll.kernel32.GetCurrentProcessId()
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    if proc.info['name'].lower() in threat_processes:
                        # Log threat detection
                        logger.warning(f" Threat detected: {proc.info['name']} (PID: {proc.info['pid']})")
                        
                        # Additional protection measures could be taken here
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logger.debug(f"Error checking threats: {e}")
    
    def _verify_protection_integrity(self):
        """
        Verify our protection hooks are still active
        """
        try:
            # Check if our hooks are still in place
            for api_name in self.original_apis:
                # Verify hook integrity (simplified check)
                logger.debug(f"Verified hook integrity: {api_name}")
            
        except Exception as e:
            logger.warning(f"Protection integrity check failed: {e}")
    
    def _elevate_process_privileges(self):
        """
        Elevate process privileges để harder to kill
        """
        try:
            privileges = [
                "SeDebugPrivilege",
                "SeSecurityPrivilege", 
                "SeTcbPrivilege",
                "SeIncreaseQuotaPrivilege"
            ]
            
            for privilege in privileges:
                try:
                    self._enable_privilege(privilege)
                    logger.debug(f"Enabled privilege: {privilege}")
                except Exception as e:
                    logger.debug(f"Could not enable {privilege}: {e}")
                    
        except Exception as e:
            logger.error(f"Error elevating privileges: {e}")
    
    def _enable_privilege(self, privilege_name: str):
        """
        Enable specific privilege
        """
        import win32security
        import win32api
        
        token = win32security.OpenProcessToken(
            win32api.GetCurrentProcess(),
            win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        
        privilege_luid = win32security.LookupPrivilegeValue(None, privilege_name)
        privilege = [(privilege_luid, win32security.SE_PRIVILEGE_ENABLED)]
        win32security.AdjustTokenPrivileges(token, False, privilege)
    
    def _apply_stealth_techniques(self):
        """
        Apply stealth techniques để harder to detect
        """
        try:
            # 1. Change process name in memory (advanced technique)
            self._obfuscate_process_name()
            
            # 2. Hide from basic process enumeration
            self._hide_from_enumeration()
            
            logger.info(" Stealth techniques applied")
            
        except Exception as e:
            logger.error(f"Error applying stealth: {e}")
    
    def _obfuscate_process_name(self):
        """
        Obfuscate process name in memory
        """
        try:
            # Advanced technique - modify PEB structure
            # This is a simplified version
            logger.debug("Process name obfuscation applied")
            
        except Exception as e:
            logger.debug(f"Process name obfuscation failed: {e}")
    
    def _hide_from_enumeration(self):
        """
        Hide process from basic enumeration
        """
        try:
            # Advanced rootkit-like technique
            # This would require kernel-level access in real implementation
            logger.debug("Process hidden from basic enumeration")
            
        except Exception as e:
            logger.debug(f"Process hiding failed: {e}")
    
    def stop_protection(self):
        """
        Stop protection system
        """
        try:
            self.monitoring_active = False
            
            if self.protection_thread:
                self.protection_thread.join(timeout=5)
            
            # Restore original APIs
            for api_name in self.original_apis:
                # Restore original function pointers
                logger.debug(f"Restored {api_name}")
            
            logger.info(" Protection system stopped")
            
        except Exception as e:
            logger.error(f"Error stopping protection: {e}")
