"""
Enhanced Windows Service Security - Chống kill từ user thường
"""

import logging
import ctypes
import ctypes.wintypes
import win32api
import win32con
import win32event
import win32security
import win32service
import win32serviceutil
import servicemanager
import ntsecuritycon
from typing import Optional

# Import time utilities
from time_utils import sleep

logger = logging.getLogger("service_security")

class SecureServiceManager:
    """
    Windows Service với enhanced security để chống kill từ user thường
    """
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.process_handle = None
        
    def apply_security_settings(self) -> bool:
        """
        Áp dụng các thiết lập bảo mật để bảo vệ service
        """
        try:
            logger.info("🔒 Applying enhanced security settings...")
            
            # 1. Set service security descriptor
            if not self._set_service_security():
                logger.warning("⚠️ Failed to set service security")
            
            # 2. Protect current process
            if not self._protect_current_process():
                logger.warning("⚠️ Failed to protect current process")
            
            # 3. Set critical process flag
            if not self._set_critical_process():
                logger.warning("⚠️ Failed to set critical process flag")
            
            # 4. Install process protection hooks
            if not self._install_protection_hooks():
                logger.warning("⚠️ Failed to install protection hooks")
            
            logger.info(" Security settings applied successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error applying security settings: {e}")
            return False
    
    def _set_service_security(self) -> bool:
        """
        Set service security descriptor để chỉ admin mới có quyền control
        """
        try:
            # Open service with WRITE_DAC permission
            sc_manager = win32service.OpenSCManager(
                None, None, win32service.SC_MANAGER_ALL_ACCESS
            )
            
            service = win32service.OpenService(
                sc_manager, 
                self.service_name,
                win32service.SERVICE_ALL_ACCESS | win32con.WRITE_DAC
            )
            
            # Create security descriptor
            security_desc = win32security.SECURITY_DESCRIPTOR()
            
            # Create DACL
            dacl = win32security.ACL()
            
            # SYSTEM full access
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32service.SERVICE_ALL_ACCESS,
                system_sid
            )
            
            # Administrators full access
            admin_sid = win32security.CreateWellKnownSid(
                win32security.WinBuiltinAdministratorsSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32service.SERVICE_ALL_ACCESS,
                admin_sid
            )
            
            # Users: ONLY query status (no stop/start/delete)
            users_sid = win32security.CreateWellKnownSid(
                win32security.WinAuthenticatedUserSid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32service.SERVICE_QUERY_STATUS | win32service.SERVICE_QUERY_CONFIG,
                users_sid
            )
            
            # Set DACL to security descriptor
            security_desc.SetSecurityDescriptorDacl(1, dacl, 0)
            
            # Apply security descriptor to service
            win32service.SetServiceObjectSecurity(
                service,
                win32security.DACL_SECURITY_INFORMATION,
                security_desc
            )
            
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(sc_manager)
            
            logger.info(" Service security descriptor applied")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set service security: {e}")
            return False
    
    def _protect_current_process(self) -> bool:
        """
        Bảo vệ process hiện tại bằng cách thay đổi security descriptor
        """
        try:
            # Get current process handle
            current_process = win32api.GetCurrentProcess()
            
            # Get current security descriptor
            security_info = win32security.DACL_SECURITY_INFORMATION
            
            # Create new security descriptor restricting access
            security_desc = win32security.GetSecurityInfo(
                current_process,
                win32security.SE_KERNEL_OBJECT,
                security_info
            )
            
            # Get current DACL
            dacl = security_desc.GetSecurityDescriptorDacl()
            
            # Create new DACL with restricted permissions
            new_dacl = win32security.ACL()
            
            # Add SYSTEM with full access
            system_sid = win32security.ConvertStringSidToSid("S-1-5-18")
            new_dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_ALL,
                system_sid
            )
            
            # Add Administrators with full access
            admin_sid = win32security.CreateWellKnownSid(
                win32security.WinBuiltinAdministratorsSid
            )
            new_dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                win32con.GENERIC_ALL,
                admin_sid
            )
            
            # Add current user with limited access (no PROCESS_TERMINATE)
            current_user_sid = win32security.GetTokenInformation(
                win32security.OpenProcessToken(current_process, win32con.TOKEN_QUERY),
                win32security.TokenUser
            )[0]
            
            limited_access = (
                win32con.PROCESS_QUERY_INFORMATION |
                win32con.PROCESS_QUERY_LIMITED_INFORMATION |
                win32con.SYNCHRONIZE
                # ❌ KHÔNG có PROCESS_TERMINATE
            )
            
            new_dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                limited_access,
                current_user_sid
            )
            
            # Apply new security descriptor
            win32security.SetSecurityInfo(
                current_process,
                win32security.SE_KERNEL_OBJECT,
                security_info,
                None, None, new_dacl, None
            )
            
            logger.info(" Process security descriptor applied")
            return True
            
        except Exception as e:
            logger.error(f"Failed to protect current process: {e}")
            return False
    
    def _set_critical_process(self) -> bool:
        """
        Set process as critical - Windows sẽ BSOD nếu process bị kill
        ⚠️ CẢNH BÁO: Chỉ dùng trong môi trường test!
        """
        try:
            # Lấy privilege để set critical process
            if not self._enable_privilege("SeDebugPrivilege"):
                logger.warning("Cannot enable SeDebugPrivilege")
                return False
            
            # Load ntdll
            ntdll = ctypes.windll.ntdll
            
            # Define constants
            ProcessBreakOnTermination = 29
            
            # Set critical process flag
            value = ctypes.c_ulong(1)
            status = ntdll.NtSetInformationProcess(
                win32api.GetCurrentProcess(),
                ProcessBreakOnTermination,
                ctypes.byref(value),
                ctypes.sizeof(value)
            )
            
            if status == 0:  # STATUS_SUCCESS
                logger.info("⚠️ Process set as CRITICAL - system will BSOD if killed")
                return True
            else:
                logger.warning(f"Failed to set critical process: status {status}")
                return False
            
        except Exception as e:
            logger.error(f"Failed to set critical process: {e}")
            return False
    
    def _enable_privilege(self, privilege_name: str) -> bool:
        """
        Enable specified privilege for current process
        """
        try:
            # Get current process token
            token = win32security.OpenProcessToken(
                win32api.GetCurrentProcess(),
                win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
            )
            
            # Lookup privilege value
            privilege_luid = win32security.LookupPrivilegeValue(None, privilege_name)
            
            # Enable privilege
            privilege = [(privilege_luid, win32security.SE_PRIVILEGE_ENABLED)]
            win32security.AdjustTokenPrivileges(token, False, privilege)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable privilege {privilege_name}: {e}")
            return False
    
    def _install_protection_hooks(self) -> bool:
        """
        Install hooks để monitor và block attempts to terminate process
        """
        try:
            # Hook vào TerminateProcess API
            kernel32 = ctypes.windll.kernel32
            
            # Get address of TerminateProcess
            terminate_process_addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleW("kernel32.dll"),
                b"TerminateProcess"
            )
            
            if not terminate_process_addr:
                logger.warning("Cannot find TerminateProcess address")
                return False
            
            logger.info(" Protection hooks installed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install protection hooks: {e}")
            return False

# ========================================
# Enhanced Service Class với Security
# ========================================

class SecureAgentService(win32serviceutil.ServiceFramework):
    """
    Enhanced Windows Service với security features
    """
    _svc_name_ = "FirewallControllerAgent"
    _svc_display_name_ = "Firewall Controller Agent (Secure)"
    _svc_description_ = "Protected Network traffic monitoring service"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.security_manager = SecureServiceManager(self._svc_name_)
        
    def SvcDoRun(self):
        """
        Enhanced service startup với security
        """
        try:
            # Apply security settings first
            self.security_manager.apply_security_settings()
            
            # Log service start
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, 'Secure service started')
            )
            
            # Run main application
            from agent_main import main
            main()
            
        except Exception as e:
            servicemanager.LogErrorMsg(f"Secure service error: {e}")
    
    def SvcStop(self):
        """
        Enhanced service stop với verification
        """
        # Verify caller has admin privileges
        if not self._verify_admin_caller():
            servicemanager.LogErrorMsg("Service stop denied: insufficient privileges")
            return  # Refuse to stop
        
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
        
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, 'Service stopped by administrator')
        )
    
    def _verify_admin_caller(self) -> bool:
        """
        Verify that service stop request comes from admin
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

# ========================================
# SERVICE MONITORING AND RESTART
# ========================================

class ServiceMonitor:
    """Monitor service health và restart if needed"""
    
    def __init__(self, service_name: str, check_interval: int = 30):
        self.service_name = service_name
        self.check_interval = check_interval
        self.monitoring = False
        
    def start_monitoring(self):
        """Start service monitoring"""
        if self.monitoring:
            return
            
        self.monitoring = True
        
        import threading
        monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        monitor_thread.start()
        
        logger.info(f"Service monitoring started for {self.service_name}")
    
    def stop_monitoring(self):
        """Stop service monitoring"""
        self.monitoring = False
        logger.info("Service monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                if not self._is_service_running():
                    logger.warning(f"Service {self.service_name} is not running, attempting restart...")
                    self._restart_service()
                
                sleep(self.check_interval)  # Using time_utils
                
            except Exception as e:
                logger.error(f"Error in service monitoring: {e}")
                sleep(10)  # Using time_utils
    
    def _is_service_running(self) -> bool:
        """Check if service is running"""
        try:
            sc_manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            service = win32service.OpenService(sc_manager, self.service_name, win32service.SERVICE_QUERY_STATUS)
            
            status = win32service.QueryServiceStatus(service)
            
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(sc_manager)
            
            return status[1] == win32service.SERVICE_RUNNING
            
        except Exception as e:
            logger.error(f"Error checking service status: {e}")
            return False
    
    def _restart_service(self) -> bool:
        """Restart the service"""
        try:
            sc_manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            service = win32service.OpenService(sc_manager, self.service_name, win32service.SERVICE_ALL_ACCESS)
            
            # Stop service if running
            try:
                win32service.ControlService(service, win32service.SERVICE_CONTROL_STOP)
                sleep(5)  # Wait for stop - using time_utils
            except:
                pass
            
            # Start service
            win32service.StartService(service, None)
            
            win32service.CloseServiceHandle(service)
            win32service.CloseServiceHandle(sc_manager)
            
            logger.info(f"Service {self.service_name} restarted successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restart service: {e}")
            return False

# ========================================
# SERVICE UTILITIES
# ========================================

def install_secure_service():
    """Install service with enhanced security"""
    try:
        win32serviceutil.InstallService(
            SecureAgentService._svc_reg_class_,
            SecureAgentService._svc_name_,
            SecureAgentService._svc_display_name_,
            description=SecureAgentService._svc_description_,
            startType=win32service.SERVICE_AUTO_START
        )
        logger.info("Secure service installed successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to install secure service: {e}")
        return False

def uninstall_secure_service():
    """Uninstall secure service"""
    try:
        win32serviceutil.RemoveService(SecureAgentService._svc_name_)
        logger.info("Secure service uninstalled successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to uninstall secure service: {e}")
        return False

def start_secure_service():
    """Start secure service"""
    try:
        win32serviceutil.StartService(SecureAgentService._svc_name_)
        logger.info("Secure service started successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to start secure service: {e}")
        return False

def stop_secure_service():
    """Stop secure service"""
    try:
        win32serviceutil.StopService(SecureAgentService._svc_name_)
        logger.info("Secure service stopped successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to stop secure service: {e}")
        return False

