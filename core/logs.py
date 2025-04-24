import subprocess
import os
import logging
import json
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Import utility functions
from core.utils import formatCommand, checkPrivileges

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('firewall_logs')

# Default Windows Firewall log file path
DEFAULT_LOG_PATH = r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

def get_log_file_path() -> str:
    """
    Get the actual path to the Windows Firewall log file.
    
    Returns:
        str: Path to the Windows Firewall log file
    """
    try:
        # Use PowerShell to get the log file path from the registry
        ps_command = """
        (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging").LogFilePath
        """
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode == 0 and result.stdout.strip():
            path = os.path.expandvars(result.stdout.strip())
            if os.path.exists(path):
                return path
                
        # If registry query fails, try the default path
        default_path = os.path.expandvars(DEFAULT_LOG_PATH)
        if os.path.exists(default_path):
            return default_path
            
        logger.warning("Could not find firewall log file. Using default path.")
        return DEFAULT_LOG_PATH
        
    except Exception as e:
        logger.error(f"Error getting log file path: {str(e)}")
        return DEFAULT_LOG_PATH


def parseLogFile(max_entries: int = 100) -> List[Dict[str, Any]]:
    """
    Parse the Windows Firewall log file and extract entries.
    
    Args:
        max_entries: Maximum number of entries to return
        
    Returns:
        List of dictionaries containing log entries
    """
    log_entries = []
    try:
        log_path = get_log_file_path()
        
        if not os.path.exists(os.path.expandvars(log_path)):
            logger.error(f"Firewall log file not found at {log_path}")
            return log_entries
            
        # Check if logging is enabled
        if not _is_logging_enabled():
            logger.warning("Firewall logging is not enabled")
            return log_entries
        
        # Open and parse the log file (reverse order to get most recent first)
        with open(os.path.expandvars(log_path), 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            
            # Skip header lines (typically first 5 lines)
            data_lines = [line for line in lines if not line.startswith('#')]
            
            # Process the most recent entries first (up to max_entries)
            for line in reversed(data_lines[:max_entries]):
                entry = _parse_log_line(line)
                if entry:
                    log_entries.append(entry)
                    
                if len(log_entries) >= max_entries:
                    break
                    
        return log_entries
        
    except Exception as e:
        logger.error(f"Error parsing log file: {str(e)}")
        return log_entries


def getRecentEvents(hours: int = 24, max_events: int = 100) -> List[Dict[str, Any]]:
    """
    Get recent firewall events from Windows Event Log.
    
    Args:
        hours: Number of hours to look back
        max_events: Maximum number of events to return
        
    Returns:
        List of dictionaries containing event information
    """
    events = []
    try:
        # PowerShell command to get recent Windows Firewall events in JSON format
        time_filter = f"(TimeCreated[timediff(@SystemTime) <= {hours * 3600000}])"
        
        ps_command = f"""
        Get-WinEvent -FilterXml @"
        <QueryList>
            <Query Id="0">
                <Select Path="Security">
                    *[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=5156 or EventID=5157)]] and 
                    {time_filter}
                </Select>
                <Select Path="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall">
                    *
                </Select>
            </Query>
        </QueryList>
        "@ -MaxEvents {max_events} | 
        Select-Object TimeCreated, Id, LevelDisplayName, 
        @{{Name='EventData'; Expression={{$_.Properties | ForEach-Object {{ $_.Value }}}}}} | 
        ConvertTo-Json -Depth 3
        """
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to get firewall events: {result.stderr}")
            return events
            
        # Parse JSON output
        if result.stdout.strip():
            data = json.loads(result.stdout)
            
            # Handle case when only one event is returned
            if isinstance(data, dict):
                data = [data]
                
            # Process and format events
            for event in data:
                processed_event = _process_event(event)
                if processed_event:
                    events.append(processed_event)
            
        return events
        
    except Exception as e:
        logger.error(f"Error getting recent firewall events: {str(e)}")
        return events


def _is_logging_enabled() -> bool:
    """
    Check if Windows Firewall logging is enabled.
    
    Returns:
        bool: True if logging is enabled, False otherwise
    """
    try:
        ps_command = """
        $logSettings = Get-NetFirewallProfile | Select-Object -ExpandProperty LogAllowed, LogBlocked, LogIgnored
        if (($logSettings -contains $true)) { Write-Output "Enabled" } else { Write-Output "Disabled" }
        """
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        return result.returncode == 0 and "Enabled" in result.stdout
        
    except Exception:
        return False


def _parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from the firewall log file.
    
    Args:
        line: Log line to parse
        
    Returns:
        Dictionary containing parsed log entry or None if parsing failed
    """
    try:
        # Windows Firewall log format is tab-delimited
        fields = line.strip().split(' ')
        
        # Standard fields in Windows Firewall log
        if len(fields) < 8:
            return None
            
        # Extract fields based on log format
        # Format: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
        entry = {
            'timestamp': f"{fields[0]} {fields[1]}",
            'action': fields[2],
            'protocol': fields[3],
            'source_ip': fields[4],
            'destination_ip': fields[5],
            'source_port': fields[6],
            'destination_port': fields[7]
        }
        
        # Add additional fields if available
        if len(fields) > 8:
            entry['size'] = fields[8]
        
        return entry
        
    except Exception:
        return None


def _process_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Process and format a Windows Event Log event.
    
    Args:
        event: Raw event data
        
    Returns:
        Dictionary containing formatted event data or None if processing failed
    """
    try:
        # Extract useful information from the event
        event_id = event.get('Id', 0)
        
        # Format time
        time_str = event.get('TimeCreated', '')
        if isinstance(time_str, str):
            time_obj = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
            formatted_time = time_obj.strftime('%Y-%m-%d %H:%M:%S')
        else:
            formatted_time = str(time_str)
        
        # Get event level
        level = event.get('LevelDisplayName', '')
        
        # Process event data based on event ID
        event_data = event.get('EventData', [])
        
        if event_id == 5156:  # Allowed connection
            return {
                'timestamp': formatted_time,
                'event_id': event_id,
                'type': 'Allowed Connection',
                'level': level,
                'protocol': _get_event_data_item(event_data, 7),
                'source_address': _get_event_data_item(event_data, 3),
                'source_port': _get_event_data_item(event_data, 4),
                'destination_address': _get_event_data_item(event_data, 5),
                'destination_port': _get_event_data_item(event_data, 6),
                'application': _get_event_data_item(event_data, 1)
            }
        elif event_id == 5157:  # Blocked connection
            return {
                'timestamp': formatted_time,
                'event_id': event_id,
                'type': 'Blocked Connection',
                'level': level,
                'protocol': _get_event_data_item(event_data, 7),
                'source_address': _get_event_data_item(event_data, 3),
                'source_port': _get_event_data_item(event_data, 4),
                'destination_address': _get_event_data_item(event_data, 5),
                'destination_port': _get_event_data_item(event_data, 6),
                'application': _get_event_data_item(event_data, 1)
            }
        else:
            return {
                'timestamp': formatted_time,
                'event_id': event_id,
                'type': 'Firewall Event',
                'level': level,
                'data': str(event_data)
            }
            
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        return None


def _get_event_data_item(data: List, index: int) -> str:
    """
    Safely get an item from event data list.
    
    Args:
        data: Event data list
        index: Index to retrieve
        
    Returns:
        String value at the specified index or empty string if not found
    """
    try:
        return str(data[index]) if index < len(data) else ""
    except (IndexError, TypeError):
        return ""


def enable_logging(enable: bool = True) -> bool:
    """
    Enable or disable Windows Firewall logging.
    
    Args:
        enable: True to enable logging, False to disable
        
    Returns:
        bool: True if successful, False otherwise
    """
    if not checkPrivileges():
        logger.error("Administrator privileges required to modify firewall logging settings")
        return False
    
    try:
        # Value to set for logging (True/False)
        value = "$true" if enable else "$false"
        
        # PowerShell command to enable/disable logging for all profiles
        ps_command = f"""
        $profiles = @("Domain", "Private", "Public")
        foreach ($profile in $profiles) {{
            Set-NetFirewallProfile -Profile $profile -LogAllowed {value} -LogBlocked {value}
        }}
        """
        
        cmd = formatCommand(["powershell", "-Command", ps_command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            status = "enable" if enable else "disable"
            logger.error(f"Failed to {status} firewall logging: {result.stderr}")
            return False
        
        status = "enabled" if enable else "disabled"
        logger.info(f"Successfully {status} firewall logging")
        return True
        
    except Exception as e:
        logger.error(f"Error modifying firewall logging settings: {str(e)}")
        return False