import subprocess
import json
import os
import logging
import sys
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import uuid

# Import firewall rule functions
from core.firewall_rules import enable_rule
from core.utils import formatCommand, checkPrivileges

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('scheduler')

# In-memory storage for scheduled tasks
_scheduled_tasks = {}
# Flag to control the background thread
_running = False
# Background thread reference
_scheduler_thread = None
# Path to save scheduled tasks
TASKS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'scheduled_tasks.json')

class ScheduledTask:
    """Represents a scheduled task for firewall rule activation/deactivation."""
    
    def __init__(self, rule_name: str, action: str, schedule_time: datetime, task_id: Optional[str] = None,
                 repeat: Optional[str] = None, windows_task: bool = False, description: str = ""):
        self.rule_name = rule_name  # Name of the firewall rule
        self.action = action  # 'enable' or 'disable'
        self.schedule_time = schedule_time  # When to execute
        self.task_id = task_id or str(uuid.uuid4())  # Unique ID for the task
        self.repeat = repeat  # Optional repeat pattern: 'daily', 'weekly', etc.
        self.windows_task = windows_task  # Whether registered in Windows Task Scheduler
        self.description = description  # Optional description
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for serialization."""
        return {
            'rule_name': self.rule_name,
            'action': self.action,
            'schedule_time': self.schedule_time.isoformat(),
            'task_id': self.task_id,
            'repeat': self.repeat,
            'windows_task': self.windows_task,
            'description': self.description
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScheduledTask':
        """Create task from dictionary."""
        return cls(
            rule_name=data['rule_name'],
            action=data['action'],
            schedule_time=datetime.fromisoformat(data['schedule_time']),
            task_id=data['task_id'],
            repeat=data.get('repeat'),
            windows_task=data.get('windows_task', False),
            description=data.get('description', '')
        )


def _ensure_data_dir() -> None:
    """Ensure the data directory exists."""
    data_dir = os.path.dirname(TASKS_FILE)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)


def load_scheduled_tasks() -> None:
    """Load scheduled tasks from file."""
    global _scheduled_tasks
    try:
        _ensure_data_dir()
        if not os.path.exists(TASKS_FILE):
            _scheduled_tasks = {}
            return
            
        with open(TASKS_FILE, 'r') as f:
            data = json.load(f)
            
        loaded_tasks = {}
        for task_id, task_data in data.items():
            try:
                task = ScheduledTask.from_dict(task_data)
                loaded_tasks[task_id] = task
            except Exception as e:
                logger.error(f"Failed to load task {task_id}: {str(e)}")
                
        _scheduled_tasks = loaded_tasks
        logger.info(f"Loaded {len(_scheduled_tasks)} scheduled tasks")
    except Exception as e:
        logger.error(f"Error loading scheduled tasks: {str(e)}")
        _scheduled_tasks = {}


def save_scheduled_tasks() -> None:
    """Save scheduled tasks to file."""
    try:
        _ensure_data_dir()
        data = {task_id: task.to_dict() for task_id, task in _scheduled_tasks.items()}
        
        with open(TASKS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
            
        logger.info(f"Saved {len(_scheduled_tasks)} scheduled tasks")
    except Exception as e:
        logger.error(f"Error saving scheduled tasks: {str(e)}")


def scheduleRule(rule: Dict[str, Any], schedule_time: datetime, action: str = 'enable',
                repeat: Optional[str] = None, description: str = "") -> Optional[str]:
    """
    Schedule a firewall rule to be enabled or disabled at a specific time.
    
    Args:
        rule: Dictionary containing rule information (must include 'name')
        schedule_time: When to enable/disable the rule
        action: 'enable' or 'disable'
        repeat: Optional repeat pattern (daily, weekly, etc.)
        description: Optional description
        
    Returns:
        Task ID if successful, None otherwise
    """
    if action not in ('enable', 'disable'):
        logger.error(f"Invalid action: {action}. Must be 'enable' or 'disable'")
        return None
    
    rule_name = rule.get('name', '')
    if not rule_name:
        logger.error("Rule must have a name")
        return None
        
    try:
        # Create a new scheduled task
        task = ScheduledTask(
            rule_name=rule_name,
            action=action,
            schedule_time=schedule_time,
            repeat=repeat,
            description=description
        )
        
        # Store the task
        _scheduled_tasks[task.task_id] = task
        
        # Save tasks to file
        save_scheduled_tasks()
        
        # Ensure scheduler thread is running
        ensure_scheduler_running()
        
        logger.info(f"Rule '{rule_name}' scheduled for {action} at {schedule_time}")
        return task.task_id
        
    except Exception as e:
        logger.error(f"Error scheduling rule: {str(e)}")
        return None


def registerTask(rule: Dict[str, Any], schedule_time: datetime, action: str = 'enable',
                repeat: Optional[str] = None, description: str = "") -> Optional[str]:
    """
    Register a task with Windows Task Scheduler for persistence.
    
    Args:
        rule: Dictionary containing rule information (must include 'name')
        schedule_time: When to enable/disable the rule
        action: 'enable' or 'disable'
        repeat: Optional repeat pattern (daily, weekly, etc.)
        description: Optional description
        
    Returns:
        Task ID if successful, None otherwise
    """
    if not checkPrivileges():
        logger.error("Administrator privileges required to register Windows tasks")
        return None
        
    if action not in ('enable', 'disable'):
        logger.error(f"Invalid action: {action}. Must be 'enable' or 'disable'")
        return None
    
    rule_name = rule.get('name', '')
    if not rule_name:
        logger.error("Rule must have a name")
        return None
        
    try:
        # Create a unique task ID
        task_id = str(uuid.uuid4())
        task_name = f"FirewallController_{action}_{rule_name}_{task_id[:8]}"
        
        # Format schedule time for schtasks
        time_str = schedule_time.strftime("%H:%M")
        date_str = schedule_time.strftime("%m/%d/%Y")
        
        # Prepare repeat schedule
        schedule_type = "/SC ONCE"  # Default to one-time
        if repeat == "daily":
            schedule_type = "/SC DAILY"
        elif repeat == "weekly":
            schedule_type = "/SC WEEKLY"
        
        # Create a Python script that will be executed by the task
        script_content = f"""
import sys
import os

# Add parent directory to path so we can import our modules
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(parent_dir)

from core.firewall_rules import enable_rule

# Enable or disable the firewall rule
enable_rule('{rule_name}', {action == 'enable'})
"""
        
        # Write the script to a file in the data directory
        _ensure_data_dir()
        data_dir = os.path.dirname(TASKS_FILE)
        script_path = os.path.join(data_dir, f"task_{task_id}.py")
        
        with open(script_path, 'w') as f:
            f.write(script_content)
        
        # Get Python executable path
        python_exe = sys.executable if 'sys' in globals() else 'python'
        
        # Create the Windows Scheduled Task
        command = f'schtasks /Create /TN "{task_name}" {schedule_type} /SD {date_str} /ST {time_str} ' \
                  f'/TR "{python_exe} \"{script_path}\"" /RU SYSTEM /F'
                  
        cmd = formatCommand(["cmd", "/c", command])
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to register Windows task: {result.stderr}")
            # Clean up script file
            if os.path.exists(script_path):
                os.remove(script_path)
            return None
            
        # Create a task object and store it
        task = ScheduledTask(
            rule_name=rule_name,
            action=action,
            schedule_time=schedule_time,
            task_id=task_id,
            repeat=repeat,
            windows_task=True,
            description=description
        )
        
        # Store the task
        _scheduled_tasks[task_id] = task
        
        # Save tasks to file
        save_scheduled_tasks()
        
        logger.info(f"Windows task registered for rule '{rule_name}' ({action}) at {schedule_time}")
        return task_id
        
    except Exception as e:
        logger.error(f"Error registering Windows task: {str(e)}")
        return None


def cancelSchedule(task_id: str) -> bool:
    """
    Cancel a scheduled task.
    
    Args:
        task_id: ID of the task to cancel
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if task_id not in _scheduled_tasks:
            logger.warning(f"Task ID {task_id} not found")
            return False
            
        task = _scheduled_tasks[task_id]
        
        # If it's a Windows Task Scheduler task, delete it
        if task.windows_task:
            if not checkPrivileges():
                logger.error("Administrator privileges required to delete Windows tasks")
                return False
                
            task_name = f"FirewallController_{task.action}_{task.rule_name}_{task.task_id[:8]}"
            command = f'schtasks /Delete /TN "{task_name}" /F'
            cmd = formatCommand(["cmd", "/c", command])
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            
            if result.returncode != 0:
                logger.warning(f"Failed to delete Windows task: {result.stderr}")
                # Continue with removing from our storage even if Windows task deletion fails
            
            # Clean up the script file
            data_dir = os.path.dirname(TASKS_FILE)
            script_path = os.path.join(data_dir, f"task_{task_id}.py")
            if os.path.exists(script_path):
                try:
                    os.remove(script_path)
                except Exception as e:
                    logger.warning(f"Failed to delete task script file: {str(e)}")
        
        # Remove from our in-memory storage
        del _scheduled_tasks[task_id]
        
        # Save the updated tasks
        save_scheduled_tasks()
        
        logger.info(f"Scheduled task {task_id} for rule '{task.rule_name}' cancelled")
        return True
        
    except Exception as e:
        logger.error(f"Error cancelling scheduled task: {str(e)}")
        return False


def get_scheduled_tasks() -> List[Dict[str, Any]]:
    """
    Get all scheduled tasks.
    
    Returns:
        List of dictionaries containing task information
    """
    try:
        return [task.to_dict() for task in _scheduled_tasks.values()]
    except Exception as e:
        logger.error(f"Error getting scheduled tasks: {str(e)}")
        return []


def _scheduler_loop() -> None:
    """Background thread function to check for and execute scheduled tasks."""
    global _running
    
    logger.info("Scheduler background thread started")
    
    while _running:
        try:
            now = datetime.now()
            tasks_to_execute = []
            
            # Find tasks that need to be executed
            for task_id, task in list(_scheduled_tasks.items()):
                # Skip Windows tasks as they're handled by Task Scheduler
                if task.windows_task:
                    continue
                    
                # Check if it's time to execute
                if task.schedule_time <= now:
                    tasks_to_execute.append((task_id, task))
            
            # Execute tasks
            for task_id, task in tasks_to_execute:
                try:
                    logger.info(f"Executing scheduled task for rule '{task.rule_name}'")
                    
                    # Enable or disable the rule
                    enable = (task.action == 'enable')
                    result = enable_rule(task.rule_name, enable)
                    
                    if result:
                        logger.info(f"Successfully {task.action}d rule '{task.rule_name}'")
                    else:
                        logger.error(f"Failed to {task.action} rule '{task.rule_name}'")
                    
                    # Handle repeating tasks
                    if task.repeat:
                        # Calculate next execution time
                        if task.repeat == 'daily':
                            next_time = task.schedule_time + timedelta(days=1)
                        elif task.repeat == 'weekly':
                            next_time = task.schedule_time + timedelta(days=7)
                        else:
                            # Default to remove the task if repeat pattern is not recognized
                            del _scheduled_tasks[task_id]
                            continue
                            
                        # Update the task with the new time
                        task.schedule_time = next_time
                        _scheduled_tasks[task_id] = task
                    else:
                        # One-time task, remove it
                        del _scheduled_tasks[task_id]
                        
                except Exception as e:
                    logger.error(f"Error executing task {task_id}: {str(e)}")
            
            # Save tasks if any were executed
            if tasks_to_execute:
                save_scheduled_tasks()
                
            # Sleep for a bit before checking again (10 seconds)
            time.sleep(10)
            
        except Exception as e:
            logger.error(f"Error in scheduler loop: {str(e)}")
            time.sleep(30)  # Sleep longer on error to avoid tight loops
    
    logger.info("Scheduler background thread stopped")


def ensure_scheduler_running() -> None:
    """Ensure the scheduler background thread is running."""
    global _running, _scheduler_thread
    
    if _running and _scheduler_thread and _scheduler_thread.is_alive():
        return
        
    _running = True
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()


def stop_scheduler() -> None:
    """Stop the scheduler background thread."""
    global _running
    _running = False
    
    # Wait for thread to terminate if it's running
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=2.0)


# Initialize by loading saved tasks
load_scheduled_tasks()