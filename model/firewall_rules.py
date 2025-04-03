# ------------------------------------------------------------------------------------------------
# Standard library imports for file handling, subprocess execution, and data manipulation
# ------------------------------------------------------------------------------------------------
import subprocess  # Used to execute PowerShell commands from Python
import logging     # For application-wide logging functionality
import os          # For file/directory operations
import json        # For parsing and generating JSON data
import re          # For regular expression operations (used in rule name sanitization)
import csv         # For reading/writing CSV files when importing/exporting rules
from datetime import datetime  # For generating timestamps for rule names

# Import the database handler
from core.db_handler import FirewallDB

# ------------------------------------------------------------------------------------------------
# Configure logging for this module
# This ensures all operations and errors are properly logged for debugging
# ------------------------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,  # Default log level - shows all INFO, WARNING, ERROR, CRITICAL messages
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'  # Standard log format with timestamps
)
logger = logging.getLogger(__name__)  # Get a module-specific logger

class FirewallRules:
    """Core class for managing Windows Firewall rules.
    
    This class provides a Python interface to the Windows Firewall with Advanced Security,
    using PowerShell commands to interact with the firewall. It enables creating, modifying,
    deleting, enabling, and disabling firewall rules, as well as importing and exporting
    rule configurations.
    """
    
    def __init__(self, log_dir=None, db_path=None):
        """Initialize the FirewallRules manager.
        
        Sets up the log directory for storing operation logs if provided.
        Initializes the database connection for rule persistence.
        
        Args:
            log_dir (str, optional): Directory to store operation logs. Will be created if it doesn't exist.
            db_path (str, optional): Path to the SQLite database file. If None, a default path is used.
        """
        self.log_dir = log_dir  # Store log directory path for future operations
        # Create the log directory if it doesn't exist
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)  # exist_ok=True prevents errors if directory exists
            
        # Initialize database connection
        self.db = FirewallDB(db_path)
        
        # Sync database with actual firewall rules when initialized
        if self.is_admin():
            self._sync_db_with_firewall()

    def _execute_powershell(self, command, as_json=False):
        """Execute a PowerShell command and return the result.

        This is a private helper method that handles the execution of PowerShell commands
        and processes their output. It supports returning the results as plain text or
        parsing them as JSON.

        Args:
            command (str): PowerShell command to execute
            as_json (bool): Whether to parse the output as JSON

        Returns:
            str or dict: Command output (parsed as JSON if requested) or None on error
        """
        try:
            # Format the command for JSON output if needed
            if as_json:
                # If JSON output is requested, pipe the PowerShell output through ConvertTo-Json
                ps_command = f"{command} | ConvertTo-Json"
            else:
                ps_command = command

            # Execute PowerShell with the command using subprocess
            # capture_output=True captures stdout and stderr
            # text=True ensures output is returned as string rather than bytes
            # check=False prevents raising an exception on non-zero return code
            process = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=False
            )

            # Log errors if any (non-zero return code indicates an error)
            if process.returncode != 0:
                logger.error(f"PowerShell error: {process.stderr}")
                return None

            # Process output - parse JSON if requested
            if as_json and process.stdout.strip():
                try:
                    # Convert PowerShell's JSON output to Python dictionary/list
                    return json.loads(process.stdout)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse JSON output: {process.stdout}")
                    return None

            # Return the stripped output text for non-JSON requests
            return process.stdout.strip()

        except Exception as e:
            # Catch any other exceptions during execution
            logger.error(f"Error executing PowerShell command: {e}")
            return None
    
    def _sync_db_with_firewall(self):
        """Synchronize the database with actual Windows Firewall rules.
        
        This ensures the database accurately reflects the current state of the firewall.
        """
        try:
            logger.info("Starting database synchronization with Windows Firewall")
            
            # Get all rules from Windows Firewall
            all_firewall_rules = self.list_rules()
            
            # Track successfully synced rules for later cleanup
            synced_rule_names = []
            
            for rule in all_firewall_rules:
                try:
                    # Get detailed information for each rule
                    details = self.get_rule_details(rule['Name'])
                    if not details:
                        continue
                    
                    # Format rule data for database storage
                    rule_data = {
                        'name': details.get('Name', ''),
                        'DisplayName': details.get('DisplayName', ''),
                        'Description': details.get('Description', ''),
                        'Direction': details.get('Direction', ''),
                        'Action': details.get('Action', ''),
                        'Protocol': details.get('Protocol', 'Any'),
                        'LocalPort': details.get('LocalPort', 'Any'),
                        'RemotePort': details.get('RemotePort', 'Any'),
                        'LocalAddress': details.get('LocalAddress', 'Any'),
                        'RemoteAddress': details.get('RemoteAddress', 'Any'),
                        'Program': details.get('Program', 'Any'),
                        'Service': details.get('Service', 'Any'),
                        'Profiles': details.get('Profile', 'Any'),
                        'Enabled': details.get('Enabled', 'True'),
                        'InterfaceType': details.get('InterfaceType', 'Any'),
                        'EdgeTraversal': details.get('EdgeTraversal', 'False')
                    }
                    
                    # Check if rule exists in database
                    existing_rule = self.db.get_rule(details.get('Name', ''))
                    
                    if existing_rule:
                        # Update existing rule in database
                        self.db.update_rule(details.get('Name', ''), rule_data)
                    else:
                        # Add new rule to database
                        self.db.add_rule(rule_data)
                    
                    # Track successfully synced rule
                    synced_rule_names.append(details.get('Name', ''))
                    
                except Exception as e:
                    logger.error(f"Error syncing rule {rule.get('Name', 'unknown')}: {e}")
            
            # Optional: Clean up database by removing rules that no longer exist in firewall
            # This is optional as you might want to keep historical data
            # db_rules = self.db.list_rules()
            # for db_rule in db_rules:
            #     if db_rule['name'] not in synced_rule_names:
            #         self.db.delete_rule(db_rule['name'])
            
            logger.info(f"Synchronized {len(synced_rule_names)} rules with database")
            
        except Exception as e:
            logger.error(f"Error during database synchronization: {e}")
    
    def is_admin(self):
        """Check if the application is running with administrator privileges.
        
        Uses PowerShell to check if the current user is in the Administrators group.
        Administrator privileges are required for most firewall operations.
        
        Returns:
            bool: True if running as admin, False otherwise
        """
        # This PowerShell command checks if the current user belongs to the Administrators group
        # The S-1-5-32-544 SID represents the built-in Administrators group in Windows
        command = "[bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match 'S-1-5-32-544')"
        result = self._execute_powershell(command)
        return result == "True"  # PowerShell returns "True" as a string when the command evaluates to true

    def list_rules(self, filter_name=None, filter_direction=None, filter_enabled=None):
        """List firewall rules matching the given filters.

        Retrieves firewall rules from Windows Firewall and allows filtering by various
        criteria such as name, direction, or enabled status.

        Args:
            filter_name (str, optional): Filter by name (partial match)
            filter_direction (str, optional): Filter by direction (Inbound/Outbound)
            filter_enabled (bool, optional): Filter by enabled status

        Returns:
            list: List of dictionaries containing rule information or empty list if none found
        """
        # If not admin, try to get rules from database instead
        if not self.is_admin():
            logger.info("Not running as admin, fetching rules from database")
            db_rules = self.db.list_rules(filter_name, filter_direction, filter_enabled)
            
            # Convert database rule format to match Windows Firewall format
            # This ensures consistent format regardless of the source
            formatted_rules = []
            for rule in db_rules:
                formatted_rule = {
                    'Name': rule.get('name', ''),
                    'DisplayName': rule.get('display_name', ''),
                    'Description': rule.get('description', ''),
                    'Enabled': 'True' if rule.get('enabled', False) else 'False',
                    'Direction': rule.get('direction', ''),
                    'Action': rule.get('action', ''),
                    'Profile': rule.get('profile', 'Any')
                }
                formatted_rules.append(formatted_rule)
            
            return formatted_rules
        
        # If admin, get rules directly from Windows Firewall
        # Build the command with filters
        # Get-NetFirewallRule is the PowerShell cmdlet that retrieves firewall rules
        command = "Get-NetFirewallRule"
        filters = []

        # Add filters if provided
        if filter_name:
            # Use wildcard matching (*) for partial name matches
            filters.append(f"-DisplayName '*{filter_name}*'")

        if filter_direction:
            filters.append(f"-Direction '{filter_direction}'")

        if filter_enabled is not None:
            filters.append(f"-Enabled '{str(filter_enabled)}'")

        # Append all filters to the command
        if filters:
            command += " " + " ".join(filters)

        # Add the properties to select to limit the output fields
        # Select-Object limits the returned properties to those we're interested in
        command += " | Select-Object Name, DisplayName, Description, Enabled, Direction, Action, Profile"

        # Execute and parse results
        results = self._execute_powershell(command, as_json=True)

        # Handle case where a single rule is returned (not in a list)
        # PowerShell's ConvertTo-Json behaves differently for single items vs. arrays
        if isinstance(results, dict):
            return [results]  # Convert single result to a list for consistent handling

        return results or []  # Return empty list if no results

    def get_rule_details(self, rule_name):
        """Get detailed information about a specific rule.

        Retrieves comprehensive information about a firewall rule, including
        port, address, and application filters.

        Args:
            rule_name (str): The Name or DisplayName of the rule

        Returns:
            dict: Detailed rule information or None if not found
        """
        # If not admin, try to get rule from database instead
        if not self.is_admin():
            logger.info(f"Not running as admin, fetching rule '{rule_name}' from database")
            db_rule = self.db.get_rule(rule_name)
            
            if not db_rule:
                # Try getting by display name
                db_rules = self.db.list_rules(filter_name=rule_name)
                for rule in db_rules:
                    if rule.get('display_name') == rule_name:
                        db_rule = rule
                        break
            
            if db_rule:
                # Convert database rule format to match Windows Firewall format
                # This ensures consistent format regardless of the source
                return {
                    'Name': db_rule.get('name', ''),
                    'DisplayName': db_rule.get('display_name', ''),
                    'Description': db_rule.get('description', ''),
                    'Enabled': 'True' if db_rule.get('enabled', False) else 'False',
                    'Direction': db_rule.get('direction', ''),
                    'Action': db_rule.get('action', ''),
                    'Protocol': db_rule.get('protocol', 'Any'),
                    'LocalPort': db_rule.get('local_port', 'Any'),
                    'RemotePort': db_rule.get('remote_port', 'Any'),
                    'LocalAddress': db_rule.get('local_address', 'Any'),
                    'RemoteAddress': db_rule.get('remote_address', 'Any'),
                    'Program': db_rule.get('program', 'Any'),
                    'Service': db_rule.get('service', 'Any'),
                    'Profile': db_rule.get('profile', 'Any'),
                    'InterfaceType': db_rule.get('interface_type', 'Any'),
                    'EdgeTraversal': 'True' if db_rule.get('edge_traversal', False) else 'False'
                }
            
            return None  # Rule not found in database
        
        # If admin, get rule details directly from Windows Firewall
        # First try by DisplayName (the user-friendly name)
        # ErrorAction SilentlyContinue prevents PowerShell from throwing an error if rule not found
        command = f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue"
        result = self._execute_powershell(command, as_json=True)

        # If not found, try by internal Name (the system identifier)
        if not result:
            command = f"Get-NetFirewallRule -Name '{rule_name}' -ErrorAction SilentlyContinue"
            result = self._execute_powershell(command, as_json=True)

        if not result:
            return None  # Rule not found

        # If we got a rule, get more detailed information
        rule_name = result.get('Name')
        if not rule_name:
            return result  # Return what we have if there's no Name property

        # Firewall rules have multiple associated filter objects containing different aspects of the rule
        # We need to query each filter type separately to get complete information

        # Get port information (protocol, local and remote ports)
        port_command = f"Get-NetFirewallRule -Name '{rule_name}' | Get-NetFirewallPortFilter | Select Protocol, LocalPort, RemotePort"
        port_info = self._execute_powershell(port_command, as_json=True)

        # Get address information (local and remote IP addresses)
        addr_command = f"Get-NetFirewallRule -Name '{rule_name}' | Get-NetFirewallAddressFilter | Select LocalAddress, RemoteAddress"
        addr_info = self._execute_powershell(addr_command, as_json=True)

        # Get application information (programs and app packages)
        app_command = f"Get-NetFirewallRule -Name '{rule_name}' | Get-NetFirewallApplicationFilter | Select Program, Package"
        app_info = self._execute_powershell(app_command, as_json=True)

        # Combine all information into a single dictionary
        # Start with the base rule info
        combined = {**result}

        # Add each set of filter information if available
        if port_info:
            combined.update(port_info)
        if addr_info:
            combined.update(addr_info)
        if app_info:
            combined.update(app_info)

        return combined  # Return the combined detailed rule information
    
    def add_rule(self, display_name, direction, action, protocol=None, local_port=None, 
                 remote_port=None, local_address=None, remote_address=None, 
                 program=None, description=None, enabled=True):
        """Add a new firewall rule.
        
        Creates a new firewall rule with the specified parameters. Generates a unique
        internal name for the rule based on the display name and current timestamp.
        
        Args:
            display_name (str): Name displayed in firewall rules
            direction (str): 'Inbound' or 'Outbound'
            action (str): 'Allow' or 'Block'
            protocol (str, optional): Protocol like 'TCP' or 'UDP', default is 'Any'
            local_port (str, optional): Local port(s), can be a range like '80-90'
            remote_port (str, optional): Remote port(s), can be a range
            local_address (str, optional): Local IP address(es)
            remote_address (str, optional): Remote IP address(es)
            program (str, optional): Program path this rule applies to
            description (str, optional): Rule description
            enabled (bool, optional): Whether the rule is enabled initially
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check for admin rights (required for creating firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to add firewall rules")
            return False
            
        # Create a unique name for the rule based on display name and timestamp
        # This ensures that even rules with the same display name don't conflict
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        # Remove non-alphanumeric characters from display name for the internal name
        safe_display_name = re.sub(r'[^\w]', '_', display_name)
        rule_name = f"Rule_{timestamp}_{safe_display_name}"
        
        # Start building the command with required parameters
        # New-NetFirewallRule is the PowerShell cmdlet to create a new firewall rule
        command_parts = [
            "New-NetFirewallRule",
            f"-Name '{rule_name}'",              # Internal rule name
            f"-DisplayName '{display_name}'",    # User-visible name
            f"-Direction '{direction}'",         # Inbound or Outbound
            f"-Action '{action}'",               # Allow or Block
            f"-Enabled '{str(enabled)}'"         # Whether rule is active
        ]
        
        # Add optional parameters if provided
        if protocol:
            command_parts.append(f"-Protocol '{protocol}'")
            
        if local_port:
            command_parts.append(f"-LocalPort '{local_port}'")
            
        if remote_port:
            command_parts.append(f"-RemotePort '{remote_port}'")
            
        if local_address:
            command_parts.append(f"-LocalAddress '{local_address}'")
            
        if remote_address:
            command_parts.append(f"-RemoteAddress '{remote_address}'")
            
        if program:
            command_parts.append(f"-Program '{program}'")
            
        if description:
            command_parts.append(f"-Description '{description}'")
        
        # Execute the command by joining all parts with spaces
        result = self._execute_powershell(" ".join(command_parts))
        
        # Log the result and return success/failure
        if result is not None:
            logger.info(f"Successfully added firewall rule: {display_name}")
            
            # Save the rule to the database for persistence
            try:
                # Create a rule data dictionary for the database
                rule_data = {
                    'name': rule_name,
                    'DisplayName': display_name,
                    'Description': description or '',
                    'Direction': direction,
                    'Action': action,
                    'Protocol': protocol or 'Any',
                    'LocalPort': local_port or 'Any',
                    'RemotePort': remote_port or 'Any',
                    'LocalAddress': local_address or 'Any',
                    'RemoteAddress': remote_address or 'Any',
                    'Program': program or 'Any',
                    'Profiles': 'Any',  # Default to Any profile
                    'Enabled': 'True' if enabled else 'False'
                }
                
                # Add the rule to the database
                db_result = self.db.add_rule(rule_data)
                if not db_result:
                    logger.warning(f"Rule added to firewall but failed to save to database: {display_name}")
            
            except Exception as e:
                logger.error(f"Error saving rule to database: {e}")
            
            return True
        else:
            logger.error(f"Failed to add firewall rule: {display_name}")
            return False
    
    def remove_rule(self, rule_identifier):
        """Remove a firewall rule.
        
        Attempts to remove a firewall rule first by DisplayName, then by Name if that fails.
        
        Args:
            rule_identifier (str): The Name or DisplayName of the rule to remove
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check for admin rights (required for removing firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to remove firewall rules")
            return False
        
        # Get rule details first to have the internal name for database removal
        rule_details = self.get_rule_details(rule_identifier)
        internal_name = rule_details.get('Name') if rule_details else rule_identifier
            
        # Try to remove by DisplayName first (user-friendly name)
        # ErrorAction SilentlyContinue prevents PowerShell from throwing an error if rule not found
        command = f"Remove-NetFirewallRule -DisplayName '{rule_identifier}' -ErrorAction SilentlyContinue"
        result = self._execute_powershell(command)
        
        # If that failed, try by internal Name
        if result is None:
            command = f"Remove-NetFirewallRule -Name '{rule_identifier}' -ErrorAction SilentlyContinue"
            result = self._execute_powershell(command)
        
        # If removal was successful, also remove from database
        if result is not None:
            logger.info(f"Successfully removed firewall rule: {rule_identifier}")
            
            # Remove from database
            try:
                if internal_name:
                    self.db.delete_rule(internal_name)
            except Exception as e:
                logger.error(f"Error removing rule from database: {e}")
            
            return True
        else:
            logger.error(f"Failed to remove firewall rule: {rule_identifier}")
            return False
    
    def enable_rule(self, rule_identifier):
        """Enable a firewall rule.
        
        Attempts to enable a firewall rule first by DisplayName, then by Name if that fails.
        
        Args:
            rule_identifier (str): The Name or DisplayName of the rule
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check for admin rights (required for modifying firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to enable firewall rules")
            return False
        
        # Get rule details first to have the internal name for database update
        rule_details = self.get_rule_details(rule_identifier)
        internal_name = rule_details.get('Name') if rule_details else rule_identifier
            
        # Try to enable by DisplayName first (user-friendly name)
        command = f"Enable-NetFirewallRule -DisplayName '{rule_identifier}' -ErrorAction SilentlyContinue"
        result = self._execute_powershell(command)
        
        # If that failed, try by internal Name
        if result is None:
            command = f"Enable-NetFirewallRule -Name '{rule_identifier}' -ErrorAction SilentlyContinue"
            result = self._execute_powershell(command)
        
        # If enabling was successful, also update the database
        if result is not None:
            logger.info(f"Successfully enabled firewall rule: {rule_identifier}")
            
            # Update in database
            try:
                if internal_name:
                    self.db.update_rule(internal_name, {'Enabled': 'True'})
            except Exception as e:
                logger.error(f"Error updating rule in database: {e}")
            
            return True
        else:
            logger.error(f"Failed to enable firewall rule: {rule_identifier}")
            return False
    
    def disable_rule(self, rule_identifier):
        """Disable a firewall rule.
        
        Attempts to disable a firewall rule first by DisplayName, then by Name if that fails.
        
        Args:
            rule_identifier (str): The Name or DisplayName of the rule
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check for admin rights (required for modifying firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to disable firewall rules")
            return False
        
        # Get rule details first to have the internal name for database update
        rule_details = self.get_rule_details(rule_identifier)
        internal_name = rule_details.get('Name') if rule_details else rule_identifier
            
        # Try to disable by DisplayName first (user-friendly name)
        command = f"Disable-NetFirewallRule -DisplayName '{rule_identifier}' -ErrorAction SilentlyContinue"
        result = self._execute_powershell(command)
        
        # If that failed, try by internal Name
        if result is None:
            command = f"Disable-NetFirewallRule -Name '{rule_identifier}' -ErrorAction SilentlyContinue"
            result = self._execute_powershell(command)
        
        # If disabling was successful, also update the database
        if result is not None:
            logger.info(f"Successfully disabled firewall rule: {rule_identifier}")
            
            # Update in database
            try:
                if internal_name:
                    self.db.update_rule(internal_name, {'Enabled': 'False'})
            except Exception as e:
                logger.error(f"Error updating rule in database: {e}")
            
            return True
        else:
            logger.error(f"Failed to disable firewall rule: {rule_identifier}")
            return False
    
    def update_rule(self, rule_identifier, **properties):
        """Update properties of an existing firewall rule.
        
        Uses keyword arguments to provide flexible property updates.
        
        Args:
            rule_identifier (str): The Name or DisplayName of the rule
            **properties: Rule properties to update (e.g., Action='Allow')
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Check for admin rights (required for modifying firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to update firewall rules")
            return False
        
        # Get rule details first to have the internal name for database update
        rule_details = self.get_rule_details(rule_identifier)
        internal_name = rule_details.get('Name') if rule_details else rule_identifier
            
        # Build the command with property updates
        # Convert the key-value pairs to PowerShell parameter format
        properties_str = " ".join([f"-{k} '{v}'" for k, v in properties.items()])
        
        # Try to update by DisplayName first (user-friendly name)
        command = f"Set-NetFirewallRule -DisplayName '{rule_identifier}' {properties_str} -ErrorAction SilentlyContinue"
        result = self._execute_powershell(command)
        
        # If that failed, try by internal Name
        if result is None:
            command = f"Set-NetFirewallRule -Name '{rule_identifier}' {properties_str} -ErrorAction SilentlyContinue"
            result = self._execute_powershell(command)
        
        # If update was successful, also update the database
        if result is not None:
            logger.info(f"Successfully updated firewall rule: {rule_identifier}")
            
            # Update in database
            try:
                if internal_name:
                    self.db.update_rule(internal_name, properties)
            except Exception as e:
                logger.error(f"Error updating rule in database: {e}")
            
            return True
        else:
            logger.error(f"Failed to update firewall rule: {rule_identifier}")
            return False
    
    def export_rules(self, file_path, format='csv'):
        """Export firewall rules to a file.
        
        Exports all firewall rules to a CSV or JSON file for backup or migration.
        
        Args:
            file_path (str): Path to save the exported rules
            format (str): 'csv' or 'json'
            
        Returns:
            bool: True if successful, False otherwise
        """
        # Try to export directly from the database if possible
        try:
            db_result = self.db.export_rules(file_path, format)
            if db_result:
                logger.info(f"Successfully exported rules from database to {file_path}")
                return True
        except Exception as e:
            logger.warning(f"Failed to export from database, falling back to firewall: {e}")
            
        # If database export failed or we're running as admin, get from Windows Firewall
        # Get all rules
        rules = self.list_rules()
        if not rules:
            logger.warning("No rules to export")
            return False
            
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            
            if format.lower() == 'csv':
                # Export as CSV
                with open(file_path, 'w', newline='') as csvfile:
                    # Define the fields to export
                    fieldnames = ['Name', 'DisplayName', 'Enabled', 'Direction', 
                                 'Action', 'Profile', 'Description']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    # Write each rule's data
                    for rule in rules:
                        # Get detailed information for each rule
                        details = self.get_rule_details(rule['Name'])
                        if details:
                            # Write only the fields we care about
                            writer.writerow({
                                'Name': details.get('Name', ''),
                                'DisplayName': details.get('DisplayName', ''),
                                'Enabled': details.get('Enabled', ''),
                                'Direction': details.get('Direction', ''),
                                'Action': details.get('Action', ''),
                                'Profile': details.get('Profile', ''),
                                'Description': details.get('Description', '')
                            })
                
            elif format.lower() == 'json':
                # Export as JSON
                with open(file_path, 'w') as jsonfile:
                    # Get detailed information for each rule
                    detailed_rules = []
                    for rule in rules:
                        details = self.get_rule_details(rule['Name'])
                        if details:
                            detailed_rules.append(details)
                    
                    # Write all rules as a JSON array with pretty formatting
                    json.dump(detailed_rules, jsonfile, indent=2)
            
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
                
            logger.info(f"Successfully exported {len(rules)} rules to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting rules: {e}")
            return False
    
    def import_rules(self, file_path, format='csv'):
        """Import firewall rules from a file.
        
        Imports rules from a CSV or JSON file, updating existing rules or creating new ones.
        
        Args:
            file_path (str): Path to the file with rules to import
            format (str): 'csv' or 'json'
            
        Returns:
            tuple: (success_count, total_count)
        """
        # Check for admin rights (required for creating/modifying firewall rules)
        if not self.is_admin():
            logger.error("Administrator privileges required to import firewall rules")
            return (0, 0)
            
        # Check if the import file exists
        if not os.path.exists(file_path):
            logger.error(f"Import file not found: {file_path}")
            return (0, 0)
            
        try:
            success_count = 0
            total_count = 0
            
            if format.lower() == 'csv':
                # Import from CSV
                with open(file_path, 'r', newline='') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        total_count += 1
                        
                        # Check if rule exists
                        existing = self.get_rule_details(row['DisplayName'])
                        if existing:
                            # Update existing rule
                            if self.update_rule(
                                row['DisplayName'],
                                Enabled=row['Enabled'],
                                Direction=row['Direction'],
                                Action=row['Action']
                            ):
                                success_count += 1
                        else:
                            # Add new rule
                            if self.add_rule(
                                display_name=row['DisplayName'],
                                direction=row['Direction'],
                                action=row['Action'],
                                description=row.get('Description', ''),
                                enabled=(row['Enabled'].lower() == 'true')
                            ):
                                success_count += 1
            
            elif format.lower() == 'json':
                # Import from JSON
                with open(file_path, 'r') as jsonfile:
                    rules = json.load(jsonfile)
                    
                    for rule in rules:
                        total_count += 1
                        
                        # Check if rule exists
                        existing = self.get_rule_details(rule['DisplayName'])
                        if existing:
                            # Update existing rule
                            if self.update_rule(
                                rule['DisplayName'],
                                Enabled=rule['Enabled'],
                                Direction=rule['Direction'],
                                Action=rule['Action']
                            ):
                                success_count += 1
                        else:
                            # Add new rule with more detailed parameters if available
                            enabled = rule['Enabled']
                            if isinstance(enabled, str):
                                enabled = enabled.lower() == 'true'
                                
                            if self.add_rule(
                                display_name=rule['DisplayName'],
                                direction=rule['Direction'],
                                action=rule['Action'],
                                protocol=rule.get('Protocol'),
                                local_port=rule.get('LocalPort'),
                                remote_port=rule.get('RemotePort'),
                                local_address=rule.get('LocalAddress'),
                                remote_address=rule.get('RemoteAddress'),
                                program=rule.get('Program'),
                                description=rule.get('Description', ''),
                                enabled=enabled
                            ):
                                success_count += 1
            
            else:
                logger.error(f"Unsupported import format: {format}")
                return (0, 0)
                
            logger.info(f"Imported {success_count}/{total_count} rules from {file_path}")
            return (success_count, total_count)
            
        except Exception as e:
            logger.error(f"Error importing rules: {e}")
            return (0, 0)
    
    def test_connection(self, protocol, local_port, remote_port, local_address, remote_address):
        """Test if a connection would be allowed by the current firewall rules.
        
        This is a simplified implementation that checks if any rule would allow the connection.
        A complete implementation would simulate the Windows Firewall rule matching logic
        including precedence and profile considerations.
        
        Args:
            protocol (str): Protocol like 'TCP' or 'UDP'
            local_port (int): Local port number
            remote_port (int): Remote port number
            local_address (str): Local IP address
            remote_address (str): Remote IP address
            
        Returns:
            dict: Test result including allowed status and matching rule information
        """
        # Get relevant rules - both inbound and outbound enabled rules
        inbound_rules = self.list_rules(filter_direction="Inbound", filter_enabled=True)
        outbound_rules = self.list_rules(filter_direction="Outbound", filter_enabled=True)
        
        # Check if any rule allows this connection
        # Note: This is a simplified check - a real implementation would need to handle:
        # - Rule precedence (block rules typically override allow rules)
        # - Firewall profiles (domain/private/public)
        # - More complex port/address matching including ranges and wildcards
        for rule in inbound_rules + outbound_rules:
            details = self.get_rule_details(rule['Name'])
            if not details:
                continue
                
            # Check if this rule matches the connection parameters
            if (details.get('Action') == 'Allow' and
                # Protocol match (or rule applies to any protocol)
                (not details.get('Protocol') or details.get('Protocol') == protocol) and
                # Local port match (or rule applies to any local port)
                (not details.get('LocalPort') or str(local_port) in str(details.get('LocalPort'))) and
                # Remote port match (or rule applies to any remote port)
                (not details.get('RemotePort') or str(remote_port) in str(details.get('RemotePort'))) and
                # Local address match (or rule applies to any local address)
                (not details.get('LocalAddress') or local_address in details.get('LocalAddress')) and
                # Remote address match (or rule applies to any remote address)
                (not details.get('RemoteAddress') or remote_address in details.get('RemoteAddress'))):
                
                # Return match information
                return {
                    'allowed': True,
                    'rule_name': details.get('DisplayName'),
                    'rule_direction': details.get('Direction'),
                    'rule_action': details.get('Action')
                }
        
        # If no matching allow rule found
        return {
            'allowed': False,
            'reason': 'No matching rule found that allows this connection'
        }

    def close(self):
        """Close database connections and clean up resources."""
        if hasattr(self, 'db'):
            self.db.close()
            logger.info("Database connection closed")


# ------------------------------------------------------------------------------------------------
# Example usage if this file is run directly
# ------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    # Create a firewall rules manager
    fw = FirewallRules()
    
    # Check if running as admin and warn if not
    if not fw.is_admin():
        print("WARNING: Not running with administrator privileges.")
        print("Many operations will fail without admin rights.")
        print()
    
    # List the first few firewall rules as a demonstration
    print("Current firewall rules:")
    rules = fw.list_rules()
    for rule in rules[:5]:  # Show just the first 5 rules
        print(f"- {rule['DisplayName']} ({rule['Direction']}, {rule['Action']})")
    
    # Example operations (commented out to prevent accidental changes)
    # Uncomment these sections for testing or direct usage
    
    # Add a test rule (requires admin)
    # fw.add_rule(
    #     display_name="Firewall Controller Test",
    #     direction="Inbound",
    #     action="Allow",
    #     protocol="TCP",
    #     local_port="8080",
    #     description="Test rule created by Firewall Controller"
    # )
    
    # Export rules to file for backup
    # fw.export_rules("firewall_rules_export.csv", format="csv")
    
    # Disable a rule (requires admin)
    # fw.disable_rule("Firewall Controller Test")
    
    # Remove a rule (requires admin)
    # fw.remove_rule("Firewall Controller Test")
    
    # Clean up resources
    fw.close()