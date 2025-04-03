# ------------------------------------------------------------------------------------------------
# Database handler for the Firewall Controller application
# Manages storage, retrieval, and persistence of firewall rules in SQLite
# ------------------------------------------------------------------------------------------------
import sqlite3
import os
import json
import csv
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('FirewallDB')

class FirewallDB:
    """Database handler for firewall rules.
    
    This class provides an interface to store and retrieve firewall rules
    in a SQLite database, supporting persistence between application sessions.
    """
    
    def __init__(self, db_path=None):
        """Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file. If None, a default path is used.
        """
        if db_path is None:
            # Use default path in the application data directory
            app_data_dir = os.path.join(os.getenv('APPDATA'), 'FirewallController')
            os.makedirs(app_data_dir, exist_ok=True)
            db_path = os.path.join(app_data_dir, 'firewall_rules.db')
        
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        
        # Initialize database
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Establish a connection to the SQLite database."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row  # Return rows as dictionaries
            self.cursor = self.conn.cursor()
            logger.info(f"Connected to database at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def _create_tables(self):
        """Create necessary tables if they don't exist."""
        try:
            # Create the rules table
            self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE,
                display_name TEXT,
                direction TEXT,
                action TEXT,
                protocol TEXT,
                local_port TEXT,
                remote_port TEXT,
                local_address TEXT,
                remote_address TEXT,
                program TEXT,
                service TEXT,
                profile TEXT,
                enabled INTEGER,
                description TEXT,
                edge_traversal INTEGER,
                interface_type TEXT,
                rule_group TEXT,
                last_modified TEXT
            )
            """)
            
            # Create an audit log table for tracking changes
            self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                action TEXT,
                rule_name TEXT,
                details TEXT
            )
            """)
            
            self.conn.commit()
            logger.info("Database tables created or verified")
        except sqlite3.Error as e:
            logger.error(f"Error creating tables: {e}")
            self.conn.rollback()
            raise
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def _add_audit_log(self, action, rule_name, details=None):
        """Add an entry to the audit log.
        
        Args:
            action: The action performed (add, update, delete, etc.)
            rule_name: The name of the rule affected
            details: Additional details about the action
        """
        try:
            timestamp = datetime.now().isoformat()
            self.cursor.execute(
                "INSERT INTO audit_log (timestamp, action, rule_name, details) VALUES (?, ?, ?, ?)",
                (timestamp, action, rule_name, details)
            )
            self.conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Error adding audit log: {e}")
            self.conn.rollback()
    
    def add_rule(self, rule_data):
        """Add a new firewall rule to the database.
        
        Args:
            rule_data: Dictionary containing rule data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Extract required fields with defaults
            name = rule_data.get('name', rule_data.get('DisplayName', ''))
            
            # Check if a rule with this name already exists
            self.cursor.execute("SELECT COUNT(*) FROM rules WHERE name = ?", (name,))
            if self.cursor.fetchone()[0] > 0:
                logger.warning(f"Rule with name '{name}' already exists")
                return False
            
            # Prepare data for insertion
            columns = []
            placeholders = []
            values = []
            
            # Map rule_data to database columns
            field_mapping = {
                'DisplayName': 'display_name',
                'Description': 'description',
                'Direction': 'direction',
                'Action': 'action',
                'Protocol': 'protocol',
                'LocalPort': 'local_port',
                'RemotePort': 'remote_port',
                'LocalAddress': 'local_address',
                'RemoteAddress': 'remote_address',
                'Program': 'program',
                'Service': 'service',
                'Profiles': 'profile',
                'Enabled': 'enabled',
                'EdgeTraversal': 'edge_traversal',
                'InterfaceType': 'interface_type',
                'Group': 'rule_group'
            }
            
            # Add name field
            columns.append('name')
            placeholders.append('?')
            values.append(name)
            
            # Add last_modified field
            columns.append('last_modified')
            placeholders.append('?')
            values.append(datetime.now().isoformat())
            
            # Add other fields from rule_data
            for key, value in rule_data.items():
                if key in field_mapping:
                    db_column = field_mapping[key]
                    columns.append(db_column)
                    placeholders.append('?')
                    
                    # Convert boolean values to integers
                    if key == 'Enabled' or key == 'EdgeTraversal':
                        if isinstance(value, bool):
                            values.append(1 if value else 0)
                        elif isinstance(value, str):
                            values.append(1 if value.lower() == 'true' else 0)
                        else:
                            values.append(value)
                    else:
                        values.append(value)
            
            # Construct and execute the SQL query
            query = f"INSERT INTO rules ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
            self.cursor.execute(query, values)
            self.conn.commit()
            
            # Add audit log entry
            self._add_audit_log("add", name, f"Added rule '{name}'")
            
            logger.info(f"Added rule '{name}' to database")
            return True
        
        except sqlite3.Error as e:
            logger.error(f"Error adding rule to database: {e}")
            self.conn.rollback()
            return False
    
    def get_rule(self, rule_name):
        """Get a rule by name.
        
        Args:
            rule_name: Name of the rule to retrieve
            
        Returns:
            dict: Rule data or None if not found
        """
        try:
            self.cursor.execute("SELECT * FROM rules WHERE name = ?", (rule_name,))
            row = self.cursor.fetchone()
            
            if row:
                # Convert row to dictionary
                rule = dict(row)
                
                # Convert integer fields to boolean for easier use
                if 'enabled' in rule:
                    rule['enabled'] = bool(rule['enabled'])
                if 'edge_traversal' in rule:
                    rule['edge_traversal'] = bool(rule['edge_traversal'])
                
                return rule
            else:
                logger.warning(f"Rule '{rule_name}' not found in database")
                return None
        
        except sqlite3.Error as e:
            logger.error(f"Error retrieving rule from database: {e}")
            return None
    
    def update_rule(self, rule_name, rule_data):
        """Update an existing firewall rule.
        
        Args:
            rule_name: Name of the rule to update
            rule_data: Dictionary containing updated rule data
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if the rule exists
            self.cursor.execute("SELECT COUNT(*) FROM rules WHERE name = ?", (rule_name,))
            if self.cursor.fetchone()[0] == 0:
                logger.warning(f"Cannot update: rule '{rule_name}' not found")
                return False
            
            # Prepare data for update
            set_clauses = []
            values = []
            
            # Map rule_data to database columns
            field_mapping = {
                'DisplayName': 'display_name',
                'Description': 'description',
                'Direction': 'direction',
                'Action': 'action',
                'Protocol': 'protocol',
                'LocalPort': 'local_port',
                'RemotePort': 'remote_port',
                'LocalAddress': 'local_address',
                'RemoteAddress': 'remote_address',
                'Program': 'program',
                'Service': 'service',
                'Profiles': 'profile',
                'Enabled': 'enabled',
                'EdgeTraversal': 'edge_traversal',
                'InterfaceType': 'interface_type',
                'Group': 'rule_group'
            }
            
            # Add last_modified field
            set_clauses.append("last_modified = ?")
            values.append(datetime.now().isoformat())
            
            # Add other fields from rule_data
            for key, value in rule_data.items():
                if key in field_mapping:
                    db_column = field_mapping[key]
                    set_clauses.append(f"{db_column} = ?")
                    
                    # Convert boolean values to integers
                    if key == 'Enabled' or key == 'EdgeTraversal':
                        if isinstance(value, bool):
                            values.append(1 if value else 0)
                        elif isinstance(value, str):
                            values.append(1 if value.lower() == 'true' else 0)
                        else:
                            values.append(value)
                    else:
                        values.append(value)
            
            # Add rule name for WHERE clause
            values.append(rule_name)
            
            # Construct and execute the SQL query
            query = f"UPDATE rules SET {', '.join(set_clauses)} WHERE name = ?"
            self.cursor.execute(query, values)
            
            if self.cursor.rowcount == 0:
                logger.warning(f"No changes made to rule '{rule_name}'")
                self.conn.rollback()
                return False
            
            self.conn.commit()
            
            # Add audit log entry
            self._add_audit_log("update", rule_name, f"Updated rule '{rule_name}'")
            
            logger.info(f"Updated rule '{rule_name}' in database")
            return True
        
        except sqlite3.Error as e:
            logger.error(f"Error updating rule in database: {e}")
            self.conn.rollback()
            return False
    
    def delete_rule(self, rule_name):
        """Delete a firewall rule from the database.
        
        Args:
            rule_name: Name of the rule to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Check if the rule exists
            self.cursor.execute("SELECT COUNT(*) FROM rules WHERE name = ?", (rule_name,))
            if self.cursor.fetchone()[0] == 0:
                logger.warning(f"Cannot delete: rule '{rule_name}' not found")
                return False
            
            # Delete the rule
            self.cursor.execute("DELETE FROM rules WHERE name = ?", (rule_name,))
            self.conn.commit()
            
            # Add audit log entry
            self._add_audit_log("delete", rule_name, f"Deleted rule '{rule_name}'")
            
            logger.info(f"Deleted rule '{rule_name}' from database")
            return True
        
        except sqlite3.Error as e:
            logger.error(f"Error deleting rule from database: {e}")
            self.conn.rollback()
            return False
    
    def list_rules(self, filter_name=None, filter_direction=None, filter_enabled=None):
        """List firewall rules from the database with optional filtering.
        
        Args:
            filter_name: Filter by rule name (substring match)
            filter_direction: Filter by direction (Inbound/Outbound)
            filter_enabled: Filter by enabled status (True/False)
            
        Returns:
            list: List of rule dictionaries
        """
        try:
            query = "SELECT * FROM rules"
            conditions = []
            values = []
            
            # Add filter conditions
            if filter_name:
                conditions.append("(name LIKE ? OR display_name LIKE ?)")
                values.extend([f"%{filter_name}%", f"%{filter_name}%"])
            
            if filter_direction:
                conditions.append("direction = ?")
                values.append(filter_direction)
            
            if filter_enabled is not None:
                conditions.append("enabled = ?")
                values.append(1 if filter_enabled else 0)
            
            # Add WHERE clause if there are conditions
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            
            # Add ORDER BY clause
            query += " ORDER BY name"
            
            # Execute the query
            self.cursor.execute(query, values)
            rows = self.cursor.fetchall()
            
            # Convert rows to dictionaries
            rules = []
            for row in rows:
                rule = dict(row)
                
                # Convert integer fields to boolean for easier use
                if 'enabled' in rule:
                    rule['enabled'] = bool(rule['enabled'])
                if 'edge_traversal' in rule:
                    rule['edge_traversal'] = bool(rule['edge_traversal'])
                
                rules.append(rule)
            
            logger.info(f"Retrieved {len(rules)} rules from database")
            return rules
        
        except sqlite3.Error as e:
            logger.error(f"Error listing rules from database: {e}")
            return []
    
    def export_rules(self, file_path, format="json"):
        """Export all firewall rules to a file.
        
        Args:
            file_path: Path to the export file
            format: Export format (json or csv)
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get all rules
            rules = self.list_rules()
            
            if format.lower() == "json":
                # Export to JSON
                with open(file_path, 'w') as f:
                    json.dump(rules, f, indent=4)
            
            elif format.lower() == "csv":
                # Export to CSV
                if not rules:
                    # No rules to export
                    with open(file_path, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["No rules found"])
                    return True
                
                # Get field names from first rule
                fieldnames = list(rules[0].keys())
                
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(rules)
            
            else:
                logger.error(f"Unsupported export format: {format}")
                return False
            
            logger.info(f"Exported {len(rules)} rules to {file_path}")
            return True
        
        except (sqlite3.Error, IOError) as e:
            logger.error(f"Error exporting rules: {e}")
            return False
    
    def import_rules(self, file_path, format="json"):
        """Import firewall rules from a file.
        
        Args:
            file_path: Path to the import file
            format: Import format (json or csv)
            
        Returns:
            tuple: (success_count, total_count)
        """
        try:
            rules = []
            
            if format.lower() == "json":
                # Import from JSON
                with open(file_path, 'r') as f:
                    rules = json.load(f)
            
            elif format.lower() == "csv":
                # Import from CSV
                with open(file_path, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    rules = list(reader)
            
            else:
                logger.error(f"Unsupported import format: {format}")
                return (0, 0)
            
            # Add or update rules
            success_count = 0
            for rule in rules:
                # Skip rules without a name
                if 'name' not in rule and 'display_name' not in rule:
                    continue
                
                # Use name or display_name as the rule name
                rule_name = rule.get('name', rule.get('display_name', ''))
                
                # Check if rule exists
                existing_rule = self.get_rule(rule_name)
                
                if existing_rule:
                    # Update existing rule
                    if self.update_rule(rule_name, rule):
                        success_count += 1
                else:
                    # Add new rule
                    if self.add_rule(rule):
                        success_count += 1
            
            logger.info(f"Imported {success_count} of {len(rules)} rules from {file_path}")
            return (success_count, len(rules))
        
        except (sqlite3.Error, IOError, json.JSONDecodeError) as e:
            logger.error(f"Error importing rules: {e}")
            return (0, 0)
    
    def get_audit_log(self, limit=100):
        """Get the audit log entries.
        
        Args:
            limit: Maximum number of entries to retrieve
            
        Returns:
            list: List of audit log entries
        """
        try:
            self.cursor.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = self.cursor.fetchall()
            
            # Convert rows to dictionaries
            log_entries = [dict(row) for row in rows]
            
            return log_entries
        
        except sqlite3.Error as e:
            logger.error(f"Error retrieving audit log: {e}")
            return []


# Test the module if run directly
if __name__ == "__main__":
    # Create a test database in memory
    db = FirewallDB(":memory:")
    
    # Add a test rule
    test_rule = {
        "DisplayName": "Test Rule",
        "Description": "A test rule",
        "Direction": "Inbound",
        "Action": "Allow",
        "Protocol": "TCP",
        "LocalPort": "80",
        "RemotePort": "Any",
        "LocalAddress": "Any",
        "RemoteAddress": "192.168.1.0/24",
        "Program": "C:\\Program Files\\Test\\test.exe",
        "Service": "Any",
        "Profiles": "Any",
        "Enabled": True
    }
    
    print("Adding test rule...")
    success = db.add_rule(test_rule)
    print(f"Add result: {success}")
    
    print("\nListing all rules:")
    rules = db.list_rules()
    for rule in rules:
        print(f"- {rule['display_name']} ({rule['direction']}, {'Enabled' if rule['enabled'] else 'Disabled'})")
    
    print("\nUpdating test rule...")
    test_rule["LocalPort"] = "8080"
    success = db.update_rule("Test Rule", test_rule)
    print(f"Update result: {success}")
    
    print("\nGetting test rule:")
    rule = db.get_rule("Test Rule")
    if rule:
        print(f"- {rule['display_name']} - Port: {rule['local_port']}")
    
    print("\nDeleting test rule...")
    success = db.delete_rule("Test Rule")
    print(f"Delete result: {success}")
    
    print("\nListing all rules after deletion:")
    rules = db.list_rules()
    if not rules:
        print("No rules found")
    
    # Close the database connection
    db.close()