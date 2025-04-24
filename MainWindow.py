import json
import sys
import os
import logging
from datetime import datetime, timedelta
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
                             QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QHeaderView,
                             QMessageBox, QTabWidget, QLabel, QSplitter, QAction, QMenu,
                             QToolBar, QStatusBar, QFileDialog, QDateTimeEdit, QComboBox,
                             QDialog, QFormLayout, QLineEdit, QDialogButtonBox, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, QSettings
from PyQt5.QtGui import QIcon

# Import project modules
from GUI.RuleForm import RuleForm
from core.firewall_rules import add_rule, remove_rule, list_rules, enable_rule, rule_exists
from core.scheduler import scheduleRule, registerTask, cancelSchedule, get_scheduled_tasks, ensure_scheduler_running, stop_scheduler
from core.logs import parseLogFile, getRecentEvents, enable_logging
from core.utils import checkPrivileges, loadConfig, saveConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('firewall_controller')

class MainWindow(QMainWindow):
    """Main window for the Firewall Controller application."""
    
    def __init__(self):
        super().__init__()
        
        # Check for administrator privileges
        if not checkPrivileges():
            QMessageBox.warning(
                self,
                "Administrator Privileges Required",
                "This application requires administrator privileges to modify firewall rules.\n\n"
                "Please restart the application as administrator."
            )
        
        # Initialize window properties
        self.setWindowTitle("Windows Firewall Controller")
        self.setMinimumSize(900, 600)
        
        # Initialize UI components
        self._setup_ui()
        
        # Load config
        self.config = loadConfig()
        
        # Start scheduler
        ensure_scheduler_running()
        
        # Refresh rules table initially
        self.updateRulesTable()
        
        # Start auto-refresh timer if enabled
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.updateRulesTable)
        refresh_interval = self.config.get('refresh_interval', 60)  # Default: 60 seconds
        if refresh_interval > 0:
            self.refresh_timer.start(refresh_interval * 1000)
        
        # Status message
        self.statusBar().showMessage("Ready", 3000)
    
    def _setup_ui(self):
        """Set up the user interface."""
        # Create central widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        tabs = QTabWidget()
        
        # Rules tab
        rules_tab = QWidget()
        rules_layout = QVBoxLayout(rules_tab)
        
        # Button bar
        button_layout = QHBoxLayout()
        
        # Add rule button
        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.clicked.connect(self.showAddRuleForm)
        button_layout.addWidget(self.add_rule_button)
        
        # Edit rule button
        self.edit_rule_button = QPushButton("Edit Rule")
        self.edit_rule_button.clicked.connect(self.editSelectedRule)
        button_layout.addWidget(self.edit_rule_button)
        
        # Delete rule button
        self.delete_rule_button = QPushButton("Delete Rule")
        self.delete_rule_button.clicked.connect(self.deleteSelectedRule)
        button_layout.addWidget(self.delete_rule_button)
        
        # Enable/Disable rule button
        self.toggle_rule_button = QPushButton("Enable/Disable")
        self.toggle_rule_button.clicked.connect(self.toggleSelectedRule)
        button_layout.addWidget(self.toggle_rule_button)
        
        # Schedule rule button
        self.schedule_rule_button = QPushButton("Schedule")
        self.schedule_rule_button.clicked.connect(self.scheduleSelectedRule)
        button_layout.addWidget(self.schedule_rule_button)
        
        # Refresh button
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.updateRulesTable)
        button_layout.addWidget(self.refresh_button)
        
        rules_layout.addLayout(button_layout)
        
        # Rules table
        self.rulesTable = QTableWidget()
        self.rulesTable.setColumnCount(7)
        self.rulesTable.setHorizontalHeaderLabels(["Name", "Action", "Direction", "Protocol", "Ports", "Program", "Enabled"])
        self.rulesTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.rulesTable.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.rulesTable.verticalHeader().setVisible(False)
        self.rulesTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.rulesTable.setEditTriggers(QTableWidget.NoEditTriggers)
        self.rulesTable.itemDoubleClicked.connect(self.editSelectedRule)
        
        rules_layout.addWidget(self.rulesTable)
        
        # Add rules tab
        tabs.addTab(rules_tab, "Firewall Rules")
        
        # Logs tab
        logs_tab = QWidget()
        logs_layout = QVBoxLayout(logs_tab)
        
        # Log controls
        log_controls_layout = QHBoxLayout()
        
        # Log type selector
        log_type_label = QLabel("Log Source:")
        self.log_type_combo = QComboBox()
        self.log_type_combo.addItems(["Firewall Log File", "Windows Event Log"])
        self.log_type_combo.currentIndexChanged.connect(self.updateLogs)
        
        # Time range selector
        time_range_label = QLabel("Time Range:")
        self.time_range_combo = QComboBox()
        self.time_range_combo.addItems(["Last Hour", "Last 24 Hours", "Last 7 Days", "All"])
        self.time_range_combo.currentIndexChanged.connect(self.updateLogs)
        
        # Refresh logs button
        self.refresh_logs_button = QPushButton("Refresh Logs")
        self.refresh_logs_button.clicked.connect(self.updateLogs)
        
        # Enable logging button
        self.enable_logging_button = QPushButton("Enable Logging")
        self.enable_logging_button.clicked.connect(self.toggleLogging)
        
        log_controls_layout.addWidget(log_type_label)
        log_controls_layout.addWidget(self.log_type_combo)
        log_controls_layout.addWidget(time_range_label)
        log_controls_layout.addWidget(self.time_range_combo)
        log_controls_layout.addWidget(self.refresh_logs_button)
        log_controls_layout.addWidget(self.enable_logging_button)
        
        logs_layout.addLayout(log_controls_layout)
        
        # Logs table
        self.logsTable = QTableWidget()
        self.logsTable.setColumnCount(6)
        self.logsTable.setHorizontalHeaderLabels(["Timestamp", "Action", "Protocol", "Source", "Destination", "Details"])
        self.logsTable.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.logsTable.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.logsTable.verticalHeader().setVisible(False)
        self.logsTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.logsTable.setEditTriggers(QTableWidget.NoEditTriggers)
        
        logs_layout.addWidget(self.logsTable)
        
        # Add logs tab
        tabs.addTab(logs_tab, "Firewall Logs")
        
        # Scheduler tab
        scheduler_tab = QWidget()
        scheduler_layout = QVBoxLayout(scheduler_tab)
        
        # Scheduler controls
        scheduler_controls_layout = QHBoxLayout()
        
        # Refresh scheduled tasks button
        self.refresh_tasks_button = QPushButton("Refresh Tasks")
        self.refresh_tasks_button.clicked.connect(self.updateScheduledTasks)
        
        # Cancel selected task button
        self.cancel_task_button = QPushButton("Cancel Task")
        self.cancel_task_button.clicked.connect(self.cancelSelectedTask)
        
        scheduler_controls_layout.addWidget(self.refresh_tasks_button)
        scheduler_controls_layout.addWidget(self.cancel_task_button)
        scheduler_controls_layout.addStretch()
        
        scheduler_layout.addLayout(scheduler_controls_layout)
        
        # Scheduled tasks table
        self.tasksTable = QTableWidget()
        self.tasksTable.setColumnCount(5)
        self.tasksTable.setHorizontalHeaderLabels(["Rule Name", "Action", "Schedule Time", "Repeat", "Description"])
        self.tasksTable.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tasksTable.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.tasksTable.verticalHeader().setVisible(False)
        self.tasksTable.setSelectionBehavior(QTableWidget.SelectRows)
        self.tasksTable.setEditTriggers(QTableWidget.NoEditTriggers)
        
        scheduler_layout.addWidget(self.tasksTable)
        
        # Add scheduler tab
        tabs.addTab(scheduler_tab, "Scheduled Tasks")
        
        # Add tabs to main layout
        main_layout.addWidget(tabs)
        
        # Set central widget
        self.setCentralWidget(central_widget)
        
        # Create menu bar
        menu_bar = self.menuBar()
        
        # File menu
        file_menu = menu_bar.addMenu("File")
        
        # Export rules action
        export_action = QAction("Export Rules", self)
        export_action.triggered.connect(self.exportRules)
        file_menu.addAction(export_action)
        
        # Import rules action
        import_action = QAction("Import Rules", self)
        import_action.triggered.connect(self.importRules)
        file_menu.addAction(import_action)
        
        file_menu.addSeparator()
        
        # Exit action
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menu_bar.addMenu("Tools")
        
        # Refresh action
        refresh_action = QAction("Refresh All", self)
        refresh_action.triggered.connect(self.refreshAll)
        tools_menu.addAction(refresh_action)
        
        # Enable/disable auto-refresh
        self.auto_refresh_action = QAction("Auto-Refresh", self)
        self.auto_refresh_action.setCheckable(True)
        self.auto_refresh_action.setChecked(self.config.get('auto_refresh', True))
        self.auto_refresh_action.triggered.connect(self.toggleAutoRefresh)
        tools_menu.addAction(self.auto_refresh_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("Help")
        
        # About action
        about_action = QAction("About", self)
        about_action.triggered.connect(self.showAbout)
        help_menu.addAction(about_action)
        
        # Create status bar
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
    
    def showAddRuleForm(self):
        """Show the add rule dialog."""
        self.addRuleDialog = RuleForm(self)
        self.addRuleDialog.ruleSubmitted.connect(self.onRuleSubmit)
        self.addRuleDialog.exec_()
    
    def editSelectedRule(self):
        """Edit the selected rule."""
        selected_rows = self.rulesTable.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a rule to edit.")
            return
            
        row = selected_rows[0].row()
        rule_name = self.rulesTable.item(row, 0).text()
        
        # Get rule details
        rules = list_rules()
        rule_data = None
        for rule in rules:
            if rule.get('Name') == rule_name:
                # Convert from Windows Firewall format to our format
                rule_data = {
                    'name': rule.get('Name', ''),
                    'description': rule.get('Description', ''),
                    'enabled': rule.get('Enabled', True),
                    'direction': 'in' if rule.get('Direction') == 'Inbound' else 'out',
                    'action': 'allow' if rule.get('Action') == 'Allow' else 'block',
                    'protocol': rule.get('Protocol', 'TCP'),
                    'local_port': rule.get('LocalPort'),
                    'remote_port': rule.get('RemotePort'),
                    'program': rule.get('Program'),
                    'profile': rule.get('Profile', 'Any').lower()
                }
                break
                
        if not rule_data:
            QMessageBox.warning(self, "Rule Not Found", f"Could not find details for rule '{rule_name}'")
            return
            
        # Open edit dialog
        self.editRuleDialog = RuleForm(self, edit_mode=True, rule_data=rule_data)
        self.editRuleDialog.ruleSubmitted.connect(self.onRuleEdit)
        self.editRuleDialog.exec_()
    
    def onRuleSubmit(self, rule_data):
        """Handle submission of a new rule."""
        # Check if rule already exists
        if rule_exists(rule_data['name']):
            QMessageBox.warning(
                self,
                "Rule Exists",
                f"A rule with the name '{rule_data['name']}' already exists.\n\n"
                "Please use a different name."
            )
            return
            
        # Add the rule
        success = add_rule(rule_data)
        
        if success:
            QMessageBox.information(
                self,
                "Rule Added",
                f"Rule '{rule_data['name']}' has been successfully added."
            )
            self.updateRulesTable()
        else:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to add rule '{rule_data['name']}'.\n\n"
                "Please check the logs for details."
            )
    
    def onRuleEdit(self, rule_data):
        """Handle editing of an existing rule."""
        # Remove old rule and add new one with updated properties
        old_name = rule_data['name']
        
        # Remove the old rule
        if remove_rule(old_name):
            # Add the updated rule
            success = add_rule(rule_data)
            
            if success:
                QMessageBox.information(
                    self,
                    "Rule Updated",
                    f"Rule '{rule_data['name']}' has been successfully updated."
                )
                self.updateRulesTable()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to update rule '{rule_data['name']}'.\n\n"
                    "Please check the logs for details."
                )
        else:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to update rule '{rule_data['name']}'.\n\n"
                "Could not remove the existing rule."
            )
    
    def deleteSelectedRule(self):
        """Delete the selected rule."""
        selected_rows = self.rulesTable.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a rule to delete.")
            return
            
        row = selected_rows[0].row()
        rule_name = self.rulesTable.item(row, 0).text()
        
        # Confirm deletion
        result = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the rule '{rule_name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if result == QMessageBox.Yes:
            # Delete the rule
            success = remove_rule(rule_name)
            
            if success:
                QMessageBox.information(
                    self,
                    "Rule Deleted",
                    f"Rule '{rule_name}' has been successfully deleted."
                )
                self.updateRulesTable()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to delete rule '{rule_name}'.\n\n"
                    "Please check the logs for details."
                )
    
    def toggleSelectedRule(self):
        """Enable or disable the selected rule."""
        selected_rows = self.rulesTable.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a rule to toggle.")
            return
            
        row = selected_rows[0].row()
        rule_name = self.rulesTable.item(row, 0).text()
        enabled_state = self.rulesTable.item(row, 6).text() == "Yes"
        
        # Toggle the rule state
        success = enable_rule(rule_name, not enabled_state)
        
        if success:
            new_state = "disabled" if enabled_state else "enabled"
            QMessageBox.information(
                self,
                "Rule Updated",
                f"Rule '{rule_name}' has been successfully {new_state}."
            )
            self.updateRulesTable()
        else:
            action = "disable" if enabled_state else "enable"
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to {action} rule '{rule_name}'.\n\n"
                "Please check the logs for details."
            )
    
    def scheduleSelectedRule(self):
        """Schedule the selected rule for activation/deactivation."""
        selected_rows = self.rulesTable.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a rule to schedule.")
            return
            
        row = selected_rows[0].row()
        rule_name = self.rulesTable.item(row, 0).text()
        
        # Find rule details
        rules = list_rules()
        rule_data = None
        for rule in rules:
            if rule.get('Name') == rule_name:
                rule_data = rule
                break
                
        if not rule_data:
            QMessageBox.warning(self, "Rule Not Found", f"Could not find details for rule '{rule_name}'")
            return
        
        # Show schedule dialog
        dialog = ScheduleDialog(self)
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            schedule_time = dialog.datetime_edit.dateTime().toPyDateTime()
            action = "enable" if dialog.action_combo.currentText() == "Enable" else "disable"
            repeat = dialog.repeat_combo.currentText().lower() if dialog.repeat_combo.currentIndex() > 0 else None
            use_task_scheduler = dialog.use_task_scheduler.isChecked()
            description = dialog.description_edit.text()
            
            # Schedule the rule
            rule_dict = {'name': rule_name}
            if use_task_scheduler:
                task_id = registerTask(rule_dict, schedule_time, action, repeat, description)
            else:
                task_id = scheduleRule(rule_dict, schedule_time, action, repeat, description)
                
            if task_id:
                QMessageBox.information(
                    self,
                    "Rule Scheduled",
                    f"Rule '{rule_name}' has been scheduled to {action} at {schedule_time}."
                )
                self.updateScheduledTasks()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to schedule rule '{rule_name}'.\n\n"
                    "Please check the logs for details."
                )
    
    def cancelSelectedTask(self):
        """Cancel the selected scheduled task."""
        selected_rows = self.tasksTable.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a task to cancel.")
            return
            
        row = selected_rows[0].row()
        rule_name = self.tasksTable.item(row, 0).text()
        task_id = self.tasksTable.item(row, 0).data(Qt.UserRole)
        
        # Confirm cancellation
        result = QMessageBox.question(
            self,
            "Confirm Cancellation",
            f"Are you sure you want to cancel the scheduled task for rule '{rule_name}'?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if result == QMessageBox.Yes:
            # Cancel the task
            success = cancelSchedule(task_id)
            
            if success:
                QMessageBox.information(
                    self,
                    "Task Cancelled",
                    f"Scheduled task for rule '{rule_name}' has been cancelled."
                )
                self.updateScheduledTasks()
            else:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to cancel scheduled task for rule '{rule_name}'.\n\n"
                    "Please check the logs for details."
                )
    
    def updateRulesTable(self):
        """Update the rules table with current firewall rules."""
        # Clear existing rows
        self.rulesTable.setRowCount(0)
        
        try:
            # Get all firewall rules
            rules = list_rules()
            
            # Populate the table
            for i, rule in enumerate(rules):
                self.rulesTable.insertRow(i)
                
                # Name
                self.rulesTable.setItem(i, 0, QTableWidgetItem(rule.get('Name', '')))
                
                # Action
                self.rulesTable.setItem(i, 1, QTableWidgetItem(rule.get('Action', '')))
                
                # Direction
                self.rulesTable.setItem(i, 2, QTableWidgetItem(rule.get('Direction', '')))
                
                # Protocol
                protocol = rule.get('Protocol', '')
                self.rulesTable.setItem(i, 3, QTableWidgetItem(str(protocol)))
                
                # Ports (combine local and remote ports)
                ports = []
                if rule.get('LocalPort'):
                    ports.append(f"Local: {rule.get('LocalPort')}")
                if rule.get('RemotePort'):
                    ports.append(f"Remote: {rule.get('RemotePort')}")
                self.rulesTable.setItem(i, 4, QTableWidgetItem(", ".join(ports)))
                
                # Program
                self.rulesTable.setItem(i, 5, QTableWidgetItem(rule.get('Program', '')))
                
                # Enabled
                enabled = "Yes" if rule.get('Enabled', True) else "No"
                self.rulesTable.setItem(i, 6, QTableWidgetItem(enabled))
            
            # Resize rows to contents
            self.rulesTable.resizeRowsToContents()
            
            # Update status bar
            self.statusBar().showMessage(f"Found {len(rules)} firewall rules", 3000)
            
        except Exception as e:
            logger.error(f"Error updating rules table: {str(e)}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
    
    def updateLogs(self):
        """Update the logs table with firewall log entries."""
        # Clear existing rows
        self.logsTable.setRowCount(0)
        
        try:
            # Get time range
            time_range = self.time_range_combo.currentText()
            if time_range == "Last Hour":
                hours = 1
            elif time_range == "Last 24 Hours":
                hours = 24
            elif time_range == "Last 7 Days":
                hours = 24 * 7
            else:  # All
                hours = 0
            
            # Get log entries based on selected source
            log_source = self.log_type_combo.currentText()
            log_entries = []
            
            if log_source == "Firewall Log File":
                log_entries = parseLogFile(max_entries=100)
            else:  # Windows Event Log
                log_entries = getRecentEvents(hours=hours if hours > 0 else 24 * 30, max_events=100)
            
            # Populate the table
            for i, entry in enumerate(log_entries):
                self.logsTable.insertRow(i)
                
                # Timestamp
                timestamp = entry.get('timestamp', '')
                self.logsTable.setItem(i, 0, QTableWidgetItem(str(timestamp)))
                
                # Action
                action = entry.get('action', entry.get('type', ''))
                self.logsTable.setItem(i, 1, QTableWidgetItem(str(action)))
                
                # Protocol
                protocol = entry.get('protocol', '')
                self.logsTable.setItem(i, 2, QTableWidgetItem(str(protocol)))
                
                # Source
                source = f"{entry.get('source_ip', entry.get('source_address', ''))}:{entry.get('source_port', '')}"
                self.logsTable.setItem(i, 3, QTableWidgetItem(source))
                
                # Destination
                dest = f"{entry.get('destination_ip', entry.get('destination_address', ''))}:{entry.get('destination_port', '')}"
                self.logsTable.setItem(i, 4, QTableWidgetItem(dest))
                
                # Details (application or additional info)
                details = entry.get('application', entry.get('data', ''))
                self.logsTable.setItem(i, 5, QTableWidgetItem(str(details)))
            
            # Resize rows to contents
            self.logsTable.resizeRowsToContents()
            
            # Update status bar
            self.statusBar().showMessage(f"Found {len(log_entries)} log entries", 3000)
            
        except Exception as e:
            logger.error(f"Error updating logs table: {str(e)}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
    
    def updateScheduledTasks(self):
        """Update the scheduled tasks table."""
        # Clear existing rows
        self.tasksTable.setRowCount(0)
        
        try:
            # Get all scheduled tasks
            tasks = get_scheduled_tasks()
            
            # Populate the table
            for i, task in enumerate(tasks):
                self.tasksTable.insertRow(i)
                
                # Rule Name
                name_item = QTableWidgetItem(task.get('rule_name', ''))
                name_item.setData(Qt.UserRole, task.get('task_id', ''))  # Store task_id for later use
                self.tasksTable.setItem(i, 0, name_item)
                
                # Action
                self.tasksTable.setItem(i, 1, QTableWidgetItem(task.get('action', '')))
                
                # Schedule Time
                schedule_time = task.get('schedule_time', '')
                self.tasksTable.setItem(i, 2, QTableWidgetItem(str(schedule_time)))
                
                # Repeat
                repeat = task.get('repeat', 'One-time')
                if not repeat:
                    repeat = 'One-time'
                self.tasksTable.setItem(i, 3, QTableWidgetItem(str(repeat)))
                
                # Description
                self.tasksTable.setItem(i, 4, QTableWidgetItem(task.get('description', '')))
            
            # Resize rows to contents
            self.tasksTable.resizeRowsToContents()
            
            # Update status bar
            self.statusBar().showMessage(f"Found {len(tasks)} scheduled tasks", 3000)
            
        except Exception as e:
            logger.error(f"Error updating scheduled tasks table: {str(e)}")
            self.statusBar().showMessage(f"Error: {str(e)}", 5000)
    
    def toggleLogging(self):
        """Enable or disable Windows Firewall logging."""
        # Determine current state (this is approximate; could improve with a dedicated function)
        button_text = self.enable_logging_button.text()
        enable = "Enable" in button_text
        
        # Enable/disable logging
        success = enable_logging(enable)
        
        if success:
            new_state = "enabled" if enable else "disabled"
            self.enable_logging_button.setText("Disable Logging" if enable else "Enable Logging")
            QMessageBox.information(
                self,
                "Logging Settings Updated",
                f"Windows Firewall logging has been {new_state}."
            )
            self.updateLogs()
        else:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to {'enable' if enable else 'disable'} Windows Firewall logging.\n\n"
                "Please check the logs for details."
            )
    
    def toggleAutoRefresh(self, checked):
        """Enable or disable auto-refresh."""
        if checked:
            refresh_interval = self.config.get('refresh_interval', 60)  # Default: 60 seconds
            self.refresh_timer.start(refresh_interval * 1000)
            self.config['auto_refresh'] = True
        else:
            self.refresh_timer.stop()
            self.config['auto_refresh'] = False
            
        # Save config
        saveConfig(self.config)
    
    def exportRules(self):
        """Export firewall rules to a JSON file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Firewall Rules",
            os.path.expanduser("~/firewall_rules.json"),
            "JSON Files (*.json);;All Files (*.*)"
        )
        
        if file_path:
            try:
                # Get all firewall rules
                rules = list_rules()
                
                # Save to file
                with open(file_path, 'w') as f:
                    json.dump(rules, f, indent=2)
                    
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Firewall rules have been exported to {file_path}"
                )
                    
            except Exception as e:
                logger.error(f"Error exporting rules: {str(e)}")
                QMessageBox.critical(
                    self,
                    "Export Error",
                    f"Failed to export firewall rules: {str(e)}"
                )
    
    def importRules(self):
        """Import firewall rules from a JSON file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Import Firewall Rules",
            os.path.expanduser("~"),
            "JSON Files (*.json);;All Files (*.*)"
        )
        
        if file_path:
            try:
                # Read rules from file
                with open(file_path, 'r') as f:
                    rules = json.load(f)
                    
                # Confirm import
                count = len(rules)
                result = QMessageBox.question(
                    self,
                    "Confirm Import",
                    f"Import {count} firewall rules?\n\n"
                    "Existing rules with the same names will be overwritten.",
                    QMessageBox.Yes | QMessageBox.No,
                    QMessageBox.No
                )
                
                if result == QMessageBox.Yes:
                    # Process rules
                    success_count = 0
                    fail_count = 0
                    
                    for rule in rules:
                        # Convert from saved format to our format
                        rule_data = {
                            'name': rule.get('Name', ''),
                            'description': rule.get('Description', ''),
                            'enabled': rule.get('Enabled', True),
                            'direction': 'in' if rule.get('Direction') == 'Inbound' else 'out',
                            'action': 'allow' if rule.get('Action') == 'Allow' else 'block',
                            'protocol': rule.get('Protocol', 'TCP'),
                            'local_port': rule.get('LocalPort'),
                            'remote_port': rule.get('RemotePort'),
                            'program': rule.get('Program'),
                            'profile': rule.get('Profile', 'Any').lower()
                        }
                        
                        # Check if rule exists and remove it
                        if rule_exists(rule_data['name']):
                            remove_rule(rule_data['name'])
                            
                        # Add the rule
                        if add_rule(rule_data):
                            success_count += 1
                        else:
                            fail_count += 1
                    
                    # Show results
                    QMessageBox.information(
                        self,
                        "Import Results",
                        f"Successfully imported {success_count} rules.\n"
                        f"Failed to import {fail_count} rules."
                    )
                    
                    # Update the rules table
                    self.updateRulesTable()
                    
            except Exception as e:
                logger.error(f"Error importing rules: {str(e)}")
                QMessageBox.critical(
                    self,
                    "Import Error",
                    f"Failed to import firewall rules: {str(e)}"
                )
    
    def refreshAll(self):
        """Refresh all tables."""
        self.updateRulesTable()
        self.updateLogs()
        self.updateScheduledTasks()
        self.statusBar().showMessage("All data refreshed", 3000)
    
    def showAbout(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About Windows Firewall Controller",
            "Windows Firewall Controller\n\n"
            "A GUI tool for managing Windows Firewall rules\n\n"
            "Version 1.0.0\n\n"
            "© 2023 Your Name/Organization"
        )
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop scheduler
        stop_scheduler()
        
        # Save settings
        saveConfig(self.config)
        
        # Accept the event
        event.accept()


class ScheduleDialog(QDialog):
    """Dialog for scheduling rule activation/deactivation."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        
        self.setWindowTitle("Schedule Rule")
        self.resize(400, 250)
        
        layout = QFormLayout(self)
        
        # Date/time picker
        self.datetime_edit = QDateTimeEdit(datetime.now() + timedelta(hours=1))
        self.datetime_edit.setCalendarPopup(True)
        self.datetime_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        layout.addRow("Schedule Time:", self.datetime_edit)
        
        # Action (enable/disable)
        self.action_combo = QComboBox()
        self.action_combo.addItems(["Enable", "Disable"])
        layout.addRow("Action:", self.action_combo)
        
        # Repeat pattern
        self.repeat_combo = QComboBox()
        self.repeat_combo.addItems(["One-time", "Daily", "Weekly"])
        layout.addRow("Repeat:", self.repeat_combo)
        
        # Use Windows Task Scheduler
        self.use_task_scheduler = QCheckBox("Register with Windows Task Scheduler")
        self.use_task_scheduler.setToolTip("Tasks registered with Windows Task Scheduler will run even if this application is closed")
        layout.addRow("", self.use_task_scheduler)
        
        # Description
        self.description_edit = QLineEdit()
        layout.addRow("Description:", self.description_edit)
        
        # Buttons
        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addRow(self.button_box)


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a more consistent look
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Start the event loop
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()