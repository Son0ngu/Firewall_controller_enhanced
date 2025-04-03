-- Firewall Controller Database Schema
-- This schema defines the tables used for storing firewall rules and tracking changes

-- Enable foreign keys for referential integrity
PRAGMA foreign_keys = ON;

-- ----------------------------------------------------------------------
-- Rules table
-- Stores all firewall rule information for persistence between sessions
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,                -- Internal system name (unique identifier)
    display_name TEXT,                        -- User-friendly name shown in the interface
    direction TEXT CHECK(direction IN ('Inbound', 'Outbound')), -- Traffic direction
    action TEXT CHECK(action IN ('Allow', 'Block')), -- Rule action
    protocol TEXT,                            -- Network protocol (TCP, UDP, Any, etc.)
    local_port TEXT,                          -- Local port(s) the rule applies to
    remote_port TEXT,                         -- Remote port(s) the rule applies to
    local_address TEXT,                       -- Local IP address(es) 
    remote_address TEXT,                      -- Remote IP address(es)
    program TEXT,                             -- Program/application path
    service TEXT,                             -- Service name
    profile TEXT,                             -- Network profile (Domain, Private, Public, Any)
    enabled INTEGER NOT NULL DEFAULT 1,       -- Whether rule is enabled (1) or disabled (0)
    description TEXT,                         -- Rule description
    edge_traversal INTEGER DEFAULT 0,         -- Allow edge traversal for this rule
    interface_type TEXT,                      -- Network interface type
    rule_group TEXT,                          -- Grouping for related rules
    last_modified TEXT,                       -- Timestamp of last modification
    
    -- Add index on commonly searched fields for better performance
    CONSTRAINT unique_rule_name UNIQUE (name)
);
CREATE INDEX idx_rules_display_name ON rules(display_name);
CREATE INDEX idx_rules_direction ON rules(direction);
CREATE INDEX idx_rules_enabled ON rules(enabled);
CREATE INDEX idx_rules_action ON rules(action);

-- ----------------------------------------------------------------------
-- Audit log table
-- Tracks all changes to firewall rules for auditing and history
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,                  -- When the action occurred
    action TEXT NOT NULL,                     -- Type of action (add, update, delete)
    rule_name TEXT NOT NULL,                  -- Name of the rule affected
    details TEXT,                             -- Additional details about the change
    
    -- Add index on timestamp for efficient historical queries
    CONSTRAINT audit_rule_ref FOREIGN KEY (rule_name) REFERENCES rules(name) ON DELETE SET NULL
);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_rule_name ON audit_log(rule_name);

-- ----------------------------------------------------------------------
-- Views for convenient access to common data
-- ----------------------------------------------------------------------

-- Active rules view (only enabled rules)
CREATE VIEW IF NOT EXISTS active_rules AS
SELECT * FROM rules WHERE enabled = 1;

-- Inbound rules view
CREATE VIEW IF NOT EXISTS inbound_rules AS
SELECT * FROM rules WHERE direction = 'Inbound';

-- Outbound rules view
CREATE VIEW IF NOT EXISTS outbound_rules AS
SELECT * FROM rules WHERE direction = 'Outbound';

-- Block rules view
CREATE VIEW IF NOT EXISTS block_rules AS
SELECT * FROM rules WHERE action = 'Block';

-- Recent audit activity view
CREATE VIEW IF NOT EXISTS recent_activity AS
SELECT timestamp, action, rule_name, details
FROM audit_log
ORDER BY timestamp DESC
LIMIT 100;

-- ----------------------------------------------------------------------
-- Sample data (uncomment to use)
-- ----------------------------------------------------------------------
/*
-- Example rules
INSERT INTO rules (name, display_name, direction, action, protocol, local_port, enabled, description)
VALUES 
('Rule_20250401_HTTP', 'Allow HTTP Inbound', 'Inbound', 'Allow', 'TCP', '80', 1, 'Allow inbound HTTP traffic'),
('Rule_20250401_SSH', 'Block SSH Inbound', 'Inbound', 'Block', 'TCP', '22', 1, 'Block inbound SSH connections'),
('Rule_20250401_FTP', 'Allow FTP Outbound', 'Outbound', 'Allow', 'TCP', '21', 1, 'Allow outbound FTP connections');

-- Example audit log entries
INSERT INTO audit_log (timestamp, action, rule_name, details)
VALUES 
('2025-04-01T10:15:30', 'add', 'Rule_20250401_HTTP', 'Added new HTTP inbound rule'),
('2025-04-01T10:16:45', 'add', 'Rule_20250401_SSH', 'Added new SSH blocking rule'),
('2025-04-01T10:17:20', 'add', 'Rule_20250401_FTP', 'Added new FTP outbound rule');
*/