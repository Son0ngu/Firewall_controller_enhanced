CREATE TABLE Admin_User (
    admin_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Firewall_Rule (
    rule_id INT PRIMARY KEY AUTO_INCREMENT,
    rule_name VARCHAR(100) NOT NULL,
    direction ENUM('INBOUND','OUTBOUND') NOT NULL,
    protocol ENUM('TCP','UDP','ICMP') NOT NULL,
    ip_address VARCHAR(50),
    port INT,
    action ENUM('ALLOW','BLOCK') NOT NULL,
    status BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    admin_id INT,
    FOREIGN KEY (admin_id) REFERENCES Admin_User(admin_id)
);

CREATE TABLE Firewall_Log (
    log_id INT PRIMARY KEY AUTO_INCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    protocol ENUM('TCP','UDP','ICMP') NOT NULL,
    src_ip VARCHAR(50),
    dest_ip VARCHAR(50),
    src_port INT,
    dest_port INT,
    action ENUM('ALLOW','DROP') NOT NULL,
    packet_size INT,
    rule_id INT,
    FOREIGN KEY (rule_id) REFERENCES Firewall_Rule(rule_id)
);
