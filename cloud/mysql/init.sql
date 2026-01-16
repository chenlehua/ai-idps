-- 探针节点表
CREATE TABLE IF NOT EXISTS probe_nodes (
    node_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    status ENUM('online', 'offline', 'unknown') DEFAULT 'unknown',
    last_seen DATETIME,
    current_rule_version VARCHAR(32),
    system_status JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_last_seen (last_seen)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 探针实例表
CREATE TABLE IF NOT EXISTS probe_instances (
    instance_id VARCHAR(64) PRIMARY KEY,
    node_id VARCHAR(64) NOT NULL,
    probe_type VARCHAR(32) NOT NULL,
    interface VARCHAR(32),
    status ENUM('running', 'stopped', 'error') DEFAULT 'stopped',
    last_seen DATETIME,
    metrics JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES probe_nodes(node_id) ON DELETE CASCADE,
    INDEX idx_node_id (node_id),
    INDEX idx_probe_type (probe_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 规则版本表
CREATE TABLE IF NOT EXISTS rule_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version VARCHAR(32) UNIQUE NOT NULL,
    content LONGTEXT NOT NULL,
    checksum VARCHAR(128) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_version (version),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
