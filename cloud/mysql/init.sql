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
    rule_count INT DEFAULT 0 COMMENT '规则总数',
    added_count INT DEFAULT 0 COMMENT '新增规则数',
    modified_count INT DEFAULT 0 COMMENT '修改规则数',
    deleted_count INT DEFAULT 0 COMMENT '删除规则数',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_version (version),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- =====================================================
-- Phase 1: 规则更新与攻击测试功能新增表
-- =====================================================

-- 规则分类表
CREATE TABLE IF NOT EXISTS rule_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category_type VARCHAR(32) NOT NULL COMMENT '分类类型: classtype/msg_prefix',
    category_name VARCHAR(128) NOT NULL COMMENT '分类名称',
    description TEXT COMMENT '分类描述',
    rule_count INT DEFAULT 0 COMMENT '规则数量',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_type_name (category_type, category_name),
    INDEX idx_category_type (category_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='规则分类表';

-- 规则表 (单条规则)
CREATE TABLE IF NOT EXISTS rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sid INT NOT NULL UNIQUE COMMENT '规则SID',
    gid INT DEFAULT 1 COMMENT '规则GID',
    rev INT DEFAULT 1 COMMENT '规则版本',
    action VARCHAR(16) DEFAULT 'alert' COMMENT '动作: alert/drop/pass',
    protocol VARCHAR(16) COMMENT '协议: tcp/udp/icmp/ip/http等',
    src_addr VARCHAR(1024) COMMENT '源地址',
    src_port VARCHAR(512) COMMENT '源端口',
    direction VARCHAR(4) DEFAULT '->' COMMENT '方向: ->/</><>',
    dst_addr VARCHAR(1024) COMMENT '目标地址',
    dst_port VARCHAR(512) COMMENT '目标端口',
    msg VARCHAR(512) COMMENT '规则消息',
    content TEXT COMMENT '完整规则内容',
    classtype VARCHAR(64) COMMENT 'classtype分类',
    category VARCHAR(64) COMMENT 'msg前缀分类',
    mitre_attack VARCHAR(32) COMMENT 'MITRE ATT&CK ID',
    severity TINYINT DEFAULT 3 COMMENT '严重级别 1-4',
    metadata JSON COMMENT '规则元数据',
    enabled BOOLEAN DEFAULT TRUE COMMENT '是否启用',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_classtype (classtype),
    INDEX idx_category (category),
    INDEX idx_severity (severity),
    INDEX idx_enabled (enabled),
    INDEX idx_protocol (protocol)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='规则表';

-- 规则版本关联表 (记录每个版本包含哪些规则及变更类型)
CREATE TABLE IF NOT EXISTS rule_version_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    version_id INT NOT NULL COMMENT '规则版本ID',
    rule_id INT NOT NULL COMMENT '规则ID',
    change_type ENUM('added', 'modified', 'deleted', 'unchanged') DEFAULT 'unchanged' COMMENT '变更类型',
    previous_content TEXT COMMENT '变更前内容(仅modified)',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_version_id (version_id),
    INDEX idx_rule_id (rule_id),
    INDEX idx_change_type (change_type),
    FOREIGN KEY (version_id) REFERENCES rule_versions(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='规则版本关联表';

-- 攻击测试表
CREATE TABLE IF NOT EXISTS attack_tests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    test_id VARCHAR(64) NOT NULL UNIQUE COMMENT '测试唯一标识',
    name VARCHAR(256) COMMENT '测试名称',
    test_type ENUM('single', 'batch') NOT NULL DEFAULT 'single' COMMENT '测试类型',
    status ENUM('pending', 'running', 'completed', 'failed', 'cancelled') DEFAULT 'pending',
    total_rules INT DEFAULT 0 COMMENT '测试规则数',
    success_count INT DEFAULT 0 COMMENT '成功数',
    failed_count INT DEFAULT 0 COMMENT '失败数',
    config JSON COMMENT '测试配置',
    probe_id VARCHAR(64) COMMENT '执行探针ID',
    started_at DATETIME COMMENT '开始时间',
    completed_at DATETIME COMMENT '完成时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_probe_id (probe_id),
    INDEX idx_created_at (created_at),
    INDEX idx_test_type (test_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击测试表';

-- 攻击测试项表
CREATE TABLE IF NOT EXISTS attack_test_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    test_id INT NOT NULL COMMENT '测试ID',
    rule_id INT NOT NULL COMMENT '规则ID',
    sid INT NOT NULL COMMENT '规则SID',
    status ENUM('pending', 'running', 'success', 'failed', 'timeout', 'skipped') DEFAULT 'pending',
    attack_type VARCHAR(16) COMMENT '攻击类型: http/tcp/udp/dns',
    attack_payload TEXT COMMENT '攻击载荷',
    attack_config JSON COMMENT '攻击配置',
    attack_result JSON COMMENT '攻击结果',
    matched_log_id VARCHAR(64) COMMENT '匹配的日志ID',
    response_time_ms INT COMMENT '响应时间(ms)',
    error_message TEXT COMMENT '错误信息',
    executed_at DATETIME COMMENT '执行时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_test_id (test_id),
    INDEX idx_status (status),
    INDEX idx_sid (sid),
    INDEX idx_rule_id (rule_id),
    FOREIGN KEY (test_id) REFERENCES attack_tests(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击测试项表';

-- 攻击模板表
CREATE TABLE IF NOT EXISTS attack_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(128) NOT NULL COMMENT '模板名称',
    attack_type VARCHAR(16) NOT NULL COMMENT '攻击类型: http/tcp/udp/dns',
    protocol VARCHAR(16) COMMENT '协议',
    template_config JSON NOT NULL COMMENT '模板配置',
    description TEXT COMMENT '模板描述',
    classtype VARCHAR(64) COMMENT '适用的classtype',
    enabled BOOLEAN DEFAULT TRUE COMMENT '是否启用',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_attack_type (attack_type),
    INDEX idx_classtype (classtype),
    INDEX idx_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='攻击模板表';

-- 探针任务队列表
CREATE TABLE IF NOT EXISTS probe_tasks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(64) NOT NULL UNIQUE COMMENT '任务唯一标识',
    task_type ENUM('attack', 'rule_update') NOT NULL COMMENT '任务类型',
    probe_id VARCHAR(64) COMMENT '目标探针ID，NULL表示任意探针',
    status ENUM('pending', 'assigned', 'running', 'completed', 'failed', 'cancelled', 'expired') DEFAULT 'pending',
    priority INT DEFAULT 5 COMMENT '优先级 1-10，数字越小优先级越高',
    payload JSON NOT NULL COMMENT '任务载荷',
    result JSON COMMENT '执行结果',
    retry_count INT DEFAULT 0 COMMENT '重试次数',
    max_retries INT DEFAULT 3 COMMENT '最大重试次数',
    assigned_at DATETIME COMMENT '分配时间',
    started_at DATETIME COMMENT '开始执行时间',
    completed_at DATETIME COMMENT '完成时间',
    expire_at DATETIME COMMENT '过期时间',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status_probe (status, probe_id),
    INDEX idx_task_type (task_type),
    INDEX idx_priority (priority),
    INDEX idx_expire_at (expire_at),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='探针任务队列表';
