-- 创建数据库
CREATE DATABASE IF NOT EXISTS nids;

-- 告警日志表 (按日分区)
CREATE TABLE IF NOT EXISTS nids.alert_logs (
    id UUID DEFAULT generateUUIDv4(),
    node_id String,
    instance_id String,
    probe_type LowCardinality(String),
    timestamp DateTime64(3),
    src_ip IPv4,
    dest_ip IPv4,
    src_port UInt16,
    dest_port UInt16,
    protocol LowCardinality(String),
    alert_msg String,
    signature_id UInt32,
    severity UInt8,
    category LowCardinality(String),
    raw_log String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, node_id, severity)
TTL timestamp + INTERVAL 90 DAY;

-- 统计物化视图 (按小时聚合)
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.alert_stats_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, node_id, severity)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    node_id,
    severity,
    count() AS alert_count
FROM nids.alert_logs
GROUP BY hour, node_id, severity;

-- 按探针类型统计视图
CREATE MATERIALIZED VIEW IF NOT EXISTS nids.alert_stats_by_type
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, probe_type, category)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    probe_type,
    category,
    count() AS alert_count
FROM nids.alert_logs
GROUP BY hour, probe_type, category;
