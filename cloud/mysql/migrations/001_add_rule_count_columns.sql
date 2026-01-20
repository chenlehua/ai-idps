-- Migration: 添加 rule_count 相关列到 rule_versions 表
-- 执行方式: mysql -u root -p ai_idps < 001_add_rule_count_columns.sql

-- 检查并添加 rule_count 列
SET @dbname = DATABASE();
SET @tablename = 'rule_versions';

-- 添加 rule_count 列
SET @preparedStatement = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'rule_count') > 0,
    'SELECT 1',
    'ALTER TABLE rule_versions ADD COLUMN rule_count INT DEFAULT 0 COMMENT "规则总数" AFTER is_active'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 添加 added_count 列
SET @preparedStatement = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'added_count') > 0,
    'SELECT 1',
    'ALTER TABLE rule_versions ADD COLUMN added_count INT DEFAULT 0 COMMENT "新增规则数" AFTER rule_count'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 添加 modified_count 列
SET @preparedStatement = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'modified_count') > 0,
    'SELECT 1',
    'ALTER TABLE rule_versions ADD COLUMN modified_count INT DEFAULT 0 COMMENT "修改规则数" AFTER added_count'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 添加 deleted_count 列
SET @preparedStatement = (SELECT IF(
    (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
     WHERE TABLE_SCHEMA = @dbname AND TABLE_NAME = @tablename AND COLUMN_NAME = 'deleted_count') > 0,
    'SELECT 1',
    'ALTER TABLE rule_versions ADD COLUMN deleted_count INT DEFAULT 0 COMMENT "删除规则数" AFTER modified_count'
));
PREPARE alterIfNotExists FROM @preparedStatement;
EXECUTE alterIfNotExists;
DEALLOCATE PREPARE alterIfNotExists;

-- 更新现有版本的 rule_count（从关联表计算）
UPDATE rule_versions rv
SET rule_count = (
    SELECT COUNT(*) FROM rule_version_rules rvr
    WHERE rvr.version_id = rv.id AND rvr.change_type != 'deleted'
)
WHERE rule_count = 0 OR rule_count IS NULL;

-- 显示结果
SELECT 'Migration completed successfully!' as status;
SELECT id, version, rule_count, added_count, modified_count, deleted_count, is_active
FROM rule_versions ORDER BY created_at DESC LIMIT 10;
