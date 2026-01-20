"""规则版本管理服务"""

import hashlib
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

from app.models.rule import Rule, ParsedRule, RuleChangeSummary, ChangeType
from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


@dataclass
class RuleVersion:
    """规则版本"""
    id: int
    version: str
    content: str
    checksum: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    rule_count: int = 0
    added_count: int = 0
    modified_count: int = 0
    deleted_count: int = 0

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'version': self.version,
            'checksum': self.checksum,
            'description': self.description,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'rule_count': self.rule_count,
            'added_count': self.added_count,
            'modified_count': self.modified_count,
            'deleted_count': self.deleted_count,
        }


class RuleVersionService:
    """规则版本管理服务"""

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None
    ):
        """初始化版本管理服务

        Args:
            mysql_service: MySQL 服务实例
            redis_service: Redis 服务实例
        """
        self.mysql_service = mysql_service
        self.redis_service = redis_service

    async def create_version(
        self,
        new_rules: List[Dict],
        changes: RuleChangeSummary,
        description: str = ""
    ) -> RuleVersion:
        """创建新版本

        Args:
            new_rules: 新规则列表 (字典格式)
            changes: 规则变更摘要
            description: 版本描述

        Returns:
            新创建的版本
        """
        # 生成版本号
        version = self._generate_version()

        # 生成规则文件内容
        content = self._generate_rules_content(new_rules)
        checksum = hashlib.sha256(content.encode()).hexdigest()

        # 开始事务
        try:
            # 1. 将当前活跃版本设为非活跃
            await self.mysql_service.execute(
                "UPDATE rule_versions SET is_active = FALSE WHERE is_active = TRUE"
            )

            # 2. 创建新版本记录
            rule_count = len(new_rules)
            added_count = len(changes.added_rules)
            modified_count = len(changes.modified_rules)
            deleted_count = len(changes.deleted_sids)

            version_id = await self.mysql_service.insert(
                """
                INSERT INTO rule_versions (version, content, checksum, description, is_active,
                                          rule_count, added_count, modified_count, deleted_count)
                VALUES (%s, %s, %s, %s, TRUE, %s, %s, %s, %s)
                """,
                (version, content, checksum, description, rule_count, added_count, modified_count, deleted_count)
            )

            # 3. 更新/插入规则
            await self._apply_rule_changes(version_id, new_rules, changes)

            # 4. 更新 Redis 缓存
            await self._update_cache(version, content)

            logger.info(f"Created rule version {version} with {len(new_rules)} rules")

            return RuleVersion(
                id=version_id,
                version=version,
                content=content,
                checksum=checksum,
                description=description,
                is_active=True,
                created_at=datetime.utcnow(),
                rule_count=rule_count,
                added_count=added_count,
                modified_count=modified_count,
                deleted_count=deleted_count,
            )

        except Exception as e:
            logger.error(f"Failed to create version: {e}")
            raise

    async def get_active_version(self) -> Optional[RuleVersion]:
        """获取当前活跃版本

        Returns:
            活跃版本，不存在返回 None
        """
        # 先查缓存
        if self.redis_service:
            cached_version = await self.redis_service.get(RedisKeys.RULE_VERSION_LATEST)
            if cached_version:
                row = await self.mysql_service.fetchone(
                    "SELECT * FROM rule_versions WHERE version = %s",
                    (cached_version,)
                )
                if row:
                    return self._row_to_version(row)

        # 查数据库
        row = await self.mysql_service.fetchone(
            "SELECT * FROM rule_versions WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1"
        )

        if row:
            version = self._row_to_version(row)
            # 更新缓存
            if self.redis_service:
                await self.redis_service.set(
                    RedisKeys.RULE_VERSION_LATEST,
                    version.version
                )
            return version

        return None

    async def get_version_by_id(self, version_id: int) -> Optional[RuleVersion]:
        """按 ID 获取版本

        Args:
            version_id: 版本 ID

        Returns:
            版本对象
        """
        row = await self.mysql_service.fetchone(
            "SELECT * FROM rule_versions WHERE id = %s",
            (version_id,)
        )
        return self._row_to_version(row) if row else None

    async def get_version(self, version: str) -> Optional[RuleVersion]:
        """按版本号获取版本

        Args:
            version: 版本号

        Returns:
            版本对象
        """
        row = await self.mysql_service.fetchone(
            "SELECT * FROM rule_versions WHERE version = %s",
            (version,)
        )
        return self._row_to_version(row) if row else None

    async def list_versions(self, limit: int = 20, offset: int = 0) -> List[RuleVersion]:
        """获取版本列表

        Args:
            limit: 返回数量
            offset: 偏移量

        Returns:
            版本列表
        """
        # 查询版本列表，同时计算每个版本的规则数
        rows = await self.mysql_service.fetchall(
            """
            SELECT rv.*,
                   (SELECT COUNT(*) FROM rule_version_rules rvr
                    WHERE rvr.version_id = rv.id AND rvr.change_type != 'deleted'
                   ) as computed_rule_count
            FROM rule_versions rv
            ORDER BY rv.created_at DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset)
        )

        if not rows:
            return []

        versions = []
        for row in rows:
            version = self._row_to_version(row)
            # 如果 rule_count 为 0（数据库列不存在或未设置），使用计算的值
            if version.rule_count == 0:
                version.rule_count = row.get('computed_rule_count', 0) or 0
            versions.append(version)

        return versions

    async def get_version_diff(self, v1: str, v2: str) -> Dict:
        """获取版本差异

        Args:
            v1: 版本 1
            v2: 版本 2

        Returns:
            差异字典
        """
        # 获取两个版本的规则关联记录
        v1_rules = await self.mysql_service.fetchall(
            """
            SELECT rvr.*, r.sid, r.msg FROM rule_version_rules rvr
            JOIN rule_versions rv ON rvr.version_id = rv.id
            JOIN rules r ON rvr.rule_id = r.id
            WHERE rv.version = %s
            """,
            (v1,)
        )

        v2_rules = await self.mysql_service.fetchall(
            """
            SELECT rvr.*, r.sid, r.msg FROM rule_version_rules rvr
            JOIN rule_versions rv ON rvr.version_id = rv.id
            JOIN rules r ON rvr.rule_id = r.id
            WHERE rv.version = %s
            """,
            (v2,)
        )

        v1_by_sid = {r['sid']: r for r in v1_rules} if v1_rules else {}
        v2_by_sid = {r['sid']: r for r in v2_rules} if v2_rules else {}

        v1_sids = set(v1_by_sid.keys())
        v2_sids = set(v2_by_sid.keys())

        return {
            'v1': v1,
            'v2': v2,
            'added_in_v2': list(v2_sids - v1_sids),
            'removed_in_v2': list(v1_sids - v2_sids),
            'common_count': len(v1_sids & v2_sids),
        }

    async def rollback_to_version(self, version_id: int) -> bool:
        """回滚到指定版本

        Args:
            version_id: 目标版本 ID

        Returns:
            是否成功
        """
        try:
            # 获取目标版本
            target_version = await self.get_version_by_id(version_id)
            if not target_version:
                logger.error(f"Version {version_id} not found")
                return False

            # 将所有版本设为非活跃
            await self.mysql_service.execute(
                "UPDATE rule_versions SET is_active = FALSE"
            )

            # 将目标版本设为活跃
            await self.mysql_service.execute(
                "UPDATE rule_versions SET is_active = TRUE WHERE id = %s",
                (version_id,)
            )

            # 更新缓存
            await self._update_cache(target_version.version, target_version.content)

            logger.info(f"Rolled back to version {target_version.version}")
            return True

        except Exception as e:
            logger.error(f"Failed to rollback: {e}")
            return False

    async def _apply_rule_changes(
        self,
        version_id: int,
        new_rules: List[Dict],
        changes: RuleChangeSummary
    ):
        """应用规则变更

        Args:
            version_id: 版本 ID
            new_rules: 新规则列表
            changes: 变更摘要
        """
        new_rules_by_sid = {r['sid']: r for r in new_rules}

        # 1. 处理新增规则
        for parsed_rule in changes.added_rules:
            rule_data = new_rules_by_sid.get(parsed_rule.sid)
            if not rule_data:
                continue

            # 插入新规则
            rule_id = await self._insert_rule(rule_data)

            # 记录版本关联
            await self._insert_version_rule(version_id, rule_id, ChangeType.ADDED)

        # 2. 处理修改规则
        for parsed_rule in changes.modified_rules:
            rule_data = new_rules_by_sid.get(parsed_rule.sid)
            if not rule_data:
                continue

            # 获取现有规则
            existing = await self.mysql_service.fetchone(
                "SELECT id, content FROM rules WHERE sid = %s",
                (parsed_rule.sid,)
            )

            if existing:
                # 更新规则
                await self._update_rule(existing['id'], rule_data)
                # 记录版本关联
                await self._insert_version_rule(
                    version_id, existing['id'], ChangeType.MODIFIED,
                    existing.get('content')
                )

        # 3. 处理删除规则
        for sid in changes.deleted_sids:
            existing = await self.mysql_service.fetchone(
                "SELECT id FROM rules WHERE sid = %s",
                (sid,)
            )

            if existing:
                # 标记为禁用而不是物理删除
                await self.mysql_service.execute(
                    "UPDATE rules SET enabled = FALSE WHERE id = %s",
                    (existing['id'],)
                )
                # 记录版本关联
                await self._insert_version_rule(
                    version_id, existing['id'], ChangeType.DELETED
                )

        # 4. 处理未变更规则
        for rule_data in new_rules:
            sid = rule_data['sid']
            if sid in [r.sid for r in changes.added_rules]:
                continue
            if sid in [r.sid for r in changes.modified_rules]:
                continue
            if sid in changes.deleted_sids:
                continue

            existing = await self.mysql_service.fetchone(
                "SELECT id FROM rules WHERE sid = %s",
                (sid,)
            )

            if existing:
                await self._insert_version_rule(
                    version_id, existing['id'], ChangeType.UNCHANGED
                )

    async def _insert_rule(self, rule_data: Dict) -> int:
        """插入规则

        Args:
            rule_data: 规则数据

        Returns:
            规则 ID
        """
        metadata_json = json.dumps(rule_data.get('metadata')) if rule_data.get('metadata') else None

        rule_id = await self.mysql_service.insert(
            """
            INSERT INTO rules (sid, gid, rev, action, protocol, src_addr, src_port,
                             direction, dst_addr, dst_port, msg, content, classtype,
                             category, mitre_attack, severity, metadata, enabled)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, TRUE)
            ON DUPLICATE KEY UPDATE
                gid = VALUES(gid), rev = VALUES(rev), action = VALUES(action),
                protocol = VALUES(protocol), src_addr = VALUES(src_addr),
                src_port = VALUES(src_port), direction = VALUES(direction),
                dst_addr = VALUES(dst_addr), dst_port = VALUES(dst_port),
                msg = VALUES(msg), content = VALUES(content), classtype = VALUES(classtype),
                category = VALUES(category), mitre_attack = VALUES(mitre_attack),
                severity = VALUES(severity), metadata = VALUES(metadata), enabled = TRUE
            """,
            (
                rule_data.get('sid'), rule_data.get('gid', 1), rule_data.get('rev', 1),
                rule_data.get('action', 'alert'), rule_data.get('protocol'),
                rule_data.get('src_addr'), rule_data.get('src_port'),
                rule_data.get('direction', '->'), rule_data.get('dst_addr'),
                rule_data.get('dst_port'), rule_data.get('msg'),
                rule_data.get('content'), rule_data.get('classtype'),
                rule_data.get('category'), rule_data.get('mitre_attack'),
                rule_data.get('severity', 3), metadata_json
            )
        )

        # 如果是 ON DUPLICATE KEY UPDATE，需要获取现有 ID
        if not rule_id:
            existing = await self.mysql_service.fetchone(
                "SELECT id FROM rules WHERE sid = %s",
                (rule_data.get('sid'),)
            )
            rule_id = existing['id'] if existing else 0

        return rule_id

    async def _update_rule(self, rule_id: int, rule_data: Dict):
        """更新规则

        Args:
            rule_id: 规则 ID
            rule_data: 规则数据
        """
        metadata_json = json.dumps(rule_data.get('metadata')) if rule_data.get('metadata') else None

        await self.mysql_service.execute(
            """
            UPDATE rules SET
                gid = %s, rev = %s, action = %s, protocol = %s,
                src_addr = %s, src_port = %s, direction = %s,
                dst_addr = %s, dst_port = %s, msg = %s, content = %s,
                classtype = %s, category = %s, mitre_attack = %s,
                severity = %s, metadata = %s, enabled = TRUE
            WHERE id = %s
            """,
            (
                rule_data.get('gid', 1), rule_data.get('rev', 1),
                rule_data.get('action', 'alert'), rule_data.get('protocol'),
                rule_data.get('src_addr'), rule_data.get('src_port'),
                rule_data.get('direction', '->'), rule_data.get('dst_addr'),
                rule_data.get('dst_port'), rule_data.get('msg'),
                rule_data.get('content'), rule_data.get('classtype'),
                rule_data.get('category'), rule_data.get('mitre_attack'),
                rule_data.get('severity', 3), metadata_json, rule_id
            )
        )

    async def _insert_version_rule(
        self,
        version_id: int,
        rule_id: int,
        change_type: ChangeType,
        previous_content: Optional[str] = None
    ):
        """插入版本规则关联

        Args:
            version_id: 版本 ID
            rule_id: 规则 ID
            change_type: 变更类型
            previous_content: 变更前内容
        """
        await self.mysql_service.execute(
            """
            INSERT INTO rule_version_rules (version_id, rule_id, change_type, previous_content)
            VALUES (%s, %s, %s, %s)
            """,
            (version_id, rule_id, change_type.value, previous_content)
        )

    def _generate_version(self) -> str:
        """生成版本号

        Returns:
            版本号 (格式: vYYYYMMDD.HHMMSS)
        """
        now = datetime.utcnow()
        return f"v{now.strftime('%Y%m%d.%H%M%S')}"

    def _generate_rules_content(self, rules: List[Dict]) -> str:
        """生成规则文件内容

        Args:
            rules: 规则列表

        Returns:
            规则文件内容
        """
        lines = [
            "# AI-IDPS Generated Rules",
            f"# Generated at: {datetime.utcnow().isoformat()}",
            f"# Total rules: {len(rules)}",
            "",
        ]

        for rule in rules:
            content = rule.get('content', '')
            if content:
                lines.append(content)

        return '\n'.join(lines)

    async def _update_cache(self, version: str, content: str):
        """更新缓存

        Args:
            version: 版本号
            content: 规则内容
        """
        if not self.redis_service:
            return

        try:
            # 更新最新版本号
            await self.redis_service.set(RedisKeys.RULE_VERSION_LATEST, version)

            # 缓存规则内容
            await self.redis_service.set(
                RedisKeys.rule_content(version),
                content,
                ex=RedisTTL.RULE_CONTENT
            )
        except Exception as e:
            logger.error(f"Failed to update cache: {e}")

    def _row_to_version(self, row: Dict) -> RuleVersion:
        """数据库行转版本对象

        Args:
            row: 数据库行

        Returns:
            版本对象
        """
        return RuleVersion(
            id=row.get('id'),
            version=row.get('version'),
            content=row.get('content', ''),
            checksum=row.get('checksum', ''),
            description=row.get('description'),
            is_active=row.get('is_active', False),
            created_at=row.get('created_at'),
            rule_count=row.get('rule_count', 0),
            added_count=row.get('added_count', 0),
            modified_count=row.get('modified_count', 0),
            deleted_count=row.get('deleted_count', 0),
        )
