"""探针规则服务 - 处理探针规则同步 (Pull模式)"""

import hashlib
import logging
from typing import Optional, Dict, List
from datetime import datetime

from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.services.rule_version_service import RuleVersionService
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


class ProbeRuleService:
    """探针规则服务"""

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None,
        rule_version_service: Optional[RuleVersionService] = None
    ):
        """初始化服务

        Args:
            mysql_service: MySQL 服务实例
            redis_service: Redis 服务实例
            rule_version_service: 规则版本服务实例
        """
        self.mysql_service = mysql_service
        self.redis_service = redis_service
        self.rule_version_service = rule_version_service

    async def get_latest_version(self) -> Optional[str]:
        """获取最新规则版本号

        Returns:
            最新版本号
        """
        # 先查缓存
        if self.redis_service:
            cached = await self.redis_service.get(RedisKeys.RULE_VERSION_LATEST)
            if cached:
                return cached

        # 查数据库
        row = await self.mysql_service.fetchone(
            "SELECT version FROM rule_versions WHERE is_active = TRUE LIMIT 1"
        )

        if row:
            version = row['version']
            # 更新缓存
            if self.redis_service:
                await self.redis_service.set(RedisKeys.RULE_VERSION_LATEST, version)
            return version

        return None

    async def check_version(self, probe_id: str, current_version: Optional[str]) -> Dict:
        """检查探针规则版本

        Args:
            probe_id: 探针 ID
            current_version: 探针当前版本

        Returns:
            版本检查结果
        """
        latest_version = await self.get_latest_version()

        result = {
            'latest_version': latest_version,
            'current_version': current_version,
            'needs_update': False,
            'server_time': datetime.utcnow().isoformat(),
        }

        if latest_version and latest_version != current_version:
            result['needs_update'] = True

        return result

    async def get_rules_content(
        self,
        version: Optional[str] = None,
        probe_id: Optional[str] = None
    ) -> Optional[Dict]:
        """获取规则内容

        Args:
            version: 指定版本号（None 表示最新版本）
            probe_id: 探针 ID（用于日志）

        Returns:
            规则内容字典
        """
        # 确定目标版本
        if version:
            target_version = version
        else:
            target_version = await self.get_latest_version()

        if not target_version:
            logger.warning(f"No rule version available for probe {probe_id}")
            return None

        # 先查缓存
        if self.redis_service:
            cached = await self.redis_service.get(
                RedisKeys.rule_content(target_version)
            )
            if cached:
                return {
                    'version': target_version,
                    'content': cached,
                    'checksum': hashlib.sha256(cached.encode()).hexdigest(),
                    'from_cache': True,
                }

        # 查数据库
        row = await self.mysql_service.fetchone(
            "SELECT version, content, checksum FROM rule_versions WHERE version = %s",
            (target_version,)
        )

        if not row:
            logger.warning(f"Rule version {target_version} not found")
            return None

        content = row['content']

        # 更新缓存
        if self.redis_service:
            await self.redis_service.set(
                RedisKeys.rule_content(target_version),
                content,
                ex=RedisTTL.RULE_CONTENT
            )

        return {
            'version': row['version'],
            'content': content,
            'checksum': row['checksum'],
            'from_cache': False,
        }

    async def get_rules_delta(
        self,
        probe_id: str,
        from_version: str,
        to_version: Optional[str] = None
    ) -> Optional[Dict]:
        """获取增量规则更新

        Args:
            probe_id: 探针 ID
            from_version: 起始版本
            to_version: 目标版本（None 表示最新版本）

        Returns:
            增量更新数据
        """
        if not to_version:
            to_version = await self.get_latest_version()

        if not to_version or from_version == to_version:
            return {'has_changes': False, 'version': to_version}

        # 获取版本差异
        if self.rule_version_service:
            diff = await self.rule_version_service.get_version_diff(from_version, to_version)
        else:
            diff = None

        # 获取目标版本内容
        content_result = await self.get_rules_content(to_version, probe_id)

        if not content_result:
            return None

        return {
            'has_changes': True,
            'from_version': from_version,
            'to_version': to_version,
            'content': content_result['content'],
            'checksum': content_result['checksum'],
            'diff': diff,
        }

    async def record_probe_version(
        self,
        probe_id: str,
        version: str,
        update_time: Optional[datetime] = None
    ):
        """记录探针规则版本

        Args:
            probe_id: 探针 ID
            version: 规则版本
            update_time: 更新时间
        """
        try:
            await self.mysql_service.execute(
                """
                UPDATE probe_nodes
                SET current_rule_version = %s, updated_at = %s
                WHERE node_id = %s
                """,
                (version, update_time or datetime.utcnow(), probe_id)
            )

            # 更新缓存
            if self.redis_service:
                await self.redis_service.hset(
                    RedisKeys.probe_status(probe_id),
                    mapping={
                        'current_rule_version': version,
                        'rule_updated_at': (update_time or datetime.utcnow()).isoformat()
                    }
                )

            logger.info(f"Probe {probe_id} updated to rule version {version}")

        except Exception as e:
            logger.error(f"Failed to record probe version: {e}")

    async def get_probes_by_version(self, version: str) -> List[Dict]:
        """获取使用指定版本的探针列表

        Args:
            version: 规则版本

        Returns:
            探针列表
        """
        rows = await self.mysql_service.fetchall(
            """
            SELECT node_id, name, ip_address, status, last_seen
            FROM probe_nodes
            WHERE current_rule_version = %s
            """,
            (version,)
        )

        return [dict(row) for row in rows] if rows else []

    async def get_version_distribution(self) -> Dict[str, int]:
        """获取规则版本分布

        Returns:
            version -> probe_count 字典
        """
        rows = await self.mysql_service.fetchall(
            """
            SELECT current_rule_version as version, COUNT(*) as count
            FROM probe_nodes
            WHERE current_rule_version IS NOT NULL
            GROUP BY current_rule_version
            ORDER BY count DESC
            """
        )

        return {row['version']: row['count'] for row in rows} if rows else {}

    async def get_outdated_probes(self) -> List[Dict]:
        """获取规则版本过期的探针

        Returns:
            过期探针列表
        """
        latest_version = await self.get_latest_version()
        if not latest_version:
            return []

        rows = await self.mysql_service.fetchall(
            """
            SELECT node_id, name, ip_address, status, last_seen, current_rule_version
            FROM probe_nodes
            WHERE current_rule_version IS NULL
               OR current_rule_version != %s
            ORDER BY last_seen DESC
            """,
            (latest_version,)
        )

        return [dict(row) for row in rows] if rows else []
