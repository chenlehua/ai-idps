"""规则分类服务"""

import json
import logging
from typing import List, Dict, Optional
from collections import defaultdict

from app.models.rule_category import RuleCategory, CategoryType, CategoryStats
from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


class RuleCategoryService:
    """规则分类服务"""

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None
    ):
        """初始化分类服务

        Args:
            mysql_service: MySQL 服务实例
            redis_service: Redis 服务实例
        """
        self.mysql_service = mysql_service
        self.redis_service = redis_service

    async def get_all_categories(self) -> Dict[str, List[CategoryStats]]:
        """获取所有分类统计

        Returns:
            按类型分组的分类统计
        """
        # 先查缓存
        if self.redis_service:
            cached = await self._get_cached_categories()
            if cached:
                return cached

        # 查数据库
        stats = await self._calculate_category_stats()

        # 更新缓存
        if self.redis_service:
            await self._cache_categories(stats)

        return stats

    async def get_categories_by_type(self, category_type: str) -> List[CategoryStats]:
        """按类型获取分类

        Args:
            category_type: 分类类型

        Returns:
            分类列表
        """
        all_categories = await self.get_all_categories()
        return all_categories.get(category_type, [])

    async def update_category_counts(self):
        """更新分类计数 (从规则表重新统计)"""
        try:
            # 统计 classtype
            classtype_counts = await self.mysql_service.fetchall(
                """
                SELECT classtype as name, COUNT(*) as count,
                       SUM(CASE WHEN enabled = TRUE THEN 1 ELSE 0 END) as enabled_count
                FROM rules
                WHERE classtype IS NOT NULL AND classtype != ''
                GROUP BY classtype
                ORDER BY count DESC
                """
            )

            # 统计 category (msg前缀)
            category_counts = await self.mysql_service.fetchall(
                """
                SELECT category as name, COUNT(*) as count,
                       SUM(CASE WHEN enabled = TRUE THEN 1 ELSE 0 END) as enabled_count
                FROM rules
                WHERE category IS NOT NULL AND category != ''
                GROUP BY category
                ORDER BY count DESC
                """
            )

            # 更新 rule_categories 表
            await self._update_category_table(CategoryType.CLASSTYPE.value, classtype_counts or [])
            await self._update_category_table(CategoryType.MSG_PREFIX.value, category_counts or [])

            # 清除缓存
            if self.redis_service:
                await self.redis_service.delete(RedisKeys.RULE_CATEGORIES)

            logger.info("Category counts updated successfully")

        except Exception as e:
            logger.error(f"Failed to update category counts: {e}")
            raise

    async def get_category_by_name(
        self,
        category_type: str,
        category_name: str
    ) -> Optional[RuleCategory]:
        """按名称获取分类

        Args:
            category_type: 分类类型
            category_name: 分类名称

        Returns:
            分类对象
        """
        row = await self.mysql_service.fetchone(
            """
            SELECT * FROM rule_categories
            WHERE category_type = %s AND category_name = %s
            """,
            (category_type, category_name)
        )
        return RuleCategory.from_db_row(row) if row else None

    async def create_category(
        self,
        category_type: str,
        category_name: str,
        description: Optional[str] = None
    ) -> RuleCategory:
        """创建分类

        Args:
            category_type: 分类类型
            category_name: 分类名称
            description: 描述

        Returns:
            创建的分类
        """
        await self.mysql_service.execute(
            """
            INSERT INTO rule_categories (category_type, category_name, description)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE description = VALUES(description)
            """,
            (category_type, category_name, description)
        )

        return await self.get_category_by_name(category_type, category_name)

    async def get_rules_by_category(
        self,
        category_type: str,
        category_name: str,
        limit: int = 100,
        offset: int = 0,
        enabled_only: bool = True
    ) -> List[Dict]:
        """获取分类下的规则

        Args:
            category_type: 分类类型
            category_name: 分类名称
            limit: 返回数量
            offset: 偏移量
            enabled_only: 是否只返回启用的规则

        Returns:
            规则列表
        """
        if category_type == CategoryType.CLASSTYPE.value:
            field = 'classtype'
        else:
            field = 'category'

        query = f"""
            SELECT id, sid, gid, rev, action, protocol, msg, classtype,
                   category, severity, enabled, created_at
            FROM rules
            WHERE {field} = %s
        """
        params = [category_name]

        if enabled_only:
            query += " AND enabled = TRUE"

        query += " ORDER BY sid LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        rows = await self.mysql_service.fetchall(query, tuple(params))
        return [dict(row) for row in rows] if rows else []

    async def get_severity_stats(self) -> Dict[int, int]:
        """获取严重级别统计

        Returns:
            severity -> count 字典
        """
        rows = await self.mysql_service.fetchall(
            """
            SELECT severity, COUNT(*) as count
            FROM rules
            WHERE enabled = TRUE
            GROUP BY severity
            ORDER BY severity
            """
        )

        return {row['severity']: row['count'] for row in rows} if rows else {}

    async def get_protocol_stats(self) -> Dict[str, int]:
        """获取协议统计

        Returns:
            protocol -> count 字典
        """
        rows = await self.mysql_service.fetchall(
            """
            SELECT protocol, COUNT(*) as count
            FROM rules
            WHERE enabled = TRUE AND protocol IS NOT NULL
            GROUP BY protocol
            ORDER BY count DESC
            """
        )

        return {row['protocol']: row['count'] for row in rows} if rows else {}

    async def _calculate_category_stats(self) -> Dict[str, List[CategoryStats]]:
        """计算分类统计

        Returns:
            分类统计字典
        """
        result = {
            CategoryType.CLASSTYPE.value: [],
            CategoryType.MSG_PREFIX.value: [],
        }

        # 统计 classtype
        classtype_rows = await self.mysql_service.fetchall(
            """
            SELECT classtype as name, COUNT(*) as total,
                   SUM(CASE WHEN enabled = TRUE THEN 1 ELSE 0 END) as enabled_count
            FROM rules
            WHERE classtype IS NOT NULL AND classtype != ''
            GROUP BY classtype
            ORDER BY total DESC
            """
        )

        if classtype_rows:
            for row in classtype_rows:
                result[CategoryType.CLASSTYPE.value].append(
                    CategoryStats(
                        category_type=CategoryType.CLASSTYPE.value,
                        category_name=row['name'],
                        rule_count=row['total'],
                        enabled_count=row['enabled_count'] or 0
                    )
                )

        # 统计 category
        category_rows = await self.mysql_service.fetchall(
            """
            SELECT category as name, COUNT(*) as total,
                   SUM(CASE WHEN enabled = TRUE THEN 1 ELSE 0 END) as enabled_count
            FROM rules
            WHERE category IS NOT NULL AND category != ''
            GROUP BY category
            ORDER BY total DESC
            """
        )

        if category_rows:
            for row in category_rows:
                result[CategoryType.MSG_PREFIX.value].append(
                    CategoryStats(
                        category_type=CategoryType.MSG_PREFIX.value,
                        category_name=row['name'],
                        rule_count=row['total'],
                        enabled_count=row['enabled_count'] or 0
                    )
                )

        return result

    async def _update_category_table(self, category_type: str, counts: List[Dict]):
        """更新分类表

        Args:
            category_type: 分类类型
            counts: 计数列表
        """
        for item in counts:
            name = item.get('name')
            count = item.get('count', 0)

            if not name:
                continue

            await self.mysql_service.execute(
                """
                INSERT INTO rule_categories (category_type, category_name, rule_count)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE rule_count = %s
                """,
                (category_type, name, count, count)
            )

    async def _get_cached_categories(self) -> Optional[Dict[str, List[CategoryStats]]]:
        """获取缓存的分类

        Returns:
            缓存的分类数据
        """
        try:
            data = await self.redis_service.hgetall(RedisKeys.RULE_CATEGORIES)
            if not data:
                return None

            result = {}
            for key, value in data.items():
                stats_list = json.loads(value)
                result[key] = [
                    CategoryStats(
                        category_type=s['category_type'],
                        category_name=s['category_name'],
                        rule_count=s['rule_count'],
                        enabled_count=s.get('enabled_count', 0)
                    )
                    for s in stats_list
                ]

            return result

        except Exception as e:
            logger.error(f"Failed to get cached categories: {e}")
            return None

    async def _cache_categories(self, stats: Dict[str, List[CategoryStats]]):
        """缓存分类统计

        Args:
            stats: 分类统计
        """
        try:
            mapping = {
                key: json.dumps([s.to_dict() for s in value], ensure_ascii=False)
                for key, value in stats.items()
            }

            await self.redis_service.hset(RedisKeys.RULE_CATEGORIES, mapping=mapping)
            await self.redis_service.expire(RedisKeys.RULE_CATEGORIES, RedisTTL.RULE_CATEGORIES)

        except Exception as e:
            logger.error(f"Failed to cache categories: {e}")
