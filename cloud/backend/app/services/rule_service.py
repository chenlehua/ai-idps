import hashlib
from typing import Optional, List, Dict
from datetime import datetime

from app.services.redis_service import redis_service
from app.services.mysql_service import mysql_service


class RuleService:
    async def get_latest_version(self) -> Optional[str]:
        """获取最新规则版本号"""
        # 先查缓存
        version = await redis_service.get_latest_rule_version()
        if version:
            return version

        # 缓存未命中，查数据库
        result = await mysql_service.fetchone(
            "SELECT version FROM rule_versions WHERE is_active = TRUE ORDER BY id DESC LIMIT 1"
        )
        if result:
            version = result['version']
            await redis_service.set_latest_rule_version(version)
            return version
        return None

    async def get_rule_by_version(self, version: str) -> Optional[Dict]:
        """获取指定版本规则"""
        # 先查缓存
        content = await redis_service.get_rule_content(version)
        if content:
            return {
                "version": version,
                "content": content,
                "checksum": self._checksum(content)
            }

        # 缓存未命中，查数据库
        result = await mysql_service.fetchone(
            "SELECT version, content, checksum FROM rule_versions WHERE version = %s",
            (version,)
        )
        if result:
            await redis_service.set_rule_content(version, result['content'])
            return dict(result)
        return None

    async def create_rule_version(self, content: str, description: str = "") -> Dict:
        """创建新规则版本"""
        version = f"v{int(datetime.utcnow().timestamp())}"
        checksum = self._checksum(content)
        now = datetime.utcnow()

        # 将之前的版本设为非活跃
        await mysql_service.execute(
            "UPDATE rule_versions SET is_active = FALSE WHERE is_active = TRUE"
        )

        # 插入新版本
        await mysql_service.execute(
            """INSERT INTO rule_versions (version, content, checksum, description, is_active, created_at)
               VALUES (%s, %s, %s, %s, TRUE, %s)""",
            (version, content, checksum, description, now)
        )

        # 更新缓存
        await redis_service.set_latest_rule_version(version)
        await redis_service.set_rule_content(version, content)

        return {"version": version, "checksum": checksum}

    async def list_versions(self, limit: int = 20) -> List[Dict]:
        """获取规则版本列表"""
        results = await mysql_service.fetchall(
            """SELECT id, version, checksum, description, is_active, created_at
               FROM rule_versions ORDER BY id DESC LIMIT %s""",
            (limit,)
        )

        versions = []
        for row in results:
            row_dict = dict(row)
            if row_dict.get('created_at'):
                row_dict['created_at'] = row_dict['created_at'].isoformat()
            versions.append(row_dict)

        return versions

    def _checksum(self, content: str) -> str:
        """计算内容校验和"""
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"


rule_service = RuleService()
