"""攻击测试服务"""

import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.models.attack_test import (
    AttackTest, AttackTestItem, AttackTemplate, TestConfig,
    TestStatus, TestItemStatus, TestType
)
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


class AttackTestService:
    """攻击测试服务"""

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None
    ):
        self.mysql_service = mysql_service
        self.redis_service = redis_service

    # ========== 攻击测试管理 ==========

    async def create_test(
        self,
        name: Optional[str],
        rule_sids: List[int],
        probe_id: str,
        config: Optional[TestConfig] = None
    ) -> AttackTest:
        """创建攻击测试

        Args:
            name: 测试名称
            rule_sids: 要测试的规则 SID 列表
            probe_id: 执行测试的探针 ID
            config: 测试配置

        Returns:
            创建的测试实例
        """
        test_id = f"test_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        test_type = TestType.SINGLE.value if len(rule_sids) == 1 else TestType.BATCH.value
        test_config = config or TestConfig()

        # 创建测试记录
        insert_sql = """
            INSERT INTO attack_tests
            (test_id, name, test_type, status, total_rules, probe_id, config)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        test_db_id = await self.mysql_service.insert(
            insert_sql,
            (
                test_id,
                name or f"测试 {test_id}",
                test_type,
                TestStatus.PENDING.value,
                len(rule_sids),
                probe_id,
                json.dumps(test_config.to_dict())
            )
        )

        # 获取规则信息并创建测试项
        if rule_sids:
            placeholders = ','.join(['%s'] * len(rule_sids))
            rules = await self.mysql_service.fetchall(
                f"""
                SELECT id, sid, protocol, msg, classtype, content
                FROM rules WHERE sid IN ({placeholders}) AND enabled = TRUE
                """,
                tuple(rule_sids)
            )

            for rule in rules:
                # 根据规则生成攻击配置
                attack_config = await self._generate_attack_config(rule, test_config)

                await self.mysql_service.execute(
                    """
                    INSERT INTO attack_test_items
                    (test_id, rule_id, sid, status, attack_type, attack_payload, attack_config)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        test_db_id,
                        rule['id'],
                        rule['sid'],
                        TestItemStatus.PENDING.value,
                        attack_config.get('attack_type', 'http'),
                        attack_config.get('payload', ''),
                        json.dumps(attack_config)
                    )
                )

        # 返回创建的测试
        return AttackTest(
            id=test_db_id,
            test_id=test_id,
            name=name or f"测试 {test_id}",
            test_type=test_type,
            status=TestStatus.PENDING.value,
            total_rules=len(rule_sids),
            probe_id=probe_id,
            config=test_config.to_dict(),
            created_at=datetime.utcnow()
        )

    async def _generate_attack_config(
        self,
        rule: dict,
        config: TestConfig
    ) -> Dict[str, Any]:
        """根据规则生成攻击配置

        Args:
            rule: 规则信息
            config: 测试配置

        Returns:
            攻击配置字典
        """
        protocol = (rule.get('protocol') or 'tcp').lower()
        content = rule.get('content', '')
        classtype = rule.get('classtype', '')

        # 尝试从模板库匹配
        template = await self._find_matching_template(protocol, classtype)

        if template:
            attack_config = {
                'attack_type': template.attack_type,
                'protocol': protocol,
                'template_id': template.id,
                **template.template_config
            }
        else:
            # 默认配置
            attack_config = {
                'attack_type': self._determine_attack_type(protocol),
                'protocol': protocol,
            }

        # 从规则内容提取攻击载荷
        payload = self._extract_payload_from_rule(content, protocol)
        attack_config['payload'] = payload

        # 添加目标配置
        attack_config['target'] = {
            'host': config.target_host or '127.0.0.1',
            'port': config.target_port or self._default_port(protocol),
        }
        attack_config['timeout'] = config.timeout_per_rule

        return attack_config

    async def _find_matching_template(
        self,
        protocol: str,
        classtype: str
    ) -> Optional[AttackTemplate]:
        """查找匹配的攻击模板"""
        # 先按 classtype 精确匹配
        row = await self.mysql_service.fetchone(
            """
            SELECT * FROM attack_templates
            WHERE enabled = TRUE
              AND (protocol = %s OR protocol IS NULL)
              AND classtype = %s
            ORDER BY classtype IS NOT NULL DESC
            LIMIT 1
            """,
            (protocol, classtype)
        )

        if row:
            return AttackTemplate.from_db_row(row)

        # 再按协议匹配
        row = await self.mysql_service.fetchone(
            """
            SELECT * FROM attack_templates
            WHERE enabled = TRUE
              AND (protocol = %s OR protocol IS NULL)
              AND classtype IS NULL
            LIMIT 1
            """,
            (protocol,)
        )

        return AttackTemplate.from_db_row(row) if row else None

    def _determine_attack_type(self, protocol: str) -> str:
        """根据协议确定攻击类型"""
        protocol_map = {
            'http': 'http',
            'https': 'http',
            'tcp': 'tcp',
            'udp': 'udp',
            'dns': 'dns',
            'icmp': 'tcp',
        }
        return protocol_map.get(protocol, 'tcp')

    def _extract_payload_from_rule(self, content: str, protocol: str) -> str:
        """从规则内容提取攻击载荷

        这是简化版，实际应该解析规则的 content、pcre 等字段
        """
        import re

        # 提取 content 字段的内容
        content_matches = re.findall(r'content:\s*"([^"]*)"', content)
        if content_matches:
            # 合并所有 content
            payload = ''.join(content_matches)
            return payload

        # 如果没有 content，使用默认载荷
        default_payloads = {
            'http': 'GET / HTTP/1.1\r\nHost: target\r\n\r\n',
            'dns': '',
            'tcp': 'TEST',
            'udp': 'TEST',
        }
        return default_payloads.get(protocol, 'TEST')

    def _default_port(self, protocol: str) -> int:
        """获取协议的默认端口"""
        port_map = {
            'http': 80,
            'https': 443,
            'dns': 53,
            'smtp': 25,
            'ssh': 22,
            'ftp': 21,
        }
        return port_map.get(protocol, 80)

    async def get_test(self, test_id: str) -> Optional[AttackTest]:
        """获取测试详情

        Args:
            test_id: 测试 ID (字符串 ID，不是数据库 ID)

        Returns:
            测试实例
        """
        row = await self.mysql_service.fetchone(
            "SELECT * FROM attack_tests WHERE test_id = %s",
            (test_id,)
        )
        return AttackTest.from_db_row(row) if row else None

    async def list_tests(
        self,
        status: Optional[str] = None,
        probe_id: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> List[AttackTest]:
        """获取测试列表"""
        conditions = ["1=1"]
        params = []

        if status:
            conditions.append("status = %s")
            params.append(status)

        if probe_id:
            conditions.append("probe_id = %s")
            params.append(probe_id)

        params.extend([limit, offset])

        rows = await self.mysql_service.fetchall(
            f"""
            SELECT * FROM attack_tests
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params)
        )

        return [AttackTest.from_db_row(row) for row in rows] if rows else []

    async def get_test_count(
        self,
        status: Optional[str] = None,
        probe_id: Optional[str] = None
    ) -> int:
        """获取测试总数"""
        conditions = ["1=1"]
        params = []

        if status:
            conditions.append("status = %s")
            params.append(status)

        if probe_id:
            conditions.append("probe_id = %s")
            params.append(probe_id)

        row = await self.mysql_service.fetchone(
            f"SELECT COUNT(*) as count FROM attack_tests WHERE {' AND '.join(conditions)}",
            tuple(params)
        )

        return row['count'] if row else 0

    async def start_test(self, test_id: str) -> bool:
        """启动测试

        Args:
            test_id: 测试 ID

        Returns:
            是否成功
        """
        result = await self.mysql_service.execute(
            """
            UPDATE attack_tests
            SET status = %s, started_at = %s, updated_at = %s
            WHERE test_id = %s AND status = %s
            """,
            (
                TestStatus.RUNNING.value,
                datetime.utcnow(),
                datetime.utcnow(),
                test_id,
                TestStatus.PENDING.value
            )
        )
        return result > 0

    async def cancel_test(self, test_id: str) -> bool:
        """取消测试"""
        result = await self.mysql_service.execute(
            """
            UPDATE attack_tests
            SET status = %s, updated_at = %s
            WHERE test_id = %s AND status IN (%s, %s)
            """,
            (
                TestStatus.CANCELLED.value,
                datetime.utcnow(),
                test_id,
                TestStatus.PENDING.value,
                TestStatus.RUNNING.value
            )
        )
        return result > 0

    async def complete_test(self, test_id: str) -> bool:
        """完成测试"""
        # 计算成功/失败数
        test = await self.get_test(test_id)
        if not test:
            return False

        stats = await self._get_test_stats(test.id)

        result = await self.mysql_service.execute(
            """
            UPDATE attack_tests
            SET status = %s, success_count = %s, failed_count = %s,
                completed_at = %s, updated_at = %s
            WHERE test_id = %s
            """,
            (
                TestStatus.COMPLETED.value,
                stats.get('success', 0),
                stats.get('failed', 0),
                datetime.utcnow(),
                datetime.utcnow(),
                test_id
            )
        )
        return result > 0

    async def _get_test_stats(self, test_db_id: int) -> Dict[str, int]:
        """获取测试统计"""
        rows = await self.mysql_service.fetchall(
            """
            SELECT status, COUNT(*) as count
            FROM attack_test_items
            WHERE test_id = %s
            GROUP BY status
            """,
            (test_db_id,)
        )

        stats = {}
        for row in rows or []:
            status = row['status']
            count = row['count']
            if status == TestItemStatus.SUCCESS.value:
                stats['success'] = count
            elif status in [TestItemStatus.FAILED.value, TestItemStatus.TIMEOUT.value]:
                stats['failed'] = stats.get('failed', 0) + count
            elif status == TestItemStatus.PENDING.value:
                stats['pending'] = count

        return stats

    # ========== 测试项管理 ==========

    async def get_test_items(
        self,
        test_id: str,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AttackTestItem]:
        """获取测试项列表"""
        test = await self.get_test(test_id)
        if not test:
            return []

        conditions = ["test_id = %s"]
        params = [test.id]

        if status:
            conditions.append("status = %s")
            params.append(status)

        params.extend([limit, offset])

        rows = await self.mysql_service.fetchall(
            f"""
            SELECT * FROM attack_test_items
            WHERE {' AND '.join(conditions)}
            ORDER BY id
            LIMIT %s OFFSET %s
            """,
            tuple(params)
        )

        return [AttackTestItem.from_db_row(row) for row in rows] if rows else []

    async def get_pending_items(self, test_id: str, limit: int = 10) -> List[AttackTestItem]:
        """获取待执行的测试项"""
        test = await self.get_test(test_id)
        if not test:
            return []

        rows = await self.mysql_service.fetchall(
            """
            SELECT * FROM attack_test_items
            WHERE test_id = %s AND status = %s
            ORDER BY id
            LIMIT %s
            """,
            (test.id, TestItemStatus.PENDING.value, limit)
        )

        return [AttackTestItem.from_db_row(row) for row in rows] if rows else []

    async def update_test_item(
        self,
        item_id: int,
        status: str,
        result: Optional[Dict[str, Any]] = None,
        matched_log_id: Optional[str] = None,
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None
    ) -> bool:
        """更新测试项状态"""
        update_fields = ["status = %s", "updated_at = %s"]
        params = [status, datetime.utcnow()]

        if status in [TestItemStatus.SUCCESS.value, TestItemStatus.FAILED.value, TestItemStatus.TIMEOUT.value]:
            update_fields.append("executed_at = %s")
            params.append(datetime.utcnow())

        if result is not None:
            update_fields.append("attack_result = %s")
            params.append(json.dumps(result))

        if matched_log_id is not None:
            update_fields.append("matched_log_id = %s")
            params.append(matched_log_id)

        if response_time_ms is not None:
            update_fields.append("response_time_ms = %s")
            params.append(response_time_ms)

        if error_message is not None:
            update_fields.append("error_message = %s")
            params.append(error_message)

        params.append(item_id)

        result = await self.mysql_service.execute(
            f"UPDATE attack_test_items SET {', '.join(update_fields)} WHERE id = %s",
            tuple(params)
        )
        return result > 0

    # ========== 攻击模板管理 ==========

    async def list_templates(
        self,
        protocol: Optional[str] = None,
        attack_type: Optional[str] = None
    ) -> List[AttackTemplate]:
        """获取攻击模板列表"""
        conditions = ["enabled = TRUE"]
        params = []

        if protocol:
            conditions.append("(protocol = %s OR protocol IS NULL)")
            params.append(protocol)

        if attack_type:
            conditions.append("attack_type = %s")
            params.append(attack_type)

        rows = await self.mysql_service.fetchall(
            f"""
            SELECT * FROM attack_templates
            WHERE {' AND '.join(conditions)}
            ORDER BY name
            """,
            tuple(params)
        )

        return [AttackTemplate.from_db_row(row) for row in rows] if rows else []

    async def create_template(
        self,
        name: str,
        attack_type: str,
        template_config: Dict[str, Any],
        protocol: Optional[str] = None,
        description: Optional[str] = None,
        classtype: Optional[str] = None
    ) -> AttackTemplate:
        """创建攻击模板"""
        template_id = await self.mysql_service.execute(
            """
            INSERT INTO attack_templates
            (name, attack_type, protocol, template_config, description, classtype)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                name,
                attack_type,
                protocol,
                json.dumps(template_config),
                description,
                classtype
            )
        )

        return AttackTemplate(
            id=template_id,
            name=name,
            attack_type=attack_type,
            protocol=protocol,
            template_config=template_config,
            description=description,
            classtype=classtype,
            created_at=datetime.utcnow()
        )
