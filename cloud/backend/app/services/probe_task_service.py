"""探针任务服务 - Pull 模式任务分发"""

import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.services.clickhouse_service import clickhouse_service
from app.models.probe_task import (
    ProbeTask, TaskType, TaskStatus, AttackTaskPayload, TaskResult
)
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


class ProbeTaskService:
    """探针任务服务

    实现 Pull 模式的任务分发：
    1. 探针定期轮询获取任务
    2. 任务按优先级排序
    3. 支持任务超时和重试
    """

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None
    ):
        self.mysql_service = mysql_service
        self.redis_service = redis_service
        self.default_task_ttl = 3600  # 任务默认 1 小时过期

    # ========== 任务创建 ==========

    async def create_attack_task(
        self,
        test_id: str,
        test_item_id: int,
        rule_sid: int,
        probe_id: str,
        attack_config: Dict[str, Any],
        priority: int = 5,
        timeout: int = 60
    ) -> ProbeTask:
        """创建攻击测试任务

        Args:
            test_id: 测试 ID
            test_item_id: 测试项 ID
            rule_sid: 规则 SID
            probe_id: 目标探针 ID
            attack_config: 攻击配置
            priority: 优先级 (1-10, 1最高)
            timeout: 任务超时时间(秒)

        Returns:
            创建的任务
        """
        task_id = f"task_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
        expire_at = datetime.utcnow() + timedelta(seconds=self.default_task_ttl)

        payload = AttackTaskPayload(
            test_id=test_id,
            test_item_id=test_item_id,
            rule_sid=rule_sid,
            attack_type=attack_config.get('attack_type', 'http'),
            attack_payload=attack_config.get('payload', ''),
            target=attack_config.get('target', {}),
            timeout=timeout
        )

        task_db_id = await self.mysql_service.execute(
            """
            INSERT INTO probe_tasks
            (task_id, task_type, probe_id, status, priority, payload, expire_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                task_id,
                TaskType.ATTACK.value,
                probe_id,
                TaskStatus.PENDING.value,
                priority,
                json.dumps(payload.to_dict()),
                expire_at
            )
        )

        task = ProbeTask(
            id=task_db_id,
            task_id=task_id,
            task_type=TaskType.ATTACK.value,
            probe_id=probe_id,
            status=TaskStatus.PENDING.value,
            priority=priority,
            payload=payload.to_dict(),
            expire_at=expire_at,
            created_at=datetime.utcnow()
        )

        # 缓存任务到 Redis (用于快速查询)
        if self.redis_service:
            await self._cache_task(task)

        return task

    async def create_batch_attack_tasks(
        self,
        test_id: str,
        test_items: List[Dict[str, Any]],
        probe_id: str,
        priority: int = 5
    ) -> List[ProbeTask]:
        """批量创建攻击任务

        Args:
            test_id: 测试 ID
            test_items: 测试项列表，包含 id, sid, attack_config
            probe_id: 目标探针 ID
            priority: 优先级

        Returns:
            创建的任务列表
        """
        tasks = []
        for item in test_items:
            task = await self.create_attack_task(
                test_id=test_id,
                test_item_id=item['id'],
                rule_sid=item['sid'],
                probe_id=probe_id,
                attack_config=item.get('attack_config', {}),
                priority=priority,
                timeout=item.get('timeout', 60)
            )
            tasks.append(task)

        return tasks

    # ========== 任务获取 (Pull 模式) ==========

    async def get_pending_tasks(
        self,
        probe_id: str,
        limit: int = 10
    ) -> List[ProbeTask]:
        """获取探针待执行任务 (Pull 模式核心接口)

        探针定期调用此接口获取分配给自己的任务

        Args:
            probe_id: 探针 ID
            limit: 获取数量限制

        Returns:
            任务列表
        """
        # 先检查并过期旧任务
        await self._expire_old_tasks()

        # 获取待执行任务，按优先级排序
        rows = await self.mysql_service.fetchall(
            """
            SELECT * FROM probe_tasks
            WHERE probe_id = %s
              AND status = %s
              AND (expire_at IS NULL OR expire_at > %s)
            ORDER BY priority ASC, created_at ASC
            LIMIT %s
            """,
            (probe_id, TaskStatus.PENDING.value, datetime.utcnow(), limit)
        )

        tasks = [ProbeTask.from_db_row(row) for row in rows] if rows else []

        # 标记任务为已分配
        for task in tasks:
            await self._assign_task(task.task_id)

        return tasks

    async def _assign_task(self, task_id: str):
        """标记任务为已分配"""
        await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, assigned_at = %s, updated_at = %s
            WHERE task_id = %s AND status = %s
            """,
            (
                TaskStatus.ASSIGNED.value,
                datetime.utcnow(),
                datetime.utcnow(),
                task_id,
                TaskStatus.PENDING.value
            )
        )

    async def _expire_old_tasks(self):
        """过期超时任务"""
        await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, updated_at = %s
            WHERE status IN (%s, %s)
              AND expire_at IS NOT NULL
              AND expire_at < %s
            """,
            (
                TaskStatus.EXPIRED.value,
                datetime.utcnow(),
                TaskStatus.PENDING.value,
                TaskStatus.ASSIGNED.value,
                datetime.utcnow()
            )
        )

    # ========== 任务结果处理 ==========

    async def report_task_result(
        self,
        task_id: str,
        result: TaskResult
    ) -> bool:
        """上报任务执行结果

        Args:
            task_id: 任务 ID
            result: 执行结果

        Returns:
            是否成功
        """
        status = TaskStatus.COMPLETED.value if result.success else TaskStatus.FAILED.value

        affected = await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, result = %s, completed_at = %s, updated_at = %s
            WHERE task_id = %s AND status IN (%s, %s)
            """,
            (
                status,
                json.dumps(result.to_dict()),
                datetime.utcnow(),
                datetime.utcnow(),
                task_id,
                TaskStatus.ASSIGNED.value,
                TaskStatus.RUNNING.value
            )
        )

        if affected > 0:
            # 清除缓存
            if self.redis_service:
                await self._remove_task_cache(task_id)

            # 更新关联的测试项
            await self._update_test_item_from_result(task_id, result)

        return affected > 0

    async def _update_test_item_from_result(
        self,
        task_id: str,
        result: TaskResult
    ):
        """根据任务结果更新测试项，并关联匹配的告警日志"""
        # 获取任务信息
        task_row = await self.mysql_service.fetchone(
            "SELECT payload, probe_id, started_at FROM probe_tasks WHERE task_id = %s",
            (task_id,)
        )

        if not task_row:
            return

        payload = task_row.get('payload')
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except:
                return

        test_item_id = payload.get('test_item_id')
        test_id = payload.get('test_id')
        rule_sid = payload.get('rule_sid')
        probe_id = task_row.get('probe_id')
        started_at = task_row.get('started_at')
        
        if not test_item_id:
            return

        # 确定测试项状态
        if result.success:
            item_status = 'success'
        elif result.error and 'timeout' in result.error.lower():
            item_status = 'timeout'
        else:
            item_status = 'failed'

        matched_log_id = None
        
        # 如果测试成功，尝试查找匹配的告警日志
        if result.success and rule_sid and probe_id:
            try:
                # 定义时间窗口：从任务开始到现在，加上一些缓冲时间
                start_time = started_at or (datetime.utcnow() - timedelta(minutes=5))
                end_time = datetime.utcnow() + timedelta(seconds=30)
                
                # 查找匹配的告警日志
                matching_alert = await clickhouse_service.find_matching_alert(
                    probe_id=probe_id,
                    signature_id=rule_sid,
                    start_time=start_time,
                    end_time=end_time
                )
                
                if matching_alert:
                    matched_log_id = str(matching_alert.get('id', ''))
                    logger.info(f"Found matching alert for test item {test_item_id}: log_id={matched_log_id}")
                    
                    # 更新告警日志的测试关联信息
                    if matched_log_id and test_id:
                        await clickhouse_service.update_alert_test_info(
                            log_id=matched_log_id,
                            test_id=test_id,
                            test_item_id=test_item_id
                        )
                else:
                    logger.warning(f"No matching alert found for test item {test_item_id}, sid={rule_sid}")
            except Exception as e:
                logger.error(f"Error finding matching alert: {e}")

        # 更新测试项
        await self.mysql_service.execute(
            """
            UPDATE attack_test_items
            SET status = %s,
                attack_result = %s,
                response_time_ms = %s,
                error_message = %s,
                matched_log_id = %s,
                executed_at = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (
                item_status,
                json.dumps(result.data) if result.data else None,
                result.response_time_ms,
                result.error,
                matched_log_id,
                result.executed_at or datetime.utcnow(),
                datetime.utcnow(),
                test_item_id
            )
        )
        
        # 检查并更新测试整体状态
        await self._check_and_update_test_status(test_id)

    async def _check_and_update_test_status(self, test_id: str):
        """检查并更新测试整体状态
        
        当所有测试项都已完成时，自动将测试状态更新为 completed
        """
        if not test_id:
            return
            
        try:
            # 获取测试信息
            test_row = await self.mysql_service.fetchone(
                "SELECT id, status, total_rules FROM attack_tests WHERE test_id = %s",
                (test_id,)
            )
            
            if not test_row or test_row.get('status') != 'running':
                return
            
            test_db_id = test_row.get('id')
            total_rules = test_row.get('total_rules', 0)
            
            # 统计已完成的测试项
            stats_row = await self.mysql_service.fetchone(
                """
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as success_count,
                    SUM(CASE WHEN status IN ('failed', 'timeout') THEN 1 ELSE 0 END) as failed_count,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count
                FROM attack_test_items
                WHERE test_id = %s
                """,
                (test_db_id,)
            )
            
            if not stats_row:
                return
                
            success_count = int(stats_row.get('success_count', 0) or 0)
            failed_count = int(stats_row.get('failed_count', 0) or 0)
            pending_count = int(stats_row.get('pending_count', 0) or 0)
            
            # 如果没有待处理的测试项，则测试完成
            if pending_count == 0:
                await self.mysql_service.execute(
                    """
                    UPDATE attack_tests
                    SET status = 'completed',
                        success_count = %s,
                        failed_count = %s,
                        completed_at = %s,
                        updated_at = %s
                    WHERE test_id = %s
                    """,
                    (
                        success_count,
                        failed_count,
                        datetime.utcnow(),
                        datetime.utcnow(),
                        test_id
                    )
                )
                logger.info(f"Test {test_id} completed: success={success_count}, failed={failed_count}")
            else:
                # 更新成功/失败计数
                await self.mysql_service.execute(
                    """
                    UPDATE attack_tests
                    SET success_count = %s,
                        failed_count = %s,
                        updated_at = %s
                    WHERE test_id = %s
                    """,
                    (
                        success_count,
                        failed_count,
                        datetime.utcnow(),
                        test_id
                    )
                )
        except Exception as e:
            logger.error(f"Error checking test status: {e}")

    async def start_task(self, task_id: str) -> bool:
        """标记任务开始执行"""
        affected = await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, started_at = %s, updated_at = %s
            WHERE task_id = %s AND status = %s
            """,
            (
                TaskStatus.RUNNING.value,
                datetime.utcnow(),
                datetime.utcnow(),
                task_id,
                TaskStatus.ASSIGNED.value
            )
        )
        return affected > 0

    # ========== 任务查询 ==========

    async def get_task(self, task_id: str) -> Optional[ProbeTask]:
        """获取任务详情"""
        row = await self.mysql_service.fetchone(
            "SELECT * FROM probe_tasks WHERE task_id = %s",
            (task_id,)
        )
        return ProbeTask.from_db_row(row) if row else None

    async def list_tasks(
        self,
        probe_id: Optional[str] = None,
        task_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> List[ProbeTask]:
        """获取任务列表"""
        conditions = ["1=1"]
        params = []

        if probe_id:
            conditions.append("probe_id = %s")
            params.append(probe_id)

        if task_type:
            conditions.append("task_type = %s")
            params.append(task_type)

        if status:
            conditions.append("status = %s")
            params.append(status)

        params.extend([limit, offset])

        rows = await self.mysql_service.fetchall(
            f"""
            SELECT * FROM probe_tasks
            WHERE {' AND '.join(conditions)}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            tuple(params)
        )

        return [ProbeTask.from_db_row(row) for row in rows] if rows else []

    async def get_task_stats(self, probe_id: Optional[str] = None) -> Dict[str, int]:
        """获取任务统计"""
        condition = "WHERE probe_id = %s" if probe_id else ""
        params = (probe_id,) if probe_id else ()

        rows = await self.mysql_service.fetchall(
            f"""
            SELECT status, COUNT(*) as count
            FROM probe_tasks
            {condition}
            GROUP BY status
            """,
            params
        )

        return {row['status']: row['count'] for row in rows} if rows else {}

    # ========== 缓存操作 ==========

    async def _cache_task(self, task: ProbeTask):
        """缓存任务到 Redis"""
        if not self.redis_service:
            return

        # 添加到探针的待处理任务列表
        await self.redis_service.rpush(
            RedisKeys.probe_pending_tasks(task.probe_id),
            task.task_id
        )
        await self.redis_service.expire(
            RedisKeys.probe_pending_tasks(task.probe_id),
            RedisTTL.TASK_CACHE
        )

        # 缓存任务详情
        await self.redis_service.set(
            RedisKeys.task_detail(task.task_id),
            json.dumps(task.to_dict()),
            ex=RedisTTL.TASK_CACHE
        )

    async def _remove_task_cache(self, task_id: str):
        """移除任务缓存"""
        if not self.redis_service:
            return

        await self.redis_service.delete(RedisKeys.task_detail(task_id))

    async def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        affected = await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, updated_at = %s
            WHERE task_id = %s AND status IN (%s, %s)
            """,
            (
                TaskStatus.CANCELLED.value,
                datetime.utcnow(),
                task_id,
                TaskStatus.PENDING.value,
                TaskStatus.ASSIGNED.value
            )
        )

        if affected > 0 and self.redis_service:
            await self._remove_task_cache(task_id)

        return affected > 0

    async def retry_task(self, task_id: str) -> bool:
        """重试失败的任务"""
        task = await self.get_task(task_id)
        if not task or not task.can_retry:
            return False

        affected = await self.mysql_service.execute(
            """
            UPDATE probe_tasks
            SET status = %s, retry_count = retry_count + 1, updated_at = %s
            WHERE task_id = %s AND status IN (%s, %s)
            """,
            (
                TaskStatus.PENDING.value,
                datetime.utcnow(),
                task_id,
                TaskStatus.FAILED.value,
                TaskStatus.EXPIRED.value
            )
        )

        return affected > 0
