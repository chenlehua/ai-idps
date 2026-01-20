"""探针任务模型"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class TaskType(str, Enum):
    """任务类型"""
    ATTACK = "attack"
    RULE_UPDATE = "rule_update"


class TaskStatus(str, Enum):
    """任务状态"""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


@dataclass
class ProbeTask:
    """探针任务"""
    id: Optional[int] = None
    task_id: str = ""
    task_type: str = "attack"
    probe_id: Optional[str] = None
    status: str = "pending"
    priority: int = 5
    payload: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    max_retries: int = 3
    assigned_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expire_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "ProbeTask":
        """从数据库行创建实例"""
        import json

        payload = row.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                payload = {}

        result = row.get("result")
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                result = None

        return cls(
            id=row.get("id"),
            task_id=row.get("task_id", ""),
            task_type=row.get("task_type", "attack"),
            probe_id=row.get("probe_id"),
            status=row.get("status", "pending"),
            priority=row.get("priority", 5),
            payload=payload or {},
            result=result,
            retry_count=row.get("retry_count", 0),
            max_retries=row.get("max_retries", 3),
            assigned_at=row.get("assigned_at"),
            started_at=row.get("started_at"),
            completed_at=row.get("completed_at"),
            expire_at=row.get("expire_at"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "task_id": self.task_id,
            "task_type": self.task_type,
            "probe_id": self.probe_id,
            "status": self.status,
            "priority": self.priority,
            "payload": self.payload,
            "result": self.result,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "expire_at": self.expire_at.isoformat() if self.expire_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_probe_response(self) -> dict:
        """转换为探针响应格式"""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "priority": self.priority,
            "payload": self.payload,
            "expire_at": self.expire_at.isoformat() if self.expire_at else None,
        }

    @property
    def is_expired(self) -> bool:
        """是否已过期"""
        if self.expire_at is None:
            return False
        return datetime.utcnow() > self.expire_at

    @property
    def can_retry(self) -> bool:
        """是否可以重试"""
        return self.retry_count < self.max_retries


@dataclass
class AttackTaskPayload:
    """攻击任务载荷"""
    test_id: str = ""
    test_item_id: int = 0
    rule_sid: int = 0
    attack_type: str = "http"
    attack_payload: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id,
            "test_item_id": self.test_item_id,
            "rule_sid": self.rule_sid,
            "attack_type": self.attack_type,
            "attack_payload": self.attack_payload,
            "target": self.target,
            "timeout": self.timeout,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AttackTaskPayload":
        return cls(
            test_id=data.get("test_id", ""),
            test_item_id=data.get("test_item_id", 0),
            rule_sid=data.get("rule_sid", 0),
            attack_type=data.get("attack_type", "http"),
            attack_payload=data.get("attack_payload", ""),
            target=data.get("target", {}),
            timeout=data.get("timeout", 30),
        )


@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str = ""
    status: str = "completed"
    success: bool = True
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    executed_at: Optional[datetime] = None
    response_time_ms: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "response_time_ms": self.response_time_ms,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TaskResult":
        executed_at = data.get("executed_at")
        if isinstance(executed_at, str):
            try:
                executed_at = datetime.fromisoformat(executed_at)
            except ValueError:
                executed_at = None

        return cls(
            task_id=data.get("task_id", ""),
            status=data.get("status", "completed"),
            success=data.get("success", True),
            data=data.get("data"),
            error=data.get("error"),
            executed_at=executed_at,
            response_time_ms=data.get("response_time_ms"),
        )
