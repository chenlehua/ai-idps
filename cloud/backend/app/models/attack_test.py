"""攻击测试模型"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class TestType(str, Enum):
    """测试类型"""
    SINGLE = "single"
    BATCH = "batch"


class TestStatus(str, Enum):
    """测试状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestItemStatus(str, Enum):
    """测试项状态"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


class AttackType(str, Enum):
    """攻击类型"""
    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"


@dataclass
class AttackTest:
    """攻击测试"""
    id: Optional[int] = None
    test_id: str = ""
    name: Optional[str] = None
    test_type: str = "single"
    status: str = "pending"
    total_rules: int = 0
    success_count: int = 0
    failed_count: int = 0
    config: Optional[Dict[str, Any]] = None
    probe_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "AttackTest":
        """从数据库行创建实例"""
        import json
        config = row.get("config")
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except json.JSONDecodeError:
                config = None

        return cls(
            id=row.get("id"),
            test_id=row.get("test_id", ""),
            name=row.get("name"),
            test_type=row.get("test_type", "single"),
            status=row.get("status", "pending"),
            total_rules=row.get("total_rules", 0),
            success_count=row.get("success_count", 0),
            failed_count=row.get("failed_count", 0),
            config=config,
            probe_id=row.get("probe_id"),
            started_at=row.get("started_at"),
            completed_at=row.get("completed_at"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "test_id": self.test_id,
            "name": self.name,
            "test_type": self.test_type,
            "status": self.status,
            "total_rules": self.total_rules,
            "success_count": self.success_count,
            "failed_count": self.failed_count,
            "config": self.config,
            "probe_id": self.probe_id,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    @property
    def pending_count(self) -> int:
        """待执行数量"""
        return self.total_rules - self.success_count - self.failed_count

    @property
    def progress_percent(self) -> float:
        """执行进度百分比"""
        if self.total_rules == 0:
            return 0.0
        return (self.success_count + self.failed_count) / self.total_rules * 100


@dataclass
class AttackTestItem:
    """攻击测试项"""
    id: Optional[int] = None
    test_id: int = 0
    rule_id: int = 0
    sid: int = 0
    status: str = "pending"
    attack_type: Optional[str] = None
    attack_payload: Optional[str] = None
    attack_config: Optional[Dict[str, Any]] = None
    attack_result: Optional[Dict[str, Any]] = None
    matched_log_id: Optional[str] = None
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    executed_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "AttackTestItem":
        """从数据库行创建实例"""
        import json

        attack_config = row.get("attack_config")
        if isinstance(attack_config, str):
            try:
                attack_config = json.loads(attack_config)
            except json.JSONDecodeError:
                attack_config = None

        attack_result = row.get("attack_result")
        if isinstance(attack_result, str):
            try:
                attack_result = json.loads(attack_result)
            except json.JSONDecodeError:
                attack_result = None

        return cls(
            id=row.get("id"),
            test_id=row.get("test_id", 0),
            rule_id=row.get("rule_id", 0),
            sid=row.get("sid", 0),
            status=row.get("status", "pending"),
            attack_type=row.get("attack_type"),
            attack_payload=row.get("attack_payload"),
            attack_config=attack_config,
            attack_result=attack_result,
            matched_log_id=row.get("matched_log_id"),
            response_time_ms=row.get("response_time_ms"),
            error_message=row.get("error_message"),
            executed_at=row.get("executed_at"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "test_id": self.test_id,
            "rule_id": self.rule_id,
            "sid": self.sid,
            "status": self.status,
            "attack_type": self.attack_type,
            "attack_payload": self.attack_payload,
            "attack_config": self.attack_config,
            "attack_result": self.attack_result,
            "matched_log_id": self.matched_log_id,
            "response_time_ms": self.response_time_ms,
            "error_message": self.error_message,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class AttackTemplate:
    """攻击模板"""
    id: Optional[int] = None
    name: str = ""
    attack_type: str = ""
    protocol: Optional[str] = None
    template_config: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    classtype: Optional[str] = None
    enabled: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "AttackTemplate":
        """从数据库行创建实例"""
        import json

        template_config = row.get("template_config")
        if isinstance(template_config, str):
            try:
                template_config = json.loads(template_config)
            except json.JSONDecodeError:
                template_config = {}

        return cls(
            id=row.get("id"),
            name=row.get("name", ""),
            attack_type=row.get("attack_type", ""),
            protocol=row.get("protocol"),
            template_config=template_config or {},
            description=row.get("description"),
            classtype=row.get("classtype"),
            enabled=row.get("enabled", True),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "name": self.name,
            "attack_type": self.attack_type,
            "protocol": self.protocol,
            "template_config": self.template_config,
            "description": self.description,
            "classtype": self.classtype,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class TestConfig:
    """测试配置"""
    timeout_per_rule: int = 30  # 每条规则超时时间(秒)
    parallel_count: int = 1  # 并行执行数量
    retry_on_failure: bool = False  # 失败是否重试
    max_retries: int = 1  # 最大重试次数
    target_host: Optional[str] = None  # 目标主机
    target_port: Optional[int] = None  # 目标端口

    def to_dict(self) -> dict:
        return {
            "timeout_per_rule": self.timeout_per_rule,
            "parallel_count": self.parallel_count,
            "retry_on_failure": self.retry_on_failure,
            "max_retries": self.max_retries,
            "target_host": self.target_host,
            "target_port": self.target_port,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TestConfig":
        return cls(
            timeout_per_rule=data.get("timeout_per_rule", 30),
            parallel_count=data.get("parallel_count", 1),
            retry_on_failure=data.get("retry_on_failure", False),
            max_retries=data.get("max_retries", 1),
            target_host=data.get("target_host"),
            target_port=data.get("target_port"),
        )
