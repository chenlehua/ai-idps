"""规则模型"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum


class RuleAction(str, Enum):
    """规则动作"""
    ALERT = "alert"
    DROP = "drop"
    PASS = "pass"
    REJECT = "reject"


class ChangeType(str, Enum):
    """规则变更类型"""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    UNCHANGED = "unchanged"


@dataclass
class Rule:
    """规则"""
    id: Optional[int] = None
    sid: int = 0
    gid: int = 1
    rev: int = 1
    action: str = "alert"
    protocol: Optional[str] = None
    src_addr: Optional[str] = None
    src_port: Optional[str] = None
    direction: str = "->"
    dst_addr: Optional[str] = None
    dst_port: Optional[str] = None
    msg: Optional[str] = None
    content: Optional[str] = None
    classtype: Optional[str] = None
    category: Optional[str] = None
    mitre_attack: Optional[str] = None
    severity: int = 3
    metadata: Optional[Dict[str, Any]] = None
    enabled: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "Rule":
        """从数据库行创建实例"""
        import json
        metadata = row.get("metadata")
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = None

        return cls(
            id=row.get("id"),
            sid=row.get("sid", 0),
            gid=row.get("gid", 1),
            rev=row.get("rev", 1),
            action=row.get("action", "alert"),
            protocol=row.get("protocol"),
            src_addr=row.get("src_addr"),
            src_port=row.get("src_port"),
            direction=row.get("direction", "->"),
            dst_addr=row.get("dst_addr"),
            dst_port=row.get("dst_port"),
            msg=row.get("msg"),
            content=row.get("content"),
            classtype=row.get("classtype"),
            category=row.get("category"),
            mitre_attack=row.get("mitre_attack"),
            severity=row.get("severity", 3),
            metadata=metadata,
            enabled=row.get("enabled", True),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "sid": self.sid,
            "gid": self.gid,
            "rev": self.rev,
            "action": self.action,
            "protocol": self.protocol,
            "src_addr": self.src_addr,
            "src_port": self.src_port,
            "direction": self.direction,
            "dst_addr": self.dst_addr,
            "dst_port": self.dst_port,
            "msg": self.msg,
            "content": self.content,
            "classtype": self.classtype,
            "category": self.category,
            "mitre_attack": self.mitre_attack,
            "severity": self.severity,
            "metadata": self.metadata,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class RuleVersionRule:
    """规则版本关联"""
    id: Optional[int] = None
    version_id: int = 0
    rule_id: int = 0
    change_type: str = "unchanged"
    previous_content: Optional[str] = None
    created_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "RuleVersionRule":
        """从数据库行创建实例"""
        return cls(
            id=row.get("id"),
            version_id=row.get("version_id", 0),
            rule_id=row.get("rule_id", 0),
            change_type=row.get("change_type", "unchanged"),
            previous_content=row.get("previous_content"),
            created_at=row.get("created_at"),
        )


@dataclass
class ParsedRule:
    """解析后的规则"""
    sid: int
    gid: int = 1
    rev: int = 1
    action: str = "alert"
    protocol: Optional[str] = None
    src_addr: Optional[str] = None
    src_port: Optional[str] = None
    direction: str = "->"
    dst_addr: Optional[str] = None
    dst_port: Optional[str] = None
    msg: Optional[str] = None
    content: str = ""
    classtype: Optional[str] = None
    category: Optional[str] = None
    mitre_attack: Optional[str] = None
    severity: int = 3
    metadata: Optional[Dict[str, Any]] = None
    raw_options: Optional[Dict[str, Any]] = None

    def to_rule(self) -> Rule:
        """转换为Rule对象"""
        return Rule(
            sid=self.sid,
            gid=self.gid,
            rev=self.rev,
            action=self.action,
            protocol=self.protocol,
            src_addr=self.src_addr,
            src_port=self.src_port,
            direction=self.direction,
            dst_addr=self.dst_addr,
            dst_port=self.dst_port,
            msg=self.msg,
            content=self.content,
            classtype=self.classtype,
            category=self.category,
            mitre_attack=self.mitre_attack,
            severity=self.severity,
            metadata=self.metadata,
            enabled=True,
        )


@dataclass
class RuleChangeSummary:
    """规则变更摘要"""
    added_rules: List[ParsedRule] = field(default_factory=list)
    modified_rules: List[ParsedRule] = field(default_factory=list)
    deleted_sids: List[int] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def total_changes(self) -> int:
        return len(self.added_rules) + len(self.modified_rules) + len(self.deleted_sids)

    @property
    def has_changes(self) -> bool:
        return self.total_changes > 0

    def to_dict(self) -> dict:
        return {
            "added_count": len(self.added_rules),
            "modified_count": len(self.modified_rules),
            "deleted_count": len(self.deleted_sids),
            "unchanged_count": self.unchanged_count,
            "total_changes": self.total_changes,
            "has_changes": self.has_changes,
        }
