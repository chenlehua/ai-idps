"""规则分类模型"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from enum import Enum


class CategoryType(str, Enum):
    """分类类型枚举"""
    CLASSTYPE = "classtype"
    MSG_PREFIX = "msg_prefix"


@dataclass
class RuleCategory:
    """规则分类"""
    id: Optional[int] = None
    category_type: str = ""
    category_name: str = ""
    description: Optional[str] = None
    rule_count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_db_row(cls, row: dict) -> "RuleCategory":
        """从数据库行创建实例"""
        return cls(
            id=row.get("id"),
            category_type=row.get("category_type", ""),
            category_name=row.get("category_name", ""),
            description=row.get("description"),
            rule_count=row.get("rule_count", 0),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            "id": self.id,
            "category_type": self.category_type,
            "category_name": self.category_name,
            "description": self.description,
            "rule_count": self.rule_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


@dataclass
class CategoryStats:
    """分类统计"""
    category_type: str
    category_name: str
    rule_count: int
    enabled_count: int = 0

    def to_dict(self) -> dict:
        return {
            "category_type": self.category_type,
            "category_name": self.category_name,
            "rule_count": self.rule_count,
            "enabled_count": self.enabled_count,
        }
