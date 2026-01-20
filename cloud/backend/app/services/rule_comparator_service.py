"""规则增量对比服务 - 对比新旧规则"""

import json
import logging
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from app.models.rule import ParsedRule, Rule, RuleChangeSummary
from app.services.mysql_service import MySQLService
from app.services.redis_service import RedisService
from app.core.redis_keys import RedisKeys, RedisTTL

logger = logging.getLogger(__name__)


@dataclass
class RuleChangePreview:
    """规则变更预览"""
    summary: RuleChangeSummary
    added_rules: List[Dict] = field(default_factory=list)
    modified_rules: List[Dict] = field(default_factory=list)
    deleted_rules: List[Dict] = field(default_factory=list)
    generated_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            'summary': self.summary.to_dict(),
            'added_rules': self.added_rules[:100],  # 限制返回数量
            'modified_rules': self.modified_rules[:100],
            'deleted_rules': self.deleted_rules[:100],
            'added_total': len(self.added_rules),
            'modified_total': len(self.modified_rules),
            'deleted_total': len(self.deleted_rules),
            'generated_at': self.generated_at.isoformat() if self.generated_at else None,
        }


class RuleComparatorService:
    """规则增量对比服务"""

    def __init__(
        self,
        mysql_service: MySQLService,
        redis_service: Optional[RedisService] = None
    ):
        """初始化对比服务

        Args:
            mysql_service: MySQL 服务实例
            redis_service: Redis 服务实例
        """
        self.mysql_service = mysql_service
        self.redis_service = redis_service

    async def compare(self, new_rules: List[ParsedRule]) -> RuleChangeSummary:
        """对比新旧规则

        Args:
            new_rules: 新规则列表

        Returns:
            规则变更摘要
        """
        # 获取现有规则
        existing_rules = await self._get_existing_rules()
        existing_by_sid = {r['sid']: r for r in existing_rules}
        existing_sids = set(existing_by_sid.keys())

        # 构建新规则映射
        new_by_sid = {r.sid: r for r in new_rules}
        new_sids = set(new_by_sid.keys())

        # 找出新增、修改、删除的规则
        added_sids = new_sids - existing_sids
        deleted_sids = existing_sids - new_sids
        common_sids = new_sids & existing_sids

        # 检查修改的规则
        modified_rules = []
        unchanged_count = 0

        for sid in common_sids:
            new_rule = new_by_sid[sid]
            existing = existing_by_sid[sid]

            if self._is_rule_modified(new_rule, existing):
                modified_rules.append(new_rule)
            else:
                unchanged_count += 1

        summary = RuleChangeSummary(
            added_rules=[new_by_sid[sid] for sid in added_sids],
            modified_rules=modified_rules,
            deleted_sids=list(deleted_sids),
            unchanged_count=unchanged_count
        )

        logger.info(
            f"Rule comparison result: "
            f"added={len(summary.added_rules)}, "
            f"modified={len(summary.modified_rules)}, "
            f"deleted={len(summary.deleted_sids)}, "
            f"unchanged={unchanged_count}"
        )

        return summary

    async def generate_preview(self, new_rules: List[ParsedRule]) -> RuleChangePreview:
        """生成变更预览

        Args:
            new_rules: 新规则列表

        Returns:
            变更预览
        """
        summary = await self.compare(new_rules)

        # 获取现有规则用于详情
        existing_rules = await self._get_existing_rules()
        existing_by_sid = {r['sid']: r for r in existing_rules}

        # 构建详细预览
        preview = RuleChangePreview(
            summary=summary,
            added_rules=[
                self._rule_to_preview_dict(r, 'added')
                for r in summary.added_rules
            ],
            modified_rules=[
                self._rule_to_preview_dict(r, 'modified', existing_by_sid.get(r.sid))
                for r in summary.modified_rules
            ],
            deleted_rules=[
                self._existing_to_preview_dict(existing_by_sid[sid], 'deleted')
                for sid in summary.deleted_sids
                if sid in existing_by_sid
            ],
            generated_at=datetime.utcnow()
        )

        # 缓存预览结果
        if self.redis_service:
            await self._cache_preview(preview, new_rules)

        return preview

    async def get_cached_preview(self) -> Optional[RuleChangePreview]:
        """获取缓存的变更预览

        Returns:
            缓存的预览，不存在返回 None
        """
        if not self.redis_service:
            return None

        try:
            data = await self.redis_service.get(RedisKeys.RULE_CHANGE_PREVIEW)
            if not data:
                return None

            preview_data = json.loads(data)

            # 获取缓存的规则数据以重建 ParsedRule 对象
            new_rules_data = await self.get_cached_new_rules()
            rules_by_sid = {r['sid']: r for r in (new_rules_data or [])}

            # 从缓存的 sid 列表重建 ParsedRule 对象
            added_sids = preview_data.get('added_sids', [])
            modified_sids = preview_data.get('modified_sids', [])

            added_rules = []
            for sid in added_sids:
                rule_data = rules_by_sid.get(sid)
                if rule_data:
                    added_rules.append(self._dict_to_parsed_rule(rule_data))

            modified_rules = []
            for sid in modified_sids:
                rule_data = rules_by_sid.get(sid)
                if rule_data:
                    modified_rules.append(self._dict_to_parsed_rule(rule_data))

            return RuleChangePreview(
                summary=RuleChangeSummary(
                    added_rules=added_rules,
                    modified_rules=modified_rules,
                    deleted_sids=preview_data.get('deleted_sids', []),
                    unchanged_count=preview_data.get('unchanged_count', 0)
                ),
                added_rules=preview_data.get('added_rules', []),
                modified_rules=preview_data.get('modified_rules', []),
                deleted_rules=preview_data.get('deleted_rules', []),
                generated_at=datetime.fromisoformat(preview_data['generated_at'])
                if preview_data.get('generated_at') else None
            )
        except Exception as e:
            logger.error(f"Failed to get cached preview: {e}")
            return None

    def _dict_to_parsed_rule(self, data: Dict) -> ParsedRule:
        """将字典转换为 ParsedRule 对象

        Args:
            data: 规则数据字典

        Returns:
            ParsedRule 对象
        """
        return ParsedRule(
            sid=data.get('sid', 0),
            gid=data.get('gid', 1),
            rev=data.get('rev', 1),
            action=data.get('action', 'alert'),
            protocol=data.get('protocol'),
            src_addr=data.get('src_addr'),
            src_port=data.get('src_port'),
            direction=data.get('direction', '->'),
            dst_addr=data.get('dst_addr'),
            dst_port=data.get('dst_port'),
            msg=data.get('msg'),
            content=data.get('content', ''),
            classtype=data.get('classtype'),
            category=data.get('category'),
            mitre_attack=data.get('mitre_attack'),
            severity=data.get('severity', 3),
            metadata=data.get('metadata'),
        )

    async def _get_existing_rules(self) -> List[Dict]:
        """获取现有规则

        Returns:
            现有规则列表
        """
        query = """
            SELECT id, sid, gid, rev, action, protocol, src_addr, src_port,
                   direction, dst_addr, dst_port, msg, content, classtype,
                   category, mitre_attack, severity, enabled
            FROM rules
            WHERE enabled = TRUE
        """
        try:
            rows = await self.mysql_service.fetchall(query)
            return [dict(row) for row in rows] if rows else []
        except Exception as e:
            logger.error(f"Failed to get existing rules: {e}")
            return []

    def _is_rule_modified(self, new_rule: ParsedRule, existing: Dict) -> bool:
        """判断规则是否被修改

        Args:
            new_rule: 新规则
            existing: 现有规则

        Returns:
            是否被修改
        """
        # 比较关键字段
        if new_rule.rev != existing.get('rev'):
            return True

        if new_rule.content != existing.get('content'):
            return True

        # 比较其他字段
        compare_fields = [
            ('action', 'action'),
            ('msg', 'msg'),
            ('classtype', 'classtype'),
            ('severity', 'severity'),
        ]

        for new_field, existing_field in compare_fields:
            new_val = getattr(new_rule, new_field, None)
            existing_val = existing.get(existing_field)
            if new_val != existing_val:
                return True

        return False

    def _rule_to_preview_dict(
        self,
        rule: ParsedRule,
        change_type: str,
        existing: Optional[Dict] = None
    ) -> Dict:
        """将规则转换为预览字典

        Args:
            rule: 规则
            change_type: 变更类型
            existing: 现有规则（用于 modified）

        Returns:
            预览字典
        """
        result = {
            'sid': rule.sid,
            'msg': rule.msg,
            'classtype': rule.classtype,
            'category': rule.category,
            'severity': rule.severity,
            'protocol': rule.protocol,
            'change_type': change_type,
        }

        if change_type == 'modified' and existing:
            result['changes'] = self._get_changes(rule, existing)
            result['old_rev'] = existing.get('rev')
            result['new_rev'] = rule.rev

        return result

    def _existing_to_preview_dict(self, existing: Dict, change_type: str) -> Dict:
        """将现有规则转换为预览字典

        Args:
            existing: 现有规则
            change_type: 变更类型

        Returns:
            预览字典
        """
        return {
            'sid': existing.get('sid'),
            'msg': existing.get('msg'),
            'classtype': existing.get('classtype'),
            'category': existing.get('category'),
            'severity': existing.get('severity'),
            'protocol': existing.get('protocol'),
            'change_type': change_type,
        }

    def _get_changes(self, new_rule: ParsedRule, existing: Dict) -> List[Dict]:
        """获取规则变更详情

        Args:
            new_rule: 新规则
            existing: 现有规则

        Returns:
            变更列表
        """
        changes = []

        compare_fields = [
            ('rev', 'rev', '版本'),
            ('action', 'action', '动作'),
            ('msg', 'msg', '消息'),
            ('classtype', 'classtype', '分类'),
            ('severity', 'severity', '严重级别'),
            ('content', 'content', '规则内容'),
        ]

        for new_field, existing_field, label in compare_fields:
            new_val = getattr(new_rule, new_field, None)
            old_val = existing.get(existing_field)

            if new_val != old_val:
                changes.append({
                    'field': new_field,
                    'label': label,
                    'old_value': str(old_val)[:100] if old_val else None,
                    'new_value': str(new_val)[:100] if new_val else None,
                })

        return changes

    async def _cache_preview(self, preview: RuleChangePreview, new_rules: List[ParsedRule]):
        """缓存预览结果

        Args:
            preview: 预览结果
            new_rules: 新规则列表
        """
        if not self.redis_service:
            return

        try:
            # 提取 added 和 modified 规则的 sid 列表
            added_sids = [r.sid for r in preview.summary.added_rules]
            modified_sids = [r.sid for r in preview.summary.modified_rules]

            cache_data = {
                'added_rules': preview.added_rules,
                'modified_rules': preview.modified_rules,
                'deleted_rules': preview.deleted_rules,
                'added_sids': added_sids,  # 新增：保存 added sids
                'modified_sids': modified_sids,  # 新增：保存 modified sids
                'deleted_sids': preview.summary.deleted_sids,
                'unchanged_count': preview.summary.unchanged_count,
                'generated_at': preview.generated_at.isoformat() if preview.generated_at else None,
            }

            await self.redis_service.set(
                RedisKeys.RULE_CHANGE_PREVIEW,
                json.dumps(cache_data, ensure_ascii=False),
                ex=RedisTTL.RULE_CHANGE_PREVIEW
            )

            # 缓存新规则供后续使用
            new_rules_data = [
                {
                    'sid': r.sid, 'gid': r.gid, 'rev': r.rev,
                    'action': r.action, 'protocol': r.protocol,
                    'src_addr': r.src_addr, 'src_port': r.src_port,
                    'direction': r.direction, 'dst_addr': r.dst_addr,
                    'dst_port': r.dst_port, 'msg': r.msg,
                    'content': r.content, 'classtype': r.classtype,
                    'category': r.category, 'mitre_attack': r.mitre_attack,
                    'severity': r.severity, 'metadata': r.metadata,
                }
                for r in new_rules
            ]
            await self.redis_service.set(
                f"{RedisKeys.RULE_CHANGE_PREVIEW}:rules",
                json.dumps(new_rules_data, ensure_ascii=False),
                ex=RedisTTL.RULE_CHANGE_PREVIEW
            )

        except Exception as e:
            logger.error(f"Failed to cache preview: {e}")

    async def get_cached_new_rules(self) -> Optional[List[Dict]]:
        """获取缓存的新规则

        Returns:
            新规则列表
        """
        if not self.redis_service:
            return None

        try:
            data = await self.redis_service.get(f"{RedisKeys.RULE_CHANGE_PREVIEW}:rules")
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Failed to get cached new rules: {e}")

        return None
