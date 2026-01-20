"""规则解析服务 - 解析Suricata规则格式"""

import re
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
import logging

from app.models.rule import ParsedRule

logger = logging.getLogger(__name__)


class RuleParserService:
    """规则解析服务"""

    # Suricata 规则格式正则表达式
    # 格式: action protocol src_addr src_port -> dst_addr dst_port (options)
    RULE_PATTERN = re.compile(
        r'^(?P<action>alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth)\s+'
        r'(?P<protocol>\w+)\s+'
        r'(?P<src_addr>[^\s]+)\s+'
        r'(?P<src_port>[^\s]+)\s+'
        r'(?P<direction>->|<>|<-)\s+'
        r'(?P<dst_addr>[^\s]+)\s+'
        r'(?P<dst_port>[^\s]+)\s+'
        r'\((?P<options>.*)\)\s*$',
        re.IGNORECASE
    )

    # 常用选项正则
    OPTION_PATTERNS = {
        'msg': re.compile(r'msg\s*:\s*"([^"]*)"', re.IGNORECASE),
        'sid': re.compile(r'sid\s*:\s*(\d+)', re.IGNORECASE),
        'gid': re.compile(r'gid\s*:\s*(\d+)', re.IGNORECASE),
        'rev': re.compile(r'rev\s*:\s*(\d+)', re.IGNORECASE),
        'classtype': re.compile(r'classtype\s*:\s*([^;]+)', re.IGNORECASE),
        'priority': re.compile(r'priority\s*:\s*(\d+)', re.IGNORECASE),
        'reference': re.compile(r'reference\s*:\s*([^;]+)', re.IGNORECASE),
        'metadata': re.compile(r'metadata\s*:\s*([^;]+)', re.IGNORECASE),
    }

    # 严重级别映射 (classtype -> severity)
    SEVERITY_MAP = {
        # Level 1 - 高危
        'attempted-admin': 1,
        'successful-admin': 1,
        'attempted-user': 1,
        'successful-user': 1,
        'trojan-activity': 1,
        'shellcode-detect': 1,
        'web-application-attack': 1,

        # Level 2 - 中危
        'attempted-dos': 2,
        'attempted-recon': 2,
        'suspicious-login': 2,
        'policy-violation': 2,
        'default-login-attempt': 2,
        'misc-attack': 2,

        # Level 3 - 低危
        'bad-unknown': 3,
        'not-suspicious': 3,
        'protocol-command-decode': 3,
        'string-detect': 3,
        'unknown': 3,

        # Level 4 - 信息
        'network-scan': 4,
        'misc-activity': 4,
        'system-call-detect': 4,
        'icmp-event': 4,
    }

    # msg前缀分类映射
    MSG_PREFIX_CATEGORIES = [
        'ET MALWARE',
        'ET TROJAN',
        'ET EXPLOIT',
        'ET WEB_SERVER',
        'ET WEB_CLIENT',
        'ET SCAN',
        'ET DOS',
        'ET POLICY',
        'ET INFO',
        'ET DNS',
        'ET NETBIOS',
        'ET SHELLCODE',
        'ET ATTACK_RESPONSE',
        'ET CURRENT_EVENTS',
        'ET GAMES',
        'ET P2P',
        'ET CHAT',
        'ET ACTIVEX',
        'ET CNC',
        'ET COMPROMISED',
        'ET DROP',
        'ET DSHIELD',
        'ET HUNTING',
        'ET MOBILE_MALWARE',
        'ET PHISHING',
        'ET RBN',
        'ET TOR',
        'ET USER_AGENTS',
        'ET VOIP',
        'ET WORM',
        'GPL',
        'SURICATA',
    ]

    def parse_rules_file(self, content: str) -> List[ParsedRule]:
        """解析规则文件内容

        Args:
            content: 规则文件内容

        Returns:
            解析后的规则列表
        """
        rules = []
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue

            try:
                parsed = self.parse_single_rule(line)
                if parsed:
                    rules.append(parsed)
            except Exception as e:
                logger.warning(f"Failed to parse rule at line {line_num}: {e}")
                continue

        logger.info(f"Parsed {len(rules)} rules from file")
        return rules

    def parse_single_rule(self, line: str) -> Optional[ParsedRule]:
        """解析单条规则

        Args:
            line: 规则行

        Returns:
            解析后的规则，解析失败返回None
        """
        line = line.strip()

        # 跳过注释和空行
        if not line or line.startswith('#'):
            return None

        # 匹配规则格式
        match = self.RULE_PATTERN.match(line)
        if not match:
            logger.debug(f"Rule doesn't match pattern: {line[:100]}...")
            return None

        # 提取基本字段
        groups = match.groupdict()
        options_str = groups.get('options', '')

        # 解析选项
        options = self.extract_options(options_str)

        # 必须有 sid
        sid = options.get('sid')
        if sid is None:
            logger.debug(f"Rule missing sid: {line[:100]}...")
            return None

        # 获取 msg 和分类
        msg = options.get('msg', '')
        classtype = options.get('classtype', '')
        category = self._extract_category_from_msg(msg)
        severity = self._get_severity(classtype, options.get('priority'))

        # 解析 metadata
        metadata = self._parse_metadata(options.get('metadata', ''))
        mitre_attack = metadata.get('mitre_attack_id') or metadata.get('mitre_tactic_id')

        return ParsedRule(
            sid=int(sid),
            gid=int(options.get('gid', 1)),
            rev=int(options.get('rev', 1)),
            action=groups.get('action', 'alert').lower(),
            protocol=groups.get('protocol', '').lower(),
            src_addr=groups.get('src_addr'),
            src_port=groups.get('src_port'),
            direction=groups.get('direction', '->'),
            dst_addr=groups.get('dst_addr'),
            dst_port=groups.get('dst_port'),
            msg=msg,
            content=line,
            classtype=classtype.strip() if classtype else None,
            category=category,
            mitre_attack=mitre_attack,
            severity=severity,
            metadata=metadata if metadata else None,
            raw_options=options,
        )

    def extract_options(self, options_str: str) -> Dict[str, Any]:
        """提取规则选项

        Args:
            options_str: 规则选项字符串

        Returns:
            选项字典
        """
        options = {}

        for key, pattern in self.OPTION_PATTERNS.items():
            match = pattern.search(options_str)
            if match:
                options[key] = match.group(1).strip()

        return options

    def _extract_category_from_msg(self, msg: str) -> Optional[str]:
        """从 msg 提取分类前缀

        Args:
            msg: 规则消息

        Returns:
            分类前缀
        """
        if not msg:
            return None

        msg_upper = msg.upper()
        for prefix in self.MSG_PREFIX_CATEGORIES:
            if msg_upper.startswith(prefix):
                return prefix

        return None

    def _get_severity(self, classtype: Optional[str], priority: Optional[str]) -> int:
        """获取严重级别

        Args:
            classtype: 规则分类
            priority: 优先级

        Returns:
            严重级别 1-4
        """
        # 优先使用 priority
        if priority:
            try:
                p = int(priority)
                if 1 <= p <= 4:
                    return p
            except ValueError:
                pass

        # 使用 classtype 映射
        if classtype:
            classtype_lower = classtype.lower().strip()
            return self.SEVERITY_MAP.get(classtype_lower, 3)

        return 3  # 默认中低级别

    def _parse_metadata(self, metadata_str: str) -> Dict[str, str]:
        """解析 metadata 字段

        Args:
            metadata_str: metadata 字符串

        Returns:
            metadata 字典
        """
        result = {}
        if not metadata_str:
            return result

        # metadata 格式: key value, key value, ...
        parts = metadata_str.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue

            # 分割 key value
            kv = part.split(None, 1)
            if len(kv) == 2:
                result[kv[0].strip()] = kv[1].strip()
            elif len(kv) == 1:
                result[kv[0].strip()] = ''

        return result

    def classify_rule(self, rule: ParsedRule) -> ParsedRule:
        """分类规则 (重新计算分类)

        Args:
            rule: 解析后的规则

        Returns:
            更新分类后的规则
        """
        if not rule.category:
            rule.category = self._extract_category_from_msg(rule.msg)

        if not rule.severity or rule.severity == 3:
            rule.severity = self._get_severity(rule.classtype, None)

        return rule

    def get_all_classtypes(self, rules: List[ParsedRule]) -> Dict[str, int]:
        """统计所有 classtype

        Args:
            rules: 规则列表

        Returns:
            classtype -> count 字典
        """
        counts = {}
        for rule in rules:
            if rule.classtype:
                ct = rule.classtype.strip().lower()
                counts[ct] = counts.get(ct, 0) + 1
        return counts

    def get_all_categories(self, rules: List[ParsedRule]) -> Dict[str, int]:
        """统计所有 msg 前缀分类

        Args:
            rules: 规则列表

        Returns:
            category -> count 字典
        """
        counts = {}
        for rule in rules:
            if rule.category:
                counts[rule.category] = counts.get(rule.category, 0) + 1
        return counts
