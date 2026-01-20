"""规则更新API模式定义"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ========== 枚举 ==========
class DownloadStatusEnum(str, Enum):
    IDLE = "idle"
    DOWNLOADING = "downloading"
    PARSING = "parsing"
    COMPARING = "comparing"
    READY = "ready"
    ERROR = "error"


# ========== 请求模式 ==========
class RuleDownloadRequest(BaseModel):
    """规则下载请求"""
    force: bool = Field(default=False, description="是否强制重新下载")


class RuleUpdateRequest(BaseModel):
    """规则更新确认请求"""
    description: Optional[str] = Field(default="", description="版本描述")
    apply_changes: bool = Field(default=True, description="是否应用变更")


class RuleFilterRequest(BaseModel):
    """规则筛选请求"""
    classtype: Optional[str] = Field(default=None, description="classtype 筛选")
    category: Optional[str] = Field(default=None, description="msg 前缀分类筛选")
    severity: Optional[int] = Field(default=None, ge=1, le=4, description="严重级别筛选")
    protocol: Optional[str] = Field(default=None, description="协议筛选")
    enabled: Optional[bool] = Field(default=None, description="是否启用")
    search: Optional[str] = Field(default=None, description="搜索关键词")
    limit: int = Field(default=20, ge=1, le=100, description="返回数量")
    offset: int = Field(default=0, ge=0, description="偏移量")


# ========== 响应模式 ==========
class RuleDownloadResponse(BaseModel):
    """规则下载响应"""
    task_id: str = Field(description="任务ID")
    status: str = Field(description="状态")
    message: str = Field(default="", description="消息")


class DownloadStatusResponse(BaseModel):
    """下载状态响应"""
    status: DownloadStatusEnum = Field(description="下载状态")
    progress: float = Field(default=0, ge=0, le=100, description="进度百分比")
    message: str = Field(default="", description="状态消息")
    task_id: str = Field(default="", description="任务ID")
    total_bytes: int = Field(default=0, description="总字节数")
    downloaded_bytes: int = Field(default=0, description="已下载字节数")


class RuleChangeSummaryResponse(BaseModel):
    """规则变更摘要响应"""
    added_count: int = Field(default=0, description="新增规则数")
    modified_count: int = Field(default=0, description="修改规则数")
    deleted_count: int = Field(default=0, description="删除规则数")
    unchanged_count: int = Field(default=0, description="未变更规则数")
    total_changes: int = Field(default=0, description="变更总数")
    has_changes: bool = Field(default=False, description="是否有变更")


class RulePreviewItem(BaseModel):
    """规则预览项"""
    sid: int = Field(description="规则SID")
    msg: Optional[str] = Field(default=None, description="规则消息")
    classtype: Optional[str] = Field(default=None, description="classtype")
    category: Optional[str] = Field(default=None, description="msg前缀分类")
    severity: int = Field(default=3, description="严重级别")
    protocol: Optional[str] = Field(default=None, description="协议")
    change_type: str = Field(description="变更类型")
    changes: Optional[List[Dict[str, Any]]] = Field(default=None, description="变更详情")


class RuleChangePreviewResponse(BaseModel):
    """规则变更预览响应"""
    summary: RuleChangeSummaryResponse = Field(description="变更摘要")
    added_rules: List[RulePreviewItem] = Field(default_factory=list, description="新增规则")
    modified_rules: List[RulePreviewItem] = Field(default_factory=list, description="修改规则")
    deleted_rules: List[RulePreviewItem] = Field(default_factory=list, description="删除规则")
    added_total: int = Field(default=0, description="新增规则总数")
    modified_total: int = Field(default=0, description="修改规则总数")
    deleted_total: int = Field(default=0, description="删除规则总数")
    generated_at: Optional[datetime] = Field(default=None, description="生成时间")


class RuleUpdateResponse(BaseModel):
    """规则更新响应"""
    success: bool = Field(description="是否成功")
    version: str = Field(default="", description="新版本号")
    message: str = Field(default="", description="消息")
    rule_count: int = Field(default=0, description="规则总数")
    added_count: int = Field(default=0, description="新增数")
    modified_count: int = Field(default=0, description="修改数")
    deleted_count: int = Field(default=0, description="删除数")


class RuleResponse(BaseModel):
    """规则响应"""
    id: int = Field(description="规则ID")
    sid: int = Field(description="规则SID")
    gid: int = Field(default=1, description="规则GID")
    rev: int = Field(default=1, description="规则版本")
    action: str = Field(default="alert", description="动作")
    protocol: Optional[str] = Field(default=None, description="协议")
    msg: Optional[str] = Field(default=None, description="消息")
    classtype: Optional[str] = Field(default=None, description="classtype")
    category: Optional[str] = Field(default=None, description="分类")
    severity: int = Field(default=3, description="严重级别")
    enabled: bool = Field(default=True, description="是否启用")
    created_at: Optional[datetime] = Field(default=None, description="创建时间")


class RuleDetailResponse(RuleResponse):
    """规则详情响应"""
    src_addr: Optional[str] = Field(default=None, description="源地址")
    src_port: Optional[str] = Field(default=None, description="源端口")
    direction: str = Field(default="->", description="方向")
    dst_addr: Optional[str] = Field(default=None, description="目标地址")
    dst_port: Optional[str] = Field(default=None, description="目标端口")
    content: Optional[str] = Field(default=None, description="完整规则内容")
    mitre_attack: Optional[str] = Field(default=None, description="MITRE ATT&CK ID")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="元数据")
    alert_count_24h: int = Field(default=0, description="24小时告警数")


class RuleListResponse(BaseModel):
    """规则列表响应"""
    rules: List[RuleResponse] = Field(default_factory=list, description="规则列表")
    total: int = Field(default=0, description="总数")
    limit: int = Field(description="返回数量")
    offset: int = Field(description="偏移量")


class CategoryStatsResponse(BaseModel):
    """分类统计响应"""
    category_type: str = Field(description="分类类型")
    category_name: str = Field(description="分类名称")
    rule_count: int = Field(default=0, description="规则数量")
    enabled_count: int = Field(default=0, description="启用规则数量")


class RuleCategoriesResponse(BaseModel):
    """规则分类响应"""
    classtype: List[CategoryStatsResponse] = Field(default_factory=list, description="classtype 分类")
    msg_prefix: List[CategoryStatsResponse] = Field(default_factory=list, description="msg前缀分类")
    severity_stats: Dict[int, int] = Field(default_factory=dict, description="严重级别统计")
    protocol_stats: Dict[str, int] = Field(default_factory=dict, description="协议统计")


class RuleVersionResponse(BaseModel):
    """规则版本响应"""
    id: int = Field(description="版本ID")
    version: str = Field(description="版本号")
    checksum: str = Field(description="校验和")
    description: Optional[str] = Field(default=None, description="描述")
    is_active: bool = Field(default=False, description="是否活跃")
    created_at: Optional[datetime] = Field(default=None, description="创建时间")
    rule_count: int = Field(default=0, description="规则数量")


class RuleVersionListResponse(BaseModel):
    """规则版本列表响应"""
    versions: List[RuleVersionResponse] = Field(default_factory=list, description="版本列表")
    total: int = Field(default=0, description="总数")


# ========== 探针规则同步响应 ==========
class ProbeRuleVersionResponse(BaseModel):
    """探针规则版本响应"""
    latest_version: Optional[str] = Field(default=None, description="最新版本")
    current_version: Optional[str] = Field(default=None, description="当前版本")
    needs_update: bool = Field(default=False, description="是否需要更新")
    server_time: str = Field(description="服务器时间")


class ProbeRuleDownloadResponse(BaseModel):
    """探针规则下载响应"""
    version: str = Field(description="版本号")
    content: str = Field(description="规则内容")
    checksum: str = Field(description="校验和")
