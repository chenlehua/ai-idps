"""攻击测试API模式定义"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ========== 枚举 ==========
class TestStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TestItemStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


# ========== 请求模式 ==========
class CreateTestRequest(BaseModel):
    """创建攻击测试请求"""
    name: Optional[str] = Field(default=None, description="测试名称")
    rule_sids: List[int] = Field(..., min_length=1, description="规则SID列表")
    probe_id: str = Field(..., description="执行探针ID")
    config: Optional[Dict[str, Any]] = Field(default=None, description="测试配置")


class TestConfigRequest(BaseModel):
    """测试配置"""
    timeout_per_rule: int = Field(default=30, ge=1, le=300, description="每条规则超时(秒)")
    parallel_count: int = Field(default=1, ge=1, le=10, description="并行执行数")
    retry_on_failure: bool = Field(default=False, description="失败是否重试")
    max_retries: int = Field(default=1, ge=1, le=5, description="最大重试次数")
    target_host: Optional[str] = Field(default=None, description="目标主机")
    target_port: Optional[int] = Field(default=None, description="目标端口")


class StartTestRequest(BaseModel):
    """启动测试请求"""
    test_id: str = Field(..., description="测试ID")


class ReportResultRequest(BaseModel):
    """上报结果请求"""
    task_id: str = Field(..., description="任务ID")
    success: bool = Field(..., description="是否成功")
    data: Optional[Dict[str, Any]] = Field(default=None, description="结果数据")
    error: Optional[str] = Field(default=None, description="错误信息")
    response_time_ms: Optional[int] = Field(default=None, description="响应时间(ms)")


class CreateTemplateRequest(BaseModel):
    """创建攻击模板请求"""
    name: str = Field(..., min_length=1, max_length=100, description="模板名称")
    attack_type: str = Field(..., description="攻击类型")
    protocol: Optional[str] = Field(default=None, description="协议")
    template_config: Dict[str, Any] = Field(default_factory=dict, description="模板配置")
    description: Optional[str] = Field(default=None, description="描述")
    classtype: Optional[str] = Field(default=None, description="关联classtype")


# ========== 响应模式 ==========
class TestResponse(BaseModel):
    """攻击测试响应"""
    id: int = Field(description="数据库ID")
    test_id: str = Field(description="测试ID")
    name: Optional[str] = Field(default=None, description="测试名称")
    test_type: str = Field(description="测试类型")
    status: str = Field(description="状态")
    total_rules: int = Field(default=0, description="规则总数")
    success_count: int = Field(default=0, description="成功数")
    failed_count: int = Field(default=0, description="失败数")
    progress_percent: float = Field(default=0, description="进度百分比")
    probe_id: Optional[str] = Field(default=None, description="探针ID")
    started_at: Optional[datetime] = Field(default=None, description="开始时间")
    completed_at: Optional[datetime] = Field(default=None, description="完成时间")
    created_at: Optional[datetime] = Field(default=None, description="创建时间")


class TestDetailResponse(TestResponse):
    """测试详情响应"""
    config: Optional[Dict[str, Any]] = Field(default=None, description="测试配置")
    items: List["TestItemResponse"] = Field(default_factory=list, description="测试项列表")


class TestItemResponse(BaseModel):
    """测试项响应"""
    id: int = Field(description="ID")
    sid: int = Field(description="规则SID")
    status: str = Field(description="状态")
    attack_type: Optional[str] = Field(default=None, description="攻击类型")
    response_time_ms: Optional[int] = Field(default=None, description="响应时间(ms)")
    error_message: Optional[str] = Field(default=None, description="错误信息")
    executed_at: Optional[datetime] = Field(default=None, description="执行时间")


class TestItemDetailResponse(TestItemResponse):
    """测试项详情响应"""
    rule_id: int = Field(description="规则数据库ID")
    attack_payload: Optional[str] = Field(default=None, description="攻击载荷")
    attack_config: Optional[Dict[str, Any]] = Field(default=None, description="攻击配置")
    attack_result: Optional[Dict[str, Any]] = Field(default=None, description="攻击结果")
    matched_log_id: Optional[str] = Field(default=None, description="匹配的日志ID")


class TestListResponse(BaseModel):
    """测试列表响应"""
    tests: List[TestResponse] = Field(default_factory=list, description="测试列表")
    total: int = Field(default=0, description="总数")
    limit: int = Field(description="返回数量")
    offset: int = Field(description="偏移量")


class TemplateResponse(BaseModel):
    """攻击模板响应"""
    id: int = Field(description="ID")
    name: str = Field(description="名称")
    attack_type: str = Field(description="攻击类型")
    protocol: Optional[str] = Field(default=None, description="协议")
    template_config: Dict[str, Any] = Field(default_factory=dict, description="配置")
    description: Optional[str] = Field(default=None, description="描述")
    classtype: Optional[str] = Field(default=None, description="关联classtype")
    enabled: bool = Field(default=True, description="是否启用")
    created_at: Optional[datetime] = Field(default=None, description="创建时间")


class TemplateListResponse(BaseModel):
    """模板列表响应"""
    templates: List[TemplateResponse] = Field(default_factory=list, description="模板列表")
    total: int = Field(default=0, description="总数")


# ========== 探针任务响应 ==========
class ProbeTaskResponse(BaseModel):
    """探针任务响应"""
    task_id: str = Field(description="任务ID")
    task_type: str = Field(description="任务类型")
    priority: int = Field(description="优先级")
    payload: Dict[str, Any] = Field(description="任务载荷")
    expire_at: Optional[datetime] = Field(default=None, description="过期时间")


class ProbeTasksResponse(BaseModel):
    """探针任务列表响应"""
    tasks: List[ProbeTaskResponse] = Field(default_factory=list, description="任务列表")
    has_more: bool = Field(default=False, description="是否有更多")


class TaskResultResponse(BaseModel):
    """任务结果响应"""
    success: bool = Field(description="是否成功")
    message: str = Field(default="", description="消息")


# 更新前向引用
TestDetailResponse.model_rebuild()
