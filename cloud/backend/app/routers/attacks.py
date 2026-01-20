"""攻击测试API路由"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List
import logging

from app.services.attack_test_service import AttackTestService
from app.services.probe_task_service import ProbeTaskService
from app.services.mysql_service import mysql_service
from app.services.redis_service import redis_service
from app.models.attack_test import TestConfig, TestStatus
from app.models.probe_task import TaskResult
from app.schemas.attack_test import (
    CreateTestRequest,
    StartTestRequest,
    ReportResultRequest,
    CreateTemplateRequest,
    TestResponse,
    TestDetailResponse,
    TestItemResponse,
    TestItemDetailResponse,
    TestListResponse,
    TemplateResponse,
    TemplateListResponse,
    ProbeTaskResponse,
    ProbeTasksResponse,
    TaskResultResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/attacks", tags=["attacks"])


# ========== 服务依赖 ==========
def get_attack_test_service() -> AttackTestService:
    return AttackTestService(mysql_service=mysql_service, redis_service=redis_service)


def get_probe_task_service() -> ProbeTaskService:
    return ProbeTaskService(mysql_service=mysql_service, redis_service=redis_service)


# ========== 攻击测试管理 ==========
@router.post("/tests", response_model=TestResponse)
async def create_test(
    request: CreateTestRequest,
    service: AttackTestService = Depends(get_attack_test_service)
):
    """创建攻击测试"""
    try:
        config = None
        if request.config:
            config = TestConfig.from_dict(request.config)

        test = await service.create_test(
            name=request.name,
            rule_sids=request.rule_sids,
            probe_id=request.probe_id,
            config=config
        )

        return TestResponse(
            id=test.id,
            test_id=test.test_id,
            name=test.name,
            test_type=test.test_type,
            status=test.status,
            total_rules=test.total_rules,
            success_count=test.success_count,
            failed_count=test.failed_count,
            progress_percent=test.progress_percent,
            probe_id=test.probe_id,
            started_at=test.started_at,
            completed_at=test.completed_at,
            created_at=test.created_at
        )
    except Exception as e:
        logger.error(f"Failed to create test: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tests", response_model=TestListResponse)
async def list_tests(
    status: Optional[str] = Query(None, description="状态筛选"),
    probe_id: Optional[str] = Query(None, description="探针ID筛选"),
    limit: int = Query(20, ge=1, le=100, description="返回数量"),
    offset: int = Query(0, ge=0, description="偏移量"),
    service: AttackTestService = Depends(get_attack_test_service)
):
    """获取测试列表"""
    tests = await service.list_tests(
        status=status,
        probe_id=probe_id,
        limit=limit,
        offset=offset
    )
    total = await service.get_test_count(status=status, probe_id=probe_id)

    return TestListResponse(
        tests=[
            TestResponse(
                id=t.id,
                test_id=t.test_id,
                name=t.name,
                test_type=t.test_type,
                status=t.status,
                total_rules=t.total_rules,
                success_count=t.success_count,
                failed_count=t.failed_count,
                progress_percent=t.progress_percent,
                probe_id=t.probe_id,
                started_at=t.started_at,
                completed_at=t.completed_at,
                created_at=t.created_at
            )
            for t in tests
        ],
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/tests/{test_id}", response_model=TestDetailResponse)
async def get_test(
    test_id: str,
    service: AttackTestService = Depends(get_attack_test_service)
):
    """获取测试详情"""
    test = await service.get_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail="测试不存在")

    items = await service.get_test_items(test_id, limit=100)

    return TestDetailResponse(
        id=test.id,
        test_id=test.test_id,
        name=test.name,
        test_type=test.test_type,
        status=test.status,
        total_rules=test.total_rules,
        success_count=test.success_count,
        failed_count=test.failed_count,
        progress_percent=test.progress_percent,
        probe_id=test.probe_id,
        started_at=test.started_at,
        completed_at=test.completed_at,
        created_at=test.created_at,
        config=test.config,
        items=[
            TestItemResponse(
                id=item.id,
                sid=item.sid,
                status=item.status,
                attack_type=item.attack_type,
                response_time_ms=item.response_time_ms,
                error_message=item.error_message,
                executed_at=item.executed_at
            )
            for item in items
        ]
    )


@router.post("/tests/{test_id}/start")
async def start_test(
    test_id: str,
    service: AttackTestService = Depends(get_attack_test_service),
    task_service: ProbeTaskService = Depends(get_probe_task_service)
):
    """启动测试

    1. 更新测试状态为 running
    2. 为每个测试项创建探针任务
    """
    test = await service.get_test(test_id)
    if not test:
        raise HTTPException(status_code=404, detail="测试不存在")

    if test.status != TestStatus.PENDING.value:
        raise HTTPException(status_code=400, detail=f"测试状态不允许启动: {test.status}")

    # 启动测试
    success = await service.start_test(test_id)
    if not success:
        raise HTTPException(status_code=500, detail="启动测试失败")

    # 获取测试项并创建任务
    items = await service.get_pending_items(test_id, limit=1000)
    for item in items:
        await task_service.create_attack_task(
            test_id=test_id,
            test_item_id=item.id,
            rule_sid=item.sid,
            probe_id=test.probe_id,
            attack_config=item.attack_config or {},
            timeout=test.config.get('timeout_per_rule', 30) if test.config else 30
        )

    return {"success": True, "message": "测试已启动", "task_count": len(items)}


@router.post("/tests/{test_id}/cancel")
async def cancel_test(
    test_id: str,
    service: AttackTestService = Depends(get_attack_test_service)
):
    """取消测试"""
    success = await service.cancel_test(test_id)
    if not success:
        raise HTTPException(status_code=400, detail="取消测试失败")

    return {"success": True, "message": "测试已取消"}


@router.get("/tests/{test_id}/items", response_model=List[TestItemDetailResponse])
async def get_test_items(
    test_id: str,
    status: Optional[str] = Query(None, description="状态筛选"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    service: AttackTestService = Depends(get_attack_test_service)
):
    """获取测试项列表"""
    items = await service.get_test_items(test_id, status=status, limit=limit, offset=offset)

    return [
        TestItemDetailResponse(
            id=item.id,
            rule_id=item.rule_id,
            sid=item.sid,
            status=item.status,
            attack_type=item.attack_type,
            attack_payload=item.attack_payload,
            attack_config=item.attack_config,
            attack_result=item.attack_result,
            matched_log_id=item.matched_log_id,
            response_time_ms=item.response_time_ms,
            error_message=item.error_message,
            executed_at=item.executed_at
        )
        for item in items
    ]


# ========== 攻击模板管理 ==========
@router.get("/templates", response_model=TemplateListResponse)
async def list_templates(
    protocol: Optional[str] = Query(None, description="协议筛选"),
    attack_type: Optional[str] = Query(None, description="攻击类型筛选"),
    service: AttackTestService = Depends(get_attack_test_service)
):
    """获取攻击模板列表"""
    templates = await service.list_templates(protocol=protocol, attack_type=attack_type)

    return TemplateListResponse(
        templates=[
            TemplateResponse(
                id=t.id,
                name=t.name,
                attack_type=t.attack_type,
                protocol=t.protocol,
                template_config=t.template_config,
                description=t.description,
                classtype=t.classtype,
                enabled=t.enabled,
                created_at=t.created_at
            )
            for t in templates
        ],
        total=len(templates)
    )


@router.post("/templates", response_model=TemplateResponse)
async def create_template(
    request: CreateTemplateRequest,
    service: AttackTestService = Depends(get_attack_test_service)
):
    """创建攻击模板"""
    template = await service.create_template(
        name=request.name,
        attack_type=request.attack_type,
        template_config=request.template_config,
        protocol=request.protocol,
        description=request.description,
        classtype=request.classtype
    )

    return TemplateResponse(
        id=template.id,
        name=template.name,
        attack_type=template.attack_type,
        protocol=template.protocol,
        template_config=template.template_config,
        description=template.description,
        classtype=template.classtype,
        enabled=template.enabled,
        created_at=template.created_at
    )


# ========== 探针任务接口 (Pull 模式) ==========
@router.get("/tasks", response_model=ProbeTasksResponse)
async def get_probe_tasks(
    probe_id: str = Query(..., description="探针ID"),
    limit: int = Query(10, ge=1, le=50, description="获取数量"),
    service: ProbeTaskService = Depends(get_probe_task_service)
):
    """获取探针待执行任务 (Pull 模式)

    探针定期调用此接口获取分配给自己的任务
    """
    tasks = await service.get_pending_tasks(probe_id=probe_id, limit=limit)

    return ProbeTasksResponse(
        tasks=[
            ProbeTaskResponse(
                task_id=t.task_id,
                task_type=t.task_type,
                priority=t.priority,
                payload=t.payload,
                expire_at=t.expire_at
            )
            for t in tasks
        ],
        has_more=len(tasks) >= limit
    )


@router.post("/tasks/{task_id}/start")
async def start_task(
    task_id: str,
    service: ProbeTaskService = Depends(get_probe_task_service)
):
    """标记任务开始执行"""
    success = await service.start_task(task_id)
    if not success:
        raise HTTPException(status_code=400, detail="任务状态不允许启动")

    return {"success": True, "message": "任务已开始"}


@router.post("/tasks/{task_id}/result", response_model=TaskResultResponse)
async def report_task_result(
    task_id: str,
    request: ReportResultRequest,
    service: ProbeTaskService = Depends(get_probe_task_service)
):
    """上报任务执行结果"""
    from datetime import datetime

    result = TaskResult(
        task_id=task_id,
        success=request.success,
        data=request.data,
        error=request.error,
        response_time_ms=request.response_time_ms,
        executed_at=datetime.utcnow()
    )

    success = await service.report_task_result(task_id, result)
    if not success:
        raise HTTPException(status_code=400, detail="上报结果失败")

    return TaskResultResponse(success=True, message="结果已接收")


@router.post("/tasks/{task_id}/cancel")
async def cancel_task(
    task_id: str,
    service: ProbeTaskService = Depends(get_probe_task_service)
):
    """取消任务"""
    success = await service.cancel_task(task_id)
    if not success:
        raise HTTPException(status_code=400, detail="取消任务失败")

    return {"success": True, "message": "任务已取消"}
