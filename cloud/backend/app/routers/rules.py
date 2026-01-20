"""规则管理API路由"""

from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks
from typing import Optional, List
import logging

from app.services.rule_service import rule_service
from app.services.mysql_service import mysql_service
from app.services.redis_service import redis_service
from app.services.rule_download_service import RuleDownloadService
from app.services.rule_parser_service import RuleParserService
from app.services.rule_comparator_service import RuleComparatorService
from app.services.rule_version_service import RuleVersionService
from app.services.rule_category_service import RuleCategoryService
from app.schemas.rule_update import (
    RuleDownloadRequest,
    RuleDownloadResponse,
    DownloadStatusResponse,
    RuleChangePreviewResponse,
    RuleChangeSummaryResponse,
    RulePreviewItem,
    RuleUpdateRequest,
    RuleUpdateResponse,
    RuleFilterRequest,
    RuleResponse,
    RuleDetailResponse,
    RuleListResponse,
    RuleCategoriesResponse,
    CategoryStatsResponse,
    RuleVersionResponse,
    RuleVersionListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rules", tags=["rules"])


# ========== 服务依赖 ==========
def get_download_service() -> RuleDownloadService:
    return RuleDownloadService(redis_service=redis_service)


def get_parser_service() -> RuleParserService:
    return RuleParserService()


def get_comparator_service() -> RuleComparatorService:
    return RuleComparatorService(
        mysql_service=mysql_service,
        redis_service=redis_service
    )


def get_version_service() -> RuleVersionService:
    return RuleVersionService(
        mysql_service=mysql_service,
        redis_service=redis_service
    )


def get_category_service() -> RuleCategoryService:
    return RuleCategoryService(
        mysql_service=mysql_service,
        redis_service=redis_service
    )


# ========== 规则下载与更新 ==========
@router.post("/download", response_model=RuleDownloadResponse)
async def trigger_download(
    request: RuleDownloadRequest,
    background_tasks: BackgroundTasks,
    download_service: RuleDownloadService = Depends(get_download_service)
):
    """触发规则下载"""
    try:
        task_id = await download_service.start_download(force=request.force)
        return RuleDownloadResponse(
            task_id=task_id,
            status="downloading",
            message="规则下载已启动"
        )
    except Exception as e:
        logger.error(f"Failed to start download: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/download/status", response_model=DownloadStatusResponse)
async def get_download_status(
    download_service: RuleDownloadService = Depends(get_download_service)
):
    """获取下载状态"""
    status = await download_service.get_download_status()
    return DownloadStatusResponse(**status)


@router.post("/download/cancel")
async def cancel_download(
    download_service: RuleDownloadService = Depends(get_download_service)
):
    """取消下载"""
    success = await download_service.cancel_download()
    return {"success": success, "message": "下载已取消" if success else "取消失败"}


@router.get("/preview", response_model=RuleChangePreviewResponse)
async def get_changes_preview(
    download_service: RuleDownloadService = Depends(get_download_service),
    parser_service: RuleParserService = Depends(get_parser_service),
    comparator_service: RuleComparatorService = Depends(get_comparator_service)
):
    """获取变更预览"""
    # 先检查是否有缓存的预览
    cached_preview = await comparator_service.get_cached_preview()
    if cached_preview:
        return RuleChangePreviewResponse(
            summary=RuleChangeSummaryResponse(**cached_preview.summary.to_dict()),
            added_rules=[RulePreviewItem(**r) for r in cached_preview.added_rules],
            modified_rules=[RulePreviewItem(**r) for r in cached_preview.modified_rules],
            deleted_rules=[RulePreviewItem(**r) for r in cached_preview.deleted_rules],
            added_total=len(cached_preview.added_rules),
            modified_total=len(cached_preview.modified_rules),
            deleted_total=len(cached_preview.deleted_rules),
            generated_at=cached_preview.generated_at
        )

    # 检查下载状态
    status = await download_service.get_download_status()
    if status.get('status') != 'ready':
        raise HTTPException(
            status_code=400,
            detail="请先下载规则。当前状态: " + status.get('status', 'unknown')
        )

    # 获取下载的内容
    task_id = status.get('task_id', '')
    content = await download_service.get_cached_download(task_id)
    if not content:
        raise HTTPException(status_code=400, detail="下载内容已过期，请重新下载")

    # 解析规则
    parsed_rules = parser_service.parse_rules_file(content)
    if not parsed_rules:
        raise HTTPException(status_code=400, detail="规则解析失败")

    # 生成预览
    preview = await comparator_service.generate_preview(parsed_rules)

    return RuleChangePreviewResponse(
        summary=RuleChangeSummaryResponse(**preview.summary.to_dict()),
        added_rules=[RulePreviewItem(**r) for r in preview.added_rules],
        modified_rules=[RulePreviewItem(**r) for r in preview.modified_rules],
        deleted_rules=[RulePreviewItem(**r) for r in preview.deleted_rules],
        added_total=len(preview.added_rules),
        modified_total=len(preview.modified_rules),
        deleted_total=len(preview.deleted_rules),
        generated_at=preview.generated_at
    )


@router.post("/update", response_model=RuleUpdateResponse)
async def confirm_update(
    request: RuleUpdateRequest,
    comparator_service: RuleComparatorService = Depends(get_comparator_service),
    version_service: RuleVersionService = Depends(get_version_service),
    category_service: RuleCategoryService = Depends(get_category_service)
):
    """确认更新规则"""
    if not request.apply_changes:
        return RuleUpdateResponse(
            success=False,
            message="更新已取消"
        )

    # 获取缓存的新规则
    new_rules = await comparator_service.get_cached_new_rules()
    if not new_rules:
        raise HTTPException(status_code=400, detail="变更预览已过期，请重新下载和预览")

    # 获取变更摘要
    cached_preview = await comparator_service.get_cached_preview()
    if not cached_preview:
        raise HTTPException(status_code=400, detail="变更预览已过期")

    try:
        # 创建新版本
        new_version = await version_service.create_version(
            new_rules=new_rules,
            changes=cached_preview.summary,
            description=request.description or ""
        )

        # 更新分类统计
        await category_service.update_category_counts()

        return RuleUpdateResponse(
            success=True,
            version=new_version.version,
            message="规则更新成功",
            rule_count=len(new_rules),
            added_count=len(cached_preview.summary.added_rules),
            modified_count=len(cached_preview.summary.modified_rules),
            deleted_count=len(cached_preview.summary.deleted_sids)
        )

    except Exception as e:
        logger.error(f"Failed to update rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ========== 规则列表与详情 ==========
@router.get("", response_model=RuleListResponse)
async def list_rules(
    classtype: Optional[str] = Query(None, description="classtype 筛选"),
    category: Optional[str] = Query(None, description="msg 前缀分类筛选"),
    severity: Optional[int] = Query(None, ge=1, le=4, description="严重级别筛选"),
    protocol: Optional[str] = Query(None, description="协议筛选"),
    enabled: Optional[bool] = Query(None, description="是否启用"),
    search: Optional[str] = Query(None, description="搜索关键词 (msg/sid)"),
    limit: int = Query(20, ge=1, le=100, description="返回数量"),
    offset: int = Query(0, ge=0, description="偏移量")
):
    """获取规则列表 (支持筛选)"""
    # 构建查询条件
    conditions = []
    params = []

    if classtype:
        conditions.append("classtype = %s")
        params.append(classtype)

    if category:
        conditions.append("category = %s")
        params.append(category)

    if severity is not None:
        conditions.append("severity = %s")
        params.append(severity)

    if protocol:
        conditions.append("protocol = %s")
        params.append(protocol)

    if enabled is not None:
        conditions.append("enabled = %s")
        params.append(enabled)

    if search:
        if search.isdigit():
            conditions.append("sid = %s")
            params.append(int(search))
        else:
            conditions.append("msg LIKE %s")
            params.append(f"%{search}%")

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # 查询总数
    count_query = f"SELECT COUNT(*) as total FROM rules WHERE {where_clause}"
    count_result = await mysql_service.fetchone(count_query, tuple(params))
    total = count_result['total'] if count_result else 0

    # 查询数据
    query = f"""
        SELECT id, sid, gid, rev, action, protocol, msg, classtype,
               category, severity, enabled, created_at
        FROM rules
        WHERE {where_clause}
        ORDER BY sid
        LIMIT %s OFFSET %s
    """
    params.extend([limit, offset])
    rows = await mysql_service.fetchall(query, tuple(params))

    rules = [
        RuleResponse(
            id=row['id'],
            sid=row['sid'],
            gid=row['gid'],
            rev=row['rev'],
            action=row['action'],
            protocol=row['protocol'],
            msg=row['msg'],
            classtype=row['classtype'],
            category=row['category'],
            severity=row['severity'],
            enabled=row['enabled'],
            created_at=row['created_at']
        )
        for row in (rows or [])
    ]

    return RuleListResponse(
        rules=rules,
        total=total,
        limit=limit,
        offset=offset
    )


@router.get("/categories", response_model=RuleCategoriesResponse)
async def get_categories(
    category_service: RuleCategoryService = Depends(get_category_service)
):
    """获取规则分类统计"""
    categories = await category_service.get_all_categories()
    severity_stats = await category_service.get_severity_stats()
    protocol_stats = await category_service.get_protocol_stats()

    return RuleCategoriesResponse(
        classtype=[
            CategoryStatsResponse(
                category_type=s.category_type,
                category_name=s.category_name,
                rule_count=s.rule_count,
                enabled_count=s.enabled_count
            )
            for s in categories.get('classtype', [])
        ],
        msg_prefix=[
            CategoryStatsResponse(
                category_type=s.category_type,
                category_name=s.category_name,
                rule_count=s.rule_count,
                enabled_count=s.enabled_count
            )
            for s in categories.get('msg_prefix', [])
        ],
        severity_stats=severity_stats,
        protocol_stats=protocol_stats
    )


@router.get("/versions", response_model=RuleVersionListResponse)
async def list_versions(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    version_service: RuleVersionService = Depends(get_version_service)
):
    """获取规则版本列表"""
    versions = await version_service.list_versions(limit=limit, offset=offset)

    return RuleVersionListResponse(
        versions=[
            RuleVersionResponse(
                id=v.id,
                version=v.version,
                checksum=v.checksum,
                description=v.description,
                is_active=v.is_active,
                created_at=v.created_at,
                rule_count=v.rule_count
            )
            for v in versions
        ],
        total=len(versions)  # 简化处理，实际应该查询总数
    )


@router.get("/latest")
async def get_latest_rule():
    """获取最新规则版本"""
    version = await rule_service.get_latest_version()
    if not version:
        return {"version": None, "message": "暂无规则"}

    rule = await rule_service.get_rule_by_version(version)
    if not rule:
        raise HTTPException(status_code=404, detail="规则版本不存在")
    return rule


@router.get("/{sid}", response_model=RuleDetailResponse)
async def get_rule_by_sid(sid: int):
    """获取规则详情 (按SID)"""
    row = await mysql_service.fetchone(
        """
        SELECT * FROM rules WHERE sid = %s
        """,
        (sid,)
    )

    if not row:
        raise HTTPException(status_code=404, detail="规则不存在")

    # 查询24小时告警数
    alert_count = 0
    try:
        from app.services.clickhouse_service import clickhouse_service
        alert_result = await clickhouse_service.get_alert_count_by_sid(sid, hours=24)
        alert_count = alert_result or 0
    except Exception:
        pass

    import json
    metadata = row.get('metadata')
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except:
            metadata = None

    return RuleDetailResponse(
        id=row['id'],
        sid=row['sid'],
        gid=row['gid'],
        rev=row['rev'],
        action=row['action'],
        protocol=row['protocol'],
        src_addr=row['src_addr'],
        src_port=row['src_port'],
        direction=row['direction'],
        dst_addr=row['dst_addr'],
        dst_port=row['dst_port'],
        msg=row['msg'],
        content=row['content'],
        classtype=row['classtype'],
        category=row['category'],
        mitre_attack=row['mitre_attack'],
        severity=row['severity'],
        metadata=metadata,
        enabled=row['enabled'],
        created_at=row['created_at'],
        alert_count_24h=alert_count
    )


@router.put("/{sid}/toggle")
async def toggle_rule(sid: int, enabled: bool):
    """启用/禁用规则"""
    result = await mysql_service.execute(
        "UPDATE rules SET enabled = %s WHERE sid = %s",
        (enabled, sid)
    )

    if result == 0:
        raise HTTPException(status_code=404, detail="规则不存在")

    return {"success": True, "sid": sid, "enabled": enabled}


# ========== 版本相关 (兼容旧接口) ==========
@router.get("/version/{version}")
async def get_rule_version(version: str):
    """获取指定版本规则"""
    rule = await rule_service.get_rule_by_version(version)
    if not rule:
        raise HTTPException(status_code=404, detail="规则版本不存在")
    return rule
