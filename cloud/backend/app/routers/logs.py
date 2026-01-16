from fastapi import APIRouter, Query
from typing import Optional

from app.services.clickhouse_service import clickhouse_service

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
async def query_logs(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    probe_id: Optional[str] = None,
    severity: Optional[int] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0
):
    """查询告警日志"""
    logs = await clickhouse_service.query_logs(
        start_time=start_time,
        end_time=end_time,
        probe_id=probe_id,
        severity=severity,
        limit=limit,
        offset=offset
    )
    
    total = await clickhouse_service.get_total_count(
        start_time=start_time,
        end_time=end_time,
        probe_id=probe_id,
        severity=severity
    )
    
    return {
        "logs": logs,
        "count": len(logs),
        "total": total
    }


@router.get("/stats")
async def get_stats(hours: int = Query(default=24, le=168)):
    """获取日志统计"""
    stats = await clickhouse_service.get_stats(hours)
    return {"stats": stats}
