from datetime import datetime
from fastapi import APIRouter

from app.models.probe_protocol import (
    ProbeCommand, ProbeRequest, ProbeResponse,
    RegisterData, HeartbeatData, RuleDownloadData, LogUploadData
)
from app.services.probe_service import probe_service
from app.services.rule_service import rule_service
from app.services.log_service import log_service

router = APIRouter(tags=["probe"])


@router.post("/probe", response_model=ProbeResponse)
async def handle_probe_request(request: ProbeRequest) -> ProbeResponse:
    """统一探针通信入口"""
    cmd = request.cmd
    data = request.data

    try:
        if cmd == ProbeCommand.REGISTER:
            return await handle_register(RegisterData(**data))
        elif cmd == ProbeCommand.HEARTBEAT:
            return await handle_heartbeat(HeartbeatData(**data))
        elif cmd == ProbeCommand.RULE_DOWNLOAD:
            return await handle_rule_download(RuleDownloadData(**data))
        elif cmd == ProbeCommand.LOG_UPLOAD:
            return await handle_log_upload(LogUploadData(**data))
        else:
            return ProbeResponse(
                cmd=cmd + 1,
                data={"status": "error", "error_code": 1004, "message": "未知命令"}
            )
    except Exception as e:
        return ProbeResponse(
            cmd=cmd + 1,
            data={"status": "error", "error_code": 1005, "message": str(e)}
        )


async def handle_register(data: RegisterData) -> ProbeResponse:
    """处理探针注册"""
    result = await probe_service.register_probe(
        probe_id=data.probe_id,
        name=data.name,
        ip=data.ip,
        probe_types=data.probe_types
    )
    return ProbeResponse(
        cmd=ProbeCommand.REGISTER_RESPONSE,
        data=result
    )


async def handle_heartbeat(data: HeartbeatData) -> ProbeResponse:
    """处理心跳请求"""
    # 更新探针状态
    await probe_service.update_probe_status(
        probe_id=data.probe_id,
        status=data.status,
        probes=data.probes,
        rule_version=data.rule_version
    )

    # 获取最新规则版本
    latest_version = await rule_service.get_latest_version()

    return ProbeResponse(
        cmd=ProbeCommand.HEARTBEAT_RESPONSE,
        data={
            "status": "ok",
            "latest_rule_version": latest_version,
            "server_time": datetime.utcnow().isoformat() + "Z"
        }
    )


async def handle_rule_download(data: RuleDownloadData) -> ProbeResponse:
    """处理规则下载"""
    rule = await rule_service.get_rule_by_version(data.version)
    if not rule:
        return ProbeResponse(
            cmd=ProbeCommand.RULE_DOWNLOAD_RESPONSE,
            data={"status": "error", "error_code": 1003, "message": "规则版本不存在"}
        )

    return ProbeResponse(
        cmd=ProbeCommand.RULE_DOWNLOAD_RESPONSE,
        data={
            "status": "ok",
            "version": rule["version"],
            "content": rule["content"],
            "checksum": rule["checksum"]
        }
    )


async def handle_log_upload(data: LogUploadData) -> ProbeResponse:
    """处理日志上报"""
    count = await log_service.insert_logs(data.probe_id, data.logs)

    return ProbeResponse(
        cmd=ProbeCommand.LOG_UPLOAD_RESPONSE,
        data={
            "status": "ok",
            "received": count,
            "message": "日志接收成功"
        }
    )
