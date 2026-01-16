from enum import IntEnum
from typing import Any, Optional, List
from pydantic import BaseModel


class ProbeCommand(IntEnum):
    LOG_UPLOAD = 10
    LOG_UPLOAD_RESPONSE = 11
    HEARTBEAT = 20
    HEARTBEAT_RESPONSE = 21
    REGISTER = 30
    REGISTER_RESPONSE = 31
    RULE_DOWNLOAD = 40
    RULE_DOWNLOAD_RESPONSE = 41


class ProbeRequest(BaseModel):
    cmd: int
    data: dict[str, Any]


class ProbeResponse(BaseModel):
    cmd: int
    data: dict[str, Any]


class RegisterData(BaseModel):
    probe_id: str
    name: str
    ip: str
    probe_types: List[str]


class HeartbeatData(BaseModel):
    probe_id: str
    rule_version: Optional[str]
    status: dict[str, Any]
    probes: List[dict[str, Any]]


class RuleDownloadData(BaseModel):
    probe_id: str
    version: str


class LogUploadData(BaseModel):
    probe_id: str
    logs: List[dict[str, Any]]
