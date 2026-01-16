from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from app.services.rule_service import rule_service

router = APIRouter(prefix="/rules", tags=["rules"])


class CreateRuleRequest(BaseModel):
    content: str
    description: Optional[str] = ""


@router.get("")
async def list_rules(limit: int = 20):
    """获取规则版本列表"""
    versions = await rule_service.list_versions(limit)
    return {"versions": versions}


@router.post("")
async def create_rule(request: CreateRuleRequest):
    """创建新规则版本"""
    result = await rule_service.create_rule_version(
        content=request.content,
        description=request.description or ""
    )
    return result


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


@router.get("/{version}")
async def get_rule(version: str):
    """获取指定版本规则"""
    rule = await rule_service.get_rule_by_version(version)
    if not rule:
        raise HTTPException(status_code=404, detail="规则版本不存在")
    return rule
