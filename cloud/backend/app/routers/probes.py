from fastapi import APIRouter, HTTPException

from app.services.probe_service import probe_service

router = APIRouter(prefix="/probes", tags=["probes"])


@router.get("")
async def list_probes():
    """获取探针列表"""
    probes = await probe_service.list_probes()
    return {"probes": probes}


@router.get("/{probe_id}")
async def get_probe(probe_id: str):
    """获取探针详情"""
    probe = await probe_service.get_probe(probe_id)
    if not probe:
        raise HTTPException(status_code=404, detail="探针不存在")
    return probe
