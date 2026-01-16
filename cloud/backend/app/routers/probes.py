from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/probes", tags=["probes"])


@router.get("")
async def list_probes():
    return {"probes": []}


@router.get("/{probe_id}")
async def get_probe(probe_id: str):
    raise HTTPException(status_code=404, detail="探针不存在")
