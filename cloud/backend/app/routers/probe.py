from fastapi import APIRouter

router = APIRouter(tags=["probe"])


@router.post("/probe")
async def handle_probe_placeholder():
    return {
        "status": "not_implemented",
        "message": "probe 接口将在后续阶段完善"
    }
