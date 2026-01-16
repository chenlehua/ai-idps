from fastapi import APIRouter

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
async def query_logs():
    return {"logs": [], "count": 0}


@router.get("/stats")
async def get_stats():
    return {"stats": []}
