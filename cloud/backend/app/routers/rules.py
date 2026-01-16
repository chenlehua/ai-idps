from fastapi import APIRouter

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("")
async def list_rules():
    return {"versions": []}
