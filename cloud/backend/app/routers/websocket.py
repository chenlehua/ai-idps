import uuid
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.websocket_service import websocket_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket 实时日志推送"""
    client_id = str(uuid.uuid4())
    await websocket_manager.connect(client_id, websocket)

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "subscribe":
                filters = data.get("filters", {})
                await websocket_manager.subscribe(client_id, filters)
                await websocket.send_json({
                    "event": "subscribed",
                    "filters": filters
                })
            elif action == "unsubscribe":
                await websocket_manager.subscribe(client_id, {})
                await websocket.send_json({"event": "unsubscribed"})
            elif action == "ping":
                await websocket.send_json({"event": "pong"})

    except WebSocketDisconnect:
        await websocket_manager.disconnect(client_id)
    except Exception:
        await websocket_manager.disconnect(client_id)
