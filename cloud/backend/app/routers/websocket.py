from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "subscribe":
                filters = data.get("filters", {})
                await websocket.send_json({"event": "subscribed", "filters": filters})
            elif action == "unsubscribe":
                await websocket.send_json({"event": "unsubscribed"})
            elif action == "ping":
                await websocket.send_json({"event": "pong"})
    except WebSocketDisconnect:
        return
