class WebSocketManager:
    async def connect(self, client_id, websocket):
        return None

    async def disconnect(self, client_id):
        return None

    async def broadcast_log(self, log):
        return None


websocket_manager = WebSocketManager()
