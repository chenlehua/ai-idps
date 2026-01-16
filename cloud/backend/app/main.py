from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import (
    probe_router,
    rules_router,
    logs_router,
    probes_router,
    websocket_router,
)
from app.services.redis_service import redis_service
from app.services.mysql_service import mysql_service
from app.services.clickhouse_service import clickhouse_service


@asynccontextmanager
async def lifespan(app: FastAPI):
    await redis_service.connect()
    await mysql_service.connect()
    await clickhouse_service.connect()
    yield
    await redis_service.disconnect()
    await mysql_service.disconnect()
    await clickhouse_service.disconnect()


app = FastAPI(
    title="NIDS Backend API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(probe_router, prefix="/api/v1")
app.include_router(rules_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(probes_router, prefix="/api/v1")
app.include_router(websocket_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {"status": "ok"}
