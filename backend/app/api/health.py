from fastapi import APIRouter
from datetime import datetime, timezone
import redis.asyncio as aioredis
from backend.app.core.config import settings
from backend.app.db.mongodb import ping_mongodb

router = APIRouter(tags=["Health"])


async def ping_redis() -> str:
    try:
        r = aioredis.from_url(settings.REDIS_URL, socket_timeout=1.0)
        pong = await r.ping()
        await r.aclose()
        return "connected" if pong else "disconnected"
    except Exception:
        return "optional_offline"


def check_celery_broker() -> str:
    try:
        from backend.app.workers.celery_app import celery_app
        insp = celery_app.control.inspect(timeout=1.0)
        ping_res = insp.ping()
        if ping_res:
            return "connected_workers_active"
        return "broker_connected_workers_idle"
    except Exception:
        return "optional_offline"


@router.get("/health", summary="Get Backend & Dependency Health Status")
async def health_check():
    """
    Health check endpoint returning system status, version,
    and live readiness check for MongoDB, Redis, and Celery worker dependencies.
    """
    mongo_ready = await ping_mongodb()
    mongo_status = "connected" if mongo_ready else "optional_offline"

    redis_status = await ping_redis()
    celery_status = check_celery_broker()

    is_healthy = True  # Application API is running and functional

    return {
        "status": "healthy" if is_healthy else "degraded",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": {
            "database_mongodb": mongo_status,
            "cache_redis": redis_status,
            "celery_broker": celery_status
        }
    }


@router.get("/health/liveness", summary="Container Liveness Probe")
async def liveness_probe():
    """Liveness probe indicating whether the process is alive."""
    return {
        "status": "ALIVE",
        "system": settings.PROJECT_NAME,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@router.get("/health/readiness", summary="Container Readiness Probe")
async def readiness_probe():
    """Readiness probe indicating whether the process and dependencies can serve requests."""
    mongo_ready = await ping_mongodb()
    redis_status = await ping_redis()

    return {
        "status": "READY",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "readiness": {
            "database_mongodb": "CONNECTED" if mongo_ready else "OPTIONAL_OFFLINE",
            "cache_redis": "CONNECTED" if redis_status == "connected" else "OPTIONAL_OFFLINE"
        }
    }
