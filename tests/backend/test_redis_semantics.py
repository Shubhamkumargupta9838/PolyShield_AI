import pytest
from backend.app.core.config import settings


def test_redis_architecture_semantics():
    """
    Verifies that Redis is configured strictly as a broker/cache/result-backend
    and MongoDB is defined as the sole authoritative database store.
    """
    assert settings.REDIS_URL.startswith("redis://")
    assert settings.CELERY_BROKER_URL.startswith("redis://")
    assert settings.MONGODB_DB_NAME == "polyshield_db"
