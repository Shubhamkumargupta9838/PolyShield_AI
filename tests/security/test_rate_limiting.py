import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_rate_limiting_middleware_configured():
    # Verify limiter attribute exists on app state
    assert hasattr(app.state, "limiter")
    # Health endpoint check
    response = client.get("/api/v1/health")
    assert response.status_code == 200
