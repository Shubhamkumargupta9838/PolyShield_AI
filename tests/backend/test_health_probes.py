"""
Health Probes & Readiness Endpoint Unit Test Suite (Phase 15).

Verifies Liveness (/api/v1/health/liveness), Readiness (/api/v1/health/readiness),
and System Health (/api/v1/health) endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_system_health_endpoint():
    """Verify /api/v1/health returns 200 with system info and service statuses."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "system" in data
    assert "version" in data
    assert "services" in data
    assert "database_mongodb" in data["services"]
    assert "cache_redis" in data["services"]


def test_liveness_probe_endpoint():
    """Verify /api/v1/health/liveness returns 200 with ALIVE status."""
    response = client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ALIVE"
    assert "timestamp" in data


def test_readiness_probe_endpoint():
    """Verify /api/v1/health/readiness returns 200 with READY status and dependency checks."""
    response = client.get("/api/v1/health/readiness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "READY"
    assert "readiness" in data
    assert "database_mongodb" in data["readiness"]
    assert "cache_redis" in data["readiness"]
