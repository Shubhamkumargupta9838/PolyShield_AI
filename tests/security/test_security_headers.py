import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_http_security_headers_present():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "content-security-policy" in response.headers
    assert "x-request-id" in response.headers
