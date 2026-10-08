import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_cors_headers_allowed_origin():
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_cors_disallowed_origin():
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://malicious-attacker-site.com",
            "Access-Control-Request-Method": "GET"
        }
    )
    assert response.headers.get("access-control-allow-origin") != "http://malicious-attacker-site.com"
