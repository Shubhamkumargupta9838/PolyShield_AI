import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token

client = TestClient(app)


def test_artifact_access_unauthorized_user():
    token_a = create_access_token({"sub": "usr_user_a", "username": "user_a", "role": "ANALYST"})
    token_b = create_access_token({"sub": "usr_user_b", "username": "user_b", "role": "ANALYST"})

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User A creates scan
    create_res = client.post("/api/v1/scans", json={"filename": "test_sample.exe"}, headers=headers_a)
    assert create_res.status_code == 201
    scan_id = create_res.json()["scan_id"]

    # User B attempts to fetch User A's dynamic artifacts -> FORBIDDEN (403)
    response_b = client.get(f"/api/v1/scans/{scan_id}/dynamic-analysis/artifacts", headers=headers_b)
    assert response_b.status_code == 403
