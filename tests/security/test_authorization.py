import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token
from backend.app.api.dependencies import check_scan_ownership
from fastapi import HTTPException

client = TestClient(app)


@pytest.mark.asyncio
async def test_scan_ownership_authorization():
    user_a = {"user_id": "usr_analyst_a", "username": "analyst_a", "role": "ANALYST"}
    user_b = {"user_id": "usr_analyst_b", "username": "analyst_b", "role": "ANALYST"}
    admin = {"user_id": "usr_admin", "username": "admin_user", "role": "ADMIN"}

    scan_a = {"scan_id": "scan_100", "owner_id": "usr_analyst_a", "filename": "sample.exe"}

    # User A -> User A scan = ALLOWED
    assert await check_scan_ownership(scan_a, user_a) is True

    # Admin -> User A scan = ALLOWED
    assert await check_scan_ownership(scan_a, admin) is True

    # User B -> User A scan = FORBIDDEN (HTTP 403)
    with pytest.raises(HTTPException) as exc_info:
        await check_scan_ownership(scan_a, user_b)
    assert exc_info.value.status_code == 403


def test_endpoint_authorization_token_role():
    token_analyst = create_access_token({"sub": "usr_analyst_a", "username": "analyst_a", "role": "ANALYST"})
    headers = {"Authorization": f"Bearer {token_analyst}"}

    response = client.get("/api/v1/scans", headers=headers)
    assert response.status_code == 200
