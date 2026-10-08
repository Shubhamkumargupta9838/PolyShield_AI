import pytest
from datetime import timedelta
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token, decode_access_token, hash_password, verify_password
from backend.app.core.exceptions import AuthenticationException

client = TestClient(app)


def test_password_hashing_and_verification():
    raw_pass = "SuperSecurePassword123!"
    hashed = hash_password(raw_pass)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False


def test_jwt_token_generation_and_decoding():
    token_data = {"sub": "usr_test123", "username": "analyst_test", "role": "ANALYST"}
    token = create_access_token(token_data)
    decoded = decode_access_token(token)

    assert decoded["sub"] == "usr_test123"
    assert decoded["username"] == "analyst_test"
    assert decoded["role"] == "ANALYST"
    assert decoded["iss"] == "polyshield"
    assert decoded["aud"] == "polyshield-api"


def test_jwt_expired_token_rejection():
    token_data = {"sub": "usr_test123", "username": "analyst_test", "role": "ANALYST"}
    token = create_access_token(token_data, expires_delta=timedelta(seconds=-10))

    with pytest.raises(AuthenticationException) as exc_info:
        decode_access_token(token)
    assert "expired" in str(exc_info.value).lower()


def test_jwt_alg_none_rejection():
    # Attempting to craft a token with alg = none
    import jwt
    none_token = jwt.encode({"sub": "usr_hacker"}, key="", algorithm="none")

    with pytest.raises(AuthenticationException) as exc_info:
        decode_access_token(none_token)
    assert "forbidden" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()


def test_unauthenticated_request_response():
    response = client.get("/api/v1/scans/non_existent_scan_id")
    # Depends on AUTH_ENABLED setting
    assert response.status_code in [401, 404]
