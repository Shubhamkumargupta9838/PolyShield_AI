import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.security import create_access_token

client = TestClient(app)


def test_upload_invalid_extension():
    token = create_access_token({"sub": "usr_test", "username": "analyst", "role": "ANALYST"})
    headers = {"Authorization": f"Bearer {token}"}

    # Uploading .pdf or .txt file should be rejected
    files = {"file": ("malicious.txt", b"Hello World text file", "text/plain")}
    response = client.post("/api/v1/scans/test_scan_ext/analyze", files=files, headers=headers)
    assert response.status_code == 400


def test_upload_missing_mz_header():
    token = create_access_token({"sub": "usr_test", "username": "analyst", "role": "ANALYST"})
    headers = {"Authorization": f"Bearer {token}"}

    # Uploading .exe extension but missing MZ magic header
    files = {"file": ("test.exe", b"NOT_MZ_HEADER_DATA", "application/x-msdownload")}
    response = client.post("/api/v1/scans/test_scan_mz/analyze", files=files, headers=headers)
    assert response.status_code == 400


def test_upload_null_byte_filename():
    token = create_access_token({"sub": "usr_test", "username": "analyst", "role": "ANALYST"})
    headers = {"Authorization": f"Bearer {token}"}

    files = {"file": ("sample.exe\x00.pdf", b"MZ_FAKE_HEADER", "application/x-msdownload")}
    response = client.post("/api/v1/scans/test_scan_null/analyze", files=files, headers=headers)
    assert response.status_code == 400
