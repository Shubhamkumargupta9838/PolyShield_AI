import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_nosql_injection_operator_rejection():
    # Attempting to send a dictionary with operator $gt inside a JSON string or field
    malicious_payload = {
        "filename": {"$gt": ""},
        "file_hash": {"$ne": None}
    }
    response = client.post("/api/v1/scans", json=malicious_payload)
    # Strict Pydantic validation rejects dict for str fields with HTTP 422
    assert response.status_code == 422
