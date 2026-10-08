"""API & Celery Integration Tests for Phase 10 Dynamic LSTM Sequence Inference."""

import hashlib
import pytest
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.schemas.scan import CreateScanRequest
from backend.app.repositories.scan_repository import InMemoryScanRepository
from backend.app.api.scans import get_scan_service
from backend.app.services.scan_service import ScanService


@pytest.fixture
def test_repo():
    return InMemoryScanRepository()


@pytest.fixture
def test_service(test_repo):
    return ScanService(repository=test_repo)


@pytest.mark.asyncio
async def test_dynamic_inference_flow(test_repo, test_service):
    """Verify dynamic sandbox analysis followed by dynamic LSTM sequence inference API endpoints."""
    get_scan_service._in_memory_repo = test_repo
    app.dependency_overrides[get_scan_service] = lambda: test_service

    try:
        pe_bytes = b"MZ" + b"\x90" * 100
        file_hash = hashlib.sha256(pe_bytes).hexdigest()

        # 1. Create scan
        created = await test_service.create_scan(CreateScanRequest(filename="dyn_inf_test.exe", file_hash=file_hash, file_size=len(pe_bytes)))
        scan_id = created.scan_id

        # 2. Save sample to storage
        test_service.storage_service.save_sample(scan_id, pe_bytes, "dyn_inf_test.exe")

        # 3. Perform dynamic analysis execution
        await test_service.analyze_pe_scan_dynamic_async(scan_id)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 4. Post dynamic sequence LSTM inference
            inf_res = await client.post(f"/api/v1/scans/{scan_id}/dynamic-inference")
            assert inf_res.status_code == 200
            inf_data = inf_res.json()

            assert inf_data["scan_id"] == scan_id
            assert inf_data["model_version"] == "dynamic_lstm_v1.0"
            assert inf_data["classification"] in ["malware", "benign"]
            assert "malware_probability" in inf_data
            assert "sequence_length" in inf_data

            # 5. GET dynamic inference result
            get_res = await client.get(f"/api/v1/scans/{scan_id}/dynamic-inference")
            assert get_res.status_code == 200
            assert get_res.json()["scan_id"] == scan_id
    finally:
        app.dependency_overrides.clear()
