"""API & Celery Integration Tests for Phase 11 Multimodal Ensemble Model."""

import hashlib
import pytest
from httpx import AsyncClient, ASGITransport

from backend.app.main import app
from backend.app.schemas.scan import CreateScanRequest
from backend.app.repositories.scan_repository import InMemoryScanRepository
from backend.app.api.scans import get_scan_service
from backend.app.services.scan_service import ScanService


from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


@pytest.fixture
def test_repo():
    return InMemoryScanRepository()


@pytest.fixture
def test_service(test_repo):
    return ScanService(repository=test_repo)


@pytest.mark.asyncio
async def test_ensemble_inference_flow(test_repo, test_service):
    """Verify static analysis, dynamic analysis, and multimodal ensemble inference endpoints."""
    get_scan_service._in_memory_repo = test_repo
    app.dependency_overrides[get_scan_service] = lambda: test_service

    try:
        pe_bytes = build_minimal_pe_bytes()
        file_hash = hashlib.sha256(pe_bytes).hexdigest()

        # 1. Create scan
        created = await test_service.create_scan(CreateScanRequest(filename="ens_inf_test.exe", file_hash=file_hash, file_size=len(pe_bytes)))
        scan_id = created.scan_id

        # 2. Save sample to storage
        test_service.storage_service.save_sample(scan_id, pe_bytes, "ens_inf_test.exe")

        # 3. Perform static and dynamic analysis
        await test_service.analyze_pe_scan_async(scan_id)
        await test_service.analyze_pe_scan_dynamic_async(scan_id)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 4. POST ensemble inference
            ens_res = await client.post(f"/api/v1/scans/{scan_id}/ensemble-inference")
            assert ens_res.status_code == 200
            ens_data = ens_res.json()

            assert ens_data["scan_id"] == scan_id
            assert ens_data["ensemble_version"] == "ensemble_v1.0"
            assert ens_data["ensemble_classification"] in ["malware", "benign"]
            assert ens_data["ensemble_mode"] in ["BOTH_MODALITIES", "STATIC_ONLY", "DYNAMIC_ONLY"]
            assert "ensemble_probability" in ens_data
            assert ens_data["dataset_provenance_status"] == "SYNTHETIC_FIXTURE"

            # 5. GET ensemble inference result
            get_res = await client.get(f"/api/v1/scans/{scan_id}/ensemble-inference")
            assert get_res.status_code == 200
            assert get_res.json()["scan_id"] == scan_id
            assert get_res.json()["ensemble_version"] == "ensemble_v1.0"
    finally:
        app.dependency_overrides.clear()
