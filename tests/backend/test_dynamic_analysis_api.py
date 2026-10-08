import hashlib
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.schemas.scan import CreateScanRequest
from backend.app.services.scan_service import ScanService
from backend.app.repositories.scan_repository import InMemoryScanRepository
from backend.app.api.scans import get_scan_service


@pytest.fixture
def test_repo():
    return InMemoryScanRepository()


@pytest.fixture
def test_service(test_repo):
    return ScanService(repository=test_repo)


@pytest.mark.asyncio
async def test_dynamic_analysis_api_endpoints_flow(test_repo, test_service):
    get_scan_service._in_memory_repo = test_repo
    app.dependency_overrides[get_scan_service] = lambda: test_service
    try:
        pe_bytes = b"MZ" + b"\x90" * 100
        file_hash = hashlib.sha256(pe_bytes).hexdigest()

        # 1. Create scan
        created = await test_service.create_scan(CreateScanRequest(filename="dyn_api_test.exe", file_hash=file_hash, file_size=len(pe_bytes)))
        scan_id = created.scan_id

        # 2. Save sample to storage
        test_service.storage_service.save_sample(scan_id, pe_bytes, "dyn_api_test.exe")

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 3. Post dynamic analysis request (HTTP 202 Accepted)
            response = await client.post(f"/api/v1/scans/{scan_id}/dynamic-analysis")
            assert response.status_code == 202
            res_data = response.json()
            assert res_data["scan_id"] == scan_id

            # 4. Perform dynamic analysis execution
            await test_service.analyze_pe_scan_dynamic_async(scan_id)

            # 5. Get dynamic analysis result
            get_res = await client.get(f"/api/v1/scans/{scan_id}/dynamic-analysis")
            assert get_res.status_code == 200
            dyn_data = get_res.json()
            assert dyn_data["scan_id"] == scan_id
            assert "dynamic_result" in dyn_data
            assert "dynamic_features" in dyn_data
            assert dyn_data["dynamic_features"]["process_count"] >= 1.0

            # 6. Get dynamic analysis artifacts
            art_res = await client.get(f"/api/v1/scans/{scan_id}/dynamic-analysis/artifacts")
            assert art_res.status_code == 200
            art_data = art_res.json()
            assert art_data["scan_id"] == scan_id
            assert "artifact_count" in art_data
    finally:
        app.dependency_overrides.clear()
