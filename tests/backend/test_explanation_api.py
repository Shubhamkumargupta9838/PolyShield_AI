"""API Integration Tests for Phase 12 Explainable AI Endpoints."""

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
async def test_explanation_api_flow(test_repo, test_service):
    """Verify static analysis, dynamic analysis, ensemble inference, and explanation endpoints."""
    get_scan_service._in_memory_repo = test_repo
    app.dependency_overrides[get_scan_service] = lambda: test_service

    try:
        pe_bytes = build_minimal_pe_bytes()
        file_hash = hashlib.sha256(pe_bytes).hexdigest()

        # 1. Create scan
        created = await test_service.create_scan(CreateScanRequest(filename="exp_inf_test.exe", file_hash=file_hash, file_size=len(pe_bytes)))
        scan_id = created.scan_id

        # 2. Save sample to storage & perform static and dynamic analysis
        test_service.storage_service.save_sample(scan_id, pe_bytes, "exp_inf_test.exe")
        await test_service.analyze_pe_scan_async(scan_id)
        await test_service.analyze_pe_scan_dynamic_async(scan_id)

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 3. POST explanation generation
            exp_res = await client.post(f"/api/v1/scans/{scan_id}/explanation")
            assert exp_res.status_code == 200
            exp_data = exp_res.json()

            assert exp_data["scan_id"] == scan_id
            assert exp_data["explanation_version"] == "explanation_v1.0"
            assert "static_explanation" in exp_data
            assert "dynamic_explanation" in exp_data
            assert "ensemble_decomposition" in exp_data
            assert "observed_evidence" in exp_data
            assert len(exp_data["observed_evidence"]) >= 4

            # Verify observed evidence facts vs attributions distinction
            obs_names = [item["metric_name"] for item in exp_data["observed_evidence"]]
            assert "max_section_entropy" in obs_names

            # Static SHAP attributions
            static_exp = exp_data["static_explanation"]
            assert static_exp["explainer_type"] == "SHAP_TreeExplainer"
            assert len(static_exp["attributions"]) == 17
            assert len(static_exp["top_k_attributions"]) == 5

            # 4. GET explanation result
            get_res = await client.get(f"/api/v1/scans/{scan_id}/explanation")
            assert get_res.status_code == 200
            assert get_res.json()["scan_id"] == scan_id
            assert get_res.json()["explanation_version"] == "explanation_v1.0"
    finally:
        app.dependency_overrides.clear()
