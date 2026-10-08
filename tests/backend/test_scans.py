import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.schemas.scan import ScanStatus
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


@pytest.mark.asyncio
async def test_create_scan_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "filename": "suspicious_payload.exe",
            "file_hash": "a" * 64,
            "file_size": 204800
        }
        response = await client.post("/api/v1/scans", json=payload)

    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == ScanStatus.QUEUED.value
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_scan_validation_error():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"file_size": 100}
        response = await client.post("/api/v1/scans", json=payload)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_scan_by_id_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create_res = await client.post("/api/v1/scans", json={"filename": "test_sample.exe"})
        scan_id = create_res.json()["scan_id"]

        get_res = await client.get(f"/api/v1/scans/{scan_id}")

    assert get_res.status_code == 200
    data = get_res.json()
    assert data["scan_id"] == scan_id
    assert data["filename"] == "test_sample.exe"
    assert data["status"] == ScanStatus.QUEUED.value


@pytest.mark.asyncio
async def test_get_scan_not_found():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scans/non_existent_uuid_12345")

    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == "SCAN_NOT_FOUND"


@pytest.mark.asyncio
async def test_list_scans_pagination():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(5):
            await client.post("/api/v1/scans", json={"filename": f"sample_{i}.exe"})

        res = await client.get("/api/v1/scans?page=1&page_size=2")

    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert len(data["items"]) == 2
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total"] >= 5


@pytest.mark.asyncio
async def test_valid_scan_status_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/api/v1/scans", json={"filename": "lifecycle.exe"})
        scan_id = c_res.json()["scan_id"]

        lifecycle = [
            ScanStatus.STATIC_ANALYSIS,
            ScanStatus.DYNAMIC_ANALYSIS,
            ScanStatus.FEATURE_EXTRACTION,
            ScanStatus.ML_INFERENCE,
            ScanStatus.REPORT_GENERATION,
            ScanStatus.COMPLETED
        ]

        for next_status in lifecycle:
            patch_res = await client.patch(
                f"/api/v1/scans/{scan_id}/status",
                json={"status": next_status.value}
            )
            assert patch_res.status_code == 200
            assert patch_res.json()["status"] == next_status.value


@pytest.mark.asyncio
async def test_invalid_status_transition():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/api/v1/scans", json={"filename": "invalid_step.exe"})
        scan_id = c_res.json()["scan_id"]

        patch_res = await client.patch(
            f"/api/v1/scans/{scan_id}/status",
            json={"status": ScanStatus.COMPLETED.value}
        )

    assert patch_res.status_code == 409
    data = patch_res.json()
    assert data["error_code"] == "INVALID_STATE_TRANSITION"


@pytest.mark.asyncio
async def test_transition_to_failed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/api/v1/scans", json={"filename": "corrupted.exe"})
        scan_id = c_res.json()["scan_id"]

        patch_res = await client.patch(
            f"/api/v1/scans/{scan_id}/status",
            json={
                "status": ScanStatus.FAILED.value,
                "error_information": "Corrupted PE header detected."
            }
        )

    assert patch_res.status_code == 200
    data = patch_res.json()
    assert data["status"] == ScanStatus.FAILED.value
    assert data["error"] == "Corrupted PE header detected."


# ------------------- PHASE 3 STATIC ANALYSIS ENDPOINT TESTS ------------------- #
@pytest.mark.asyncio
async def test_perform_static_analysis_api_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create scan record
        c_res = await client.post("/api/v1/scans", json={"filename": "benign.exe"})
        scan_id = c_res.json()["scan_id"]

        # Build benign PE fixture bytes
        pe_bytes = build_minimal_pe_bytes()

        # Perform static analysis upload
        files = {"file": ("benign.exe", pe_bytes, "application/octet-stream")}
        res = await client.post(f"/api/v1/scans/{scan_id}/static-analysis", files=files)

    assert res.status_code == 200
    data = res.json()
    assert data["file"]["filename"] == "benign.exe"
    assert "pe" in data
    assert data["pe"]["architecture"] == "x86 (32-bit)"
    assert "sections" in data
    assert len(data["sections"]) == 1
    assert "entropy" in data
    assert "indicators" in data

    # Verify scan status transitioned to STATIC_ANALYSIS
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        scan_check = await client.get(f"/api/v1/scans/{scan_id}")
        assert scan_check.json()["status"] == ScanStatus.STATIC_ANALYSIS.value
        assert scan_check.json()["static_analysis_reference"] is not None


@pytest.mark.asyncio
async def test_perform_static_analysis_invalid_pe():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        c_res = await client.post("/api/v1/scans", json={"filename": "invalid.txt"})
        scan_id = c_res.json()["scan_id"]

        invalid_file = {"file": ("invalid.txt", b"NOT A PE FILE DATA", "text/plain")}
        res = await client.post(f"/api/v1/scans/{scan_id}/static-analysis", files=invalid_file)

    assert res.status_code == 400
    data = res.json()
    assert data["error_code"] == "INVALID_PE_FILE"


@pytest.mark.asyncio
async def test_perform_static_analysis_missing_scan():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        pe_bytes = build_minimal_pe_bytes()
        files = {"file": ("benign.exe", pe_bytes, "application/octet-stream")}
        res = await client.post("/api/v1/scans/missing-scan-uuid-123/static-analysis", files=files)

    assert res.status_code == 404
    assert res.json()["error_code"] == "SCAN_NOT_FOUND"
