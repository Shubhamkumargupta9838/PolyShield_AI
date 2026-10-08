import os
import pytest
import hashlib
from pathlib import Path
from backend.app.schemas.scan import CreateScanRequest, ScanStatus
from backend.app.schemas.report import AnalysisReportResponse, RiskCategory
from backend.app.services.scan_service import ScanService
from backend.app.services.storage_service import LocalStorageService, MockStorageService
from backend.app.repositories.scan_repository import InMemoryScanRepository
from backend.app.workers.celery_app import celery_app
from backend.app.workers.analysis_tasks import analyze_scan_task
from backend.app.core.exceptions import (
    EmptyFileException,
    FileTooLargeException,
    InvalidPEFileException
)
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


@pytest.fixture(autouse=True)
def configure_celery_eager():
    """Ensure Celery runs synchronously in-process during unit tests."""
    original_eager = celery_app.conf.task_always_eager
    celery_app.conf.task_always_eager = True
    yield
    celery_app.conf.task_always_eager = original_eager


def test_local_storage_service(tmp_path):
    storage = LocalStorageService(base_dir=str(tmp_path))
    scan_id = "test-scan-uuid-1234"
    sample_bytes = b"MZ\x90\x00DummyBinaryBytes"
    
    # Save
    ref = storage.save_sample(scan_id, sample_bytes, "test.exe")
    assert ref == f"file_storage://{scan_id}"
    assert storage.exists(scan_id) is True

    # Read
    retrieved = storage.get_sample(scan_id)
    assert retrieved == sample_bytes

    # Path traversal rejection
    with pytest.raises(ValueError, match="Invalid or unsafe storage reference"):
        storage.get_path_for_scan("../../../etc/passwd")

    # Delete
    deleted = storage.delete_sample(scan_id)
    assert deleted is True
    assert storage.exists(scan_id) is False


@pytest.mark.asyncio
async def test_enqueue_scan_analysis_non_blocking():
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    mock_storage = MockStorageService()
    service = ScanService(repository=repo, storage_service=mock_storage)

    req = CreateScanRequest(filename="async_enqueue_test.exe")
    created = await service.create_scan(req)
    scan_id = created.scan_id

    # Enqueue analysis
    response = await service.enqueue_scan_analysis(scan_id=scan_id, file_bytes=pe_bytes, filename="async_enqueue_test.exe")
    
    assert response.scan_id == scan_id
    assert response.status == ScanStatus.QUEUED
    assert mock_storage.exists(scan_id) is True


@pytest.mark.asyncio
async def test_celery_task_execution_eager():
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    mock_storage = MockStorageService()
    service = ScanService(repository=repo, storage_service=mock_storage)

    req = CreateScanRequest(filename="celery_eager_test.exe")
    created = await service.create_scan(req)
    scan_id = created.scan_id

    # Save sample & enqueue
    await service.enqueue_scan_analysis(scan_id=scan_id, file_bytes=pe_bytes, filename="celery_eager_test.exe")

    # Directly run async task pipeline
    report = await service.analyze_pe_scan_async(scan_id)

    assert isinstance(report, AnalysisReportResponse)
    assert report.scan_id == scan_id
    assert report.model_name == "static_baseline_v2.0"
    assert report.dataset_provenance_status == "SYNTHETIC_FIXTURE"

    # Check database state
    scan_doc = await service.get_scan(scan_id)
    assert scan_doc.status == ScanStatus.COMPLETED
    assert scan_doc.report_reference == f"report_res://{scan_id}"


@pytest.mark.asyncio
async def test_task_idempotency():
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    mock_storage = MockStorageService()
    service = ScanService(repository=repo, storage_service=mock_storage)

    created = await service.create_scan(CreateScanRequest(filename="idempotent_worker.exe"))
    scan_id = created.scan_id

    await service.enqueue_scan_analysis(scan_id=scan_id, file_bytes=pe_bytes, filename="idempotent_worker.exe")

    # Run 1
    report1 = await service.analyze_pe_scan_async(scan_id)
    assert report1.scan_id == scan_id

    # Run 2 on COMPLETED scan should return cached report without error
    report2 = await service.analyze_pe_scan_async(scan_id)
    assert report2.scan_id == scan_id
    assert report2.file_hash == report1.file_hash


@pytest.mark.asyncio
async def test_worker_error_handling():
    repo = InMemoryScanRepository()
    mock_storage = MockStorageService()
    service = ScanService(repository=repo, storage_service=mock_storage)

    created = await service.create_scan(CreateScanRequest(filename="missing_file.exe"))
    scan_id = created.scan_id

    # No file stored in storage, trying to run worker pipeline must transition scan to FAILED
    with pytest.raises(InvalidPEFileException) as exc_info:
        await service.analyze_pe_scan_async(scan_id)

    assert "not found in storage" in str(exc_info.value)
    scan_doc = await service.get_scan(scan_id)
    assert scan_doc.status == ScanStatus.FAILED
    assert scan_doc.error is not None


@pytest.mark.asyncio
async def test_benign_file_upload_stores_payload_and_worker_retrieves(tmp_path):
    """
    Regression test:
    Verifies successful benign file upload creates and stores payload reference in storage,
    and worker analyze_pe_scan_async retrieves stored payload via scan_id.
    """
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    local_storage = LocalStorageService(base_dir=str(tmp_path))
    service = ScanService(repository=repo, storage_service=local_storage)

    created = await service.create_scan(CreateScanRequest(filename="benign_sample.exe"))
    scan_id = created.scan_id

    # Upload & enqueue
    scan_resp = await service.enqueue_scan_analysis(scan_id=scan_id, file_bytes=pe_bytes, filename="benign_sample.exe")
    assert scan_resp.status == ScanStatus.QUEUED
    assert local_storage.exists(scan_id) is True

    # Worker retrieves payload & runs analysis
    report = await service.analyze_pe_scan_async(scan_id)
    assert report.scan_id == scan_id
    assert report.classification in ["BENIGN", "MALICIOUS"]

    updated_scan = await service.get_scan(scan_id)
    assert updated_scan.status == ScanStatus.COMPLETED

