import pytest
import hashlib
from backend.app.schemas.scan import CreateScanRequest, ScanStatus
from backend.app.schemas.report import AnalysisReportResponse, RiskCategory, MalwareClassification
from backend.app.services.scan_service import ScanService, get_risk_category
from backend.app.repositories.scan_repository import InMemoryScanRepository
from backend.app.core.exceptions import (
    ScanNotFoundException,
    EmptyFileException,
    FileTooLargeException,
    InvalidPEFileException
)
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


@pytest.mark.asyncio
async def test_risk_category_mapping():
    assert get_risk_category(0.10) == RiskCategory.LOW
    assert get_risk_category(0.24) == RiskCategory.LOW
    assert get_risk_category(0.25) == RiskCategory.MEDIUM
    assert get_risk_category(0.49) == RiskCategory.MEDIUM
    assert get_risk_category(0.50) == RiskCategory.HIGH
    assert get_risk_category(0.74) == RiskCategory.HIGH
    assert get_risk_category(0.75) == RiskCategory.CRITICAL
    assert get_risk_category(0.99) == RiskCategory.CRITICAL


@pytest.mark.asyncio
async def test_upload_security_validations():
    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    req = CreateScanRequest(filename="security_test.exe")
    created = await service.create_scan(req)
    scan_id = created.scan_id

    # 1. Empty file
    with pytest.raises(EmptyFileException):
        await service.analyze_pe_scan(scan_id=scan_id, file_bytes=b"", filename="empty.exe")

    # 2. Oversized file (> 50MB)
    huge_bytes = b"MZ" + b"\x00" * (50 * 1024 * 1024 + 1)
    with pytest.raises(FileTooLargeException):
        await service.analyze_pe_scan(scan_id=scan_id, file_bytes=huge_bytes, filename="huge.exe")

    # 3. Missing MZ header
    non_pe_bytes = b"PDF-1.5 fake file format content"
    with pytest.raises(InvalidPEFileException):
        await service.analyze_pe_scan(scan_id=scan_id, file_bytes=non_pe_bytes, filename="fake.pdf")


@pytest.mark.asyncio
async def test_sha256_hash_calculation():
    pe_bytes = build_minimal_pe_bytes()
    expected_sha256 = hashlib.sha256(pe_bytes).hexdigest()

    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    req = CreateScanRequest(filename="hash_test.exe")
    created = await service.create_scan(req)

    # Changing filename parameter must not alter calculated sha256 hash from bytes
    report = await service.analyze_pe_scan(scan_id=created.scan_id, file_bytes=pe_bytes, filename="renamed_sample.exe")

    assert report.file_hash == expected_sha256
    assert report.filename in ("renamed_sample.exe", "hash_test.exe")


@pytest.mark.asyncio
async def test_end_to_end_static_ml_inference_pipeline():
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    # 1. Create scan
    created = await service.create_scan(CreateScanRequest(filename="pipeline_test.exe"))
    scan_id = created.scan_id

    # 2. Execute end-to-end pipeline
    report = await service.analyze_pe_scan(scan_id=scan_id, file_bytes=pe_bytes, filename="pipeline_test.exe")

    assert isinstance(report, AnalysisReportResponse)
    assert report.scan_id == scan_id
    assert report.filename == "pipeline_test.exe"
    assert report.file_size == len(pe_bytes)
    assert len(report.file_hash) == 64
    assert report.model_name == "static_baseline_v2.0"
    assert report.feature_schema_version == "static-v1"
    assert report.dataset_version == "v2.0"
    assert report.dataset_provenance_status == "SYNTHETIC_FIXTURE"
    assert report.threshold == 0.5
    assert 0.0 <= report.malware_score <= 1.0
    assert 0.0 <= report.benign_score <= 1.0
    assert report.risk_category in (RiskCategory.LOW, RiskCategory.MEDIUM, RiskCategory.HIGH, RiskCategory.CRITICAL)

    # Check scan record status in repository
    scan_doc = await service.get_scan(scan_id)
    assert scan_doc.status == ScanStatus.COMPLETED
    assert scan_doc.file_hash == report.file_hash
    assert scan_doc.prediction_reference == f"prediction_res://{scan_id}"
    assert scan_doc.report_reference == f"report_res://{scan_id}"

    # Check report retrieval method
    retrieved_report = await service.get_scan_report(scan_id)
    assert retrieved_report.scan_id == scan_id
    assert retrieved_report.file_hash == report.file_hash


@pytest.mark.asyncio
async def test_inference_pipeline_idempotency():
    pe_bytes = build_minimal_pe_bytes()
    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    created = await service.create_scan(CreateScanRequest(filename="idempotency_test.exe"))
    scan_id = created.scan_id

    # First analysis run
    report1 = await service.analyze_pe_scan(scan_id=scan_id, file_bytes=pe_bytes, filename="idempotency_test.exe")
    assert report1.scan_id == scan_id

    # Second analysis run on completed scan should return cached report without error
    report2 = await service.analyze_pe_scan(scan_id=scan_id, file_bytes=pe_bytes, filename="idempotency_test.exe")
    assert report2.scan_id == scan_id
    assert report2.file_hash == report1.file_hash
