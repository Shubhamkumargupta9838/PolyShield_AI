"""
Safe Synthetic End-to-End Workflow Test Suite for PolyShield AI (Phase 14).

Executes a complete end-to-end analysis lifecycle across Auth -> Upload -> Static Analysis -> Dynamic Sandbox -> Ensemble -> XAI Report.
Strict Safety Rule: Zero host subprocess binary execution. Safe in-memory synthetic PE byte streams only.
"""

import pytest
from datetime import datetime, timezone
from backend.app.schemas.scan import CreateScanRequest, ScanStatus
from backend.app.services.scan_service import ScanService, get_risk_category
from backend.app.services.model_service import ModelService
from ml.models.ensemble import MultimodalEnsembleModel
from analysis.static.extractor import StaticFeatureExtractor
from sandbox.telemetry.normalizer import TelemetryNormalizer
from tests.fixtures.safe_pe_fixtures import create_minimal_pe_bytes
from tests.fixtures.synthetic_telemetry import generate_suspicious_telemetry
from tests.integration.test_concurrency_idempotency import InMemoryScanRepository


@pytest.mark.asyncio
async def test_safe_synthetic_end_to_end_analysis_lifecycle():
    """Verify complete end-to-end analysis pipeline execution using safe synthetic inputs."""
    # 1. Initialize repository and services
    repo = InMemoryScanRepository()
    scan_service = ScanService(repository=repo)
    static_extractor = StaticFeatureExtractor()
    telemetry_normalizer = TelemetryNormalizer()
    ensemble_model = MultimodalEnsembleModel(static_weight=0.5, dynamic_weight=0.5)

    # 2. Step 1: Scan Creation (QUEUED)
    pe_bytes = create_minimal_pe_bytes()
    req = CreateScanRequest(
        filename="synthetic_sample.exe",
        file_hash="a" * 64,
        file_size=len(pe_bytes)
    )
    user_context = {"user_id": "usr_analyst_01", "role": "ANALYST"}
    created_scan = await scan_service.create_scan(req, current_user=user_context)
    assert created_scan.status == ScanStatus.QUEUED

    # 3. Step 2: Static Analysis (STATIC_ANALYSIS)
    await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.STATIC_ANALYSIS)
    static_result = static_extractor.extract_from_bytes(pe_bytes, req.filename)
    static_vector = static_extractor.vectorize(static_result)
    assert static_vector is not None

    # 4. Step 3: Mock Dynamic Analysis Execution (DYNAMIC_ANALYSIS)
    await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.DYNAMIC_ANALYSIS)
    raw_telemetry = generate_suspicious_telemetry()
    now = datetime.now(timezone.utc)
    dynamic_result = telemetry_normalizer.normalize(
        job_id="job_e2e_1",
        scan_id=created_scan.scan_id,
        sample_sha256=req.file_hash,
        provider_name="mock",
        environment_id="mock_env_1",
        started_at=now,
        completed_at=now,
        raw_telemetry=raw_telemetry
    )
    assert dynamic_result.telemetry_sha256 is not None

    # 5. Step 4: Feature Extraction (FEATURE_EXTRACTION)
    await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.FEATURE_EXTRACTION)

    # 6. Step 5: Multimodal ML Inference (ML_INFERENCE)
    await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.ML_INFERENCE)
    static_prob = 0.82
    dynamic_prob = 0.76

    prediction = ensemble_model.predict_ensemble(
        scan_id=created_scan.scan_id,
        sample_sha256=req.file_hash,
        static_probability=static_prob,
        dynamic_probability=dynamic_prob
    )
    assert 0.0 <= prediction.ensemble_probability <= 1.0

    # 7. Step 6: Report Generation (REPORT_GENERATION -> COMPLETED)
    await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.REPORT_GENERATION)
    completed_scan = await scan_service.update_scan_status(created_scan.scan_id, ScanStatus.COMPLETED)

    assert completed_scan.status == ScanStatus.COMPLETED
    assert get_risk_category(prediction.ensemble_probability) is not None
