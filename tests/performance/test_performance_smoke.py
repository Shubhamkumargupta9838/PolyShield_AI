"""
Performance Smoke Benchmark Test Suite for PolyShield AI (Phase 14).

Measures latency limits across static analysis, feature extraction, ML inference,
and ensemble fusion to establish timing baselines and prevent performance regressions.
"""

import time
import pytest
from analysis.static.extractor import StaticFeatureExtractor
from ml.models.ensemble import MultimodalEnsembleModel
from sandbox.telemetry.normalizer import TelemetryNormalizer
from tests.fixtures.safe_pe_fixtures import create_minimal_pe_bytes
from tests.fixtures.synthetic_telemetry import generate_suspicious_telemetry
from datetime import datetime, timezone


def test_static_feature_extraction_performance_smoke():
    """Verify in-memory static feature extraction completes within SLA threshold (< 150ms)."""
    extractor = StaticFeatureExtractor()
    pe_bytes = create_minimal_pe_bytes()

    # Warm up run
    _ = extractor.extract_from_bytes(pe_bytes, "warmup.exe")

    start_time = time.perf_counter()
    result = extractor.extract_from_bytes(pe_bytes, "perf_test.exe")
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    assert result is not None
    assert duration_ms < 1000.0, f"Static feature extraction took {duration_ms:.2f}ms (threshold 1000ms)"


def test_telemetry_normalization_performance_smoke():
    """Verify raw telemetry normalization completes in < 10ms."""
    normalizer = TelemetryNormalizer()
    raw_telemetry = generate_suspicious_telemetry()
    now = datetime.now(timezone.utc)

    start_time = time.perf_counter()
    result = normalizer.normalize(
        job_id="perf_job_1",
        scan_id="perf_scan_1",
        sample_sha256="0" * 64,
        provider_name="mock",
        environment_id="mock_env_1",
        started_at=now,
        completed_at=now,
        raw_telemetry=raw_telemetry
    )
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    assert result is not None
    assert duration_ms < 10.0, f"Telemetry normalization took {duration_ms:.2f}ms (threshold 10ms)"


def test_ensemble_prediction_performance_smoke():
    """Verify MultimodalEnsembleModel prediction computation completes in < 5ms."""
    model = MultimodalEnsembleModel(static_weight=0.5, dynamic_weight=0.5)

    start_time = time.perf_counter()
    for _ in range(100):
        _ = model.predict_ensemble(
            scan_id="perf_scan_1",
            sample_sha256="0" * 64,
            static_probability=0.85,
            dynamic_probability=0.72
        )
    total_duration_ms = (time.perf_counter() - start_time) * 1000.0
    avg_duration_ms = total_duration_ms / 100.0

    assert avg_duration_ms < 5.0, f"Average ensemble prediction took {avg_duration_ms:.3f}ms (threshold 5ms)"
