"""
Property-Based & Invariant Test Suite for PolyShield AI (Phase 14).

Verifies mathematical invariants across static, dynamic, ensemble, and risk scoring pipelines:
1. Risk categories strictly cover [0.0, 1.0] without gaps.
2. Static feature vectors strictly yield 17 numerical float features.
3. Dynamic aggregate vectors strictly yield 14 numerical float features.
4. Ensemble probabilities lie strictly within [0.0, 1.0].
"""

import random
import pytest
from backend.app.services.scan_service import get_risk_category
from backend.app.schemas.report import RiskCategory
from analysis.static.schemas import StaticFeatureVector
from ml.models.ensemble import MultimodalEnsembleModel
from analysis.features.dynamic_features import DYNAMIC_FEATURE_NAMES, DynamicFeatureExtractor
from sandbox.models.sandbox_result import DynamicAnalysisResult
from sandbox.models.sandbox_job import SandboxJobStatus


def test_risk_category_mapping_invariant_across_probability_range():
    """Verify get_risk_category maps every score in [0.0, 1.0] to a valid RiskCategory without exceptions."""
    boundaries = [0.0, 0.2499, 0.25, 0.4999, 0.50, 0.7499, 0.75, 1.0]
    for score in boundaries:
        risk = get_risk_category(score)
        assert isinstance(risk, RiskCategory)

    random.seed(42)
    for _ in range(500):
        score = random.uniform(0.0, 1.0)
        risk = get_risk_category(score)
        assert isinstance(risk, RiskCategory)
        if score < 0.25:
            assert risk == RiskCategory.LOW
        elif score < 0.50:
            assert risk == RiskCategory.MEDIUM
        elif score < 0.75:
            assert risk == RiskCategory.HIGH
        else:
            assert risk == RiskCategory.CRITICAL


def test_ensemble_probability_bounds_invariant():
    """Verify MultimodalEnsembleModel output probability is strictly bounded in [0.0, 1.0] under arbitrary inputs."""
    model = MultimodalEnsembleModel(static_weight=0.5, dynamic_weight=0.5)

    random.seed(42)
    for _ in range(100):
        p_static = random.uniform(0.0, 1.0)
        p_dynamic = random.uniform(0.0, 1.0)

        result = model.predict_ensemble(
            scan_id="scan_inv_1",
            sample_sha256="0" * 64,
            static_probability=p_static,
            dynamic_probability=p_dynamic
        )

        assert 0.0 <= result.ensemble_probability <= 1.0
        assert result.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def test_static_feature_vector_dimension_invariant():
    """Verify StaticFeatureVector vector conversion produces exactly 17 canonical features."""
    sfv = StaticFeatureVector(
        file_size=1024.0,
        number_of_sections=3.0,
        dll_count=5.0,
        api_count=20.0,
        max_section_entropy=6.5,
        min_section_entropy=1.2,
        mean_section_entropy=4.1,
        high_entropy_section_count=1.0,
        executable_section_count=1.0,
        writable_section_count=1.0,
        rwx_section_count=0.0,
        unusual_section_count=0.0,
        resource_count=1.0,
        suspicious_api_count=2.0,
        static_indicator_count=0.0,
        is_dll=0.0,
        is_driver=0.0
    )

    vector = list(sfv.to_dict().values())
    assert len(vector) == 17
    assert len(StaticFeatureVector.feature_names()) == 17


def test_dynamic_feature_vector_dimension_invariant():
    """Verify DynamicFeatureExtractor vector conversion produces exactly 14 canonical features."""
    assert len(DYNAMIC_FEATURE_NAMES) == 14
    result = DynamicAnalysisResult(
        job_id="job_p_1",
        scan_id="scan_p_1",
        sample_sha256="0" * 64,
        provider="mock",
        environment_id="mock_env_1",
        status=SandboxJobStatus.COMPLETED,
        started_at=None,
        completed_at=None,
        execution_duration_seconds=1.0,
        telemetry_sha256="0" * 64,
        process_events=[],
        network_events=[],
        dns_events=[],
        filesystem_events=[],
        registry_events=[],
        api_events=[],
        artifacts=[],
        error=None
    )

    extractor = DynamicFeatureExtractor()
    features = extractor.extract_features(result)
    assert len(features) == 14
    assert list(features.keys()) == DYNAMIC_FEATURE_NAMES
    assert all(isinstance(val, float) for val in features.values())
