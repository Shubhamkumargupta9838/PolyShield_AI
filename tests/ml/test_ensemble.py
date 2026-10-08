"""Unit Tests for Multimodal Ensemble Model & Ablation Evaluation (Phase 11)."""

import pytest
import numpy as np

from ml.models.prediction_schema import PredictionResult, EnsembleMode, DynamicQualityStatus
from ml.models.ensemble import MultimodalEnsembleModel
from ml.evaluation.ensemble_evaluation import EnsembleEvaluator


def test_ensemble_equal_weight_fusion():
    """Verify equal weight fusion calculation (0.5 * static + 0.5 * dynamic)."""
    model = MultimodalEnsembleModel(static_weight=0.5, dynamic_weight=0.5)

    res = model.predict_ensemble(
        scan_id="scan-123",
        sample_sha256="a" * 64,
        static_probability=0.60,
        dynamic_probability=0.80,
    )

    assert res.ensemble_mode == EnsembleMode.BOTH_MODALITIES
    assert res.ensemble_probability == 0.70
    assert res.ensemble_classification == "malware"
    assert res.risk_level == "HIGH"


def test_ensemble_missing_modalities():
    """Verify fallback behavior when static or dynamic modality is missing."""
    model = MultimodalEnsembleModel()

    # 1. Static Only
    res_static = model.predict_ensemble(
        scan_id="scan-1",
        sample_sha256="a" * 64,
        static_probability=0.40,
        dynamic_probability=None,
    )
    assert res_static.ensemble_mode == EnsembleMode.STATIC_ONLY
    assert res_static.ensemble_probability == 0.40
    assert res_static.available_modalities == ["static"]

    # 2. Dynamic Only
    res_dyn = model.predict_ensemble(
        scan_id="scan-2",
        sample_sha256="b" * 64,
        static_probability=None,
        dynamic_probability=0.90,
        dynamic_sequence_length=15,
    )
    assert res_dyn.ensemble_mode == EnsembleMode.DYNAMIC_ONLY
    assert res_dyn.ensemble_probability == 0.90
    assert res_dyn.available_modalities == ["dynamic"]

    # 3. Neither Available (Must raise ValueError)
    with pytest.raises(ValueError, match="neither static nor dynamic probability provided"):
        model.predict_ensemble(scan_id="scan-3", sample_sha256="c" * 64)


def test_ensemble_dynamic_quality_assessment():
    """Verify quality status gating for telemetry sequence properties."""
    model = MultimodalEnsembleModel()

    # Valid telemetry
    q_valid = model.assess_dynamic_quality(raw_events_count=10, unknown_event_rate=0.05)
    assert q_valid == DynamicQualityStatus.VALID

    # Low signal telemetry (high unknown event rate or very short sequence)
    q_low = model.assess_dynamic_quality(raw_events_count=1, unknown_event_rate=0.75)
    assert q_low == DynamicQualityStatus.LOW_SIGNAL

    # Unavailable telemetry (0 events)
    q_unavail = model.assess_dynamic_quality(raw_events_count=0, unknown_event_rate=0.0)
    assert q_unavail == DynamicQualityStatus.UNAVAILABLE


def test_probability_boundary_and_invalid_values():
    """Verify risk mapping and rejection of invalid NaN/Inf probability inputs."""
    model = MultimodalEnsembleModel()

    # Probability boundaries
    assert model.get_risk_level(0.0) == "LOW"
    assert model.get_risk_level(0.24) == "LOW"
    assert model.get_risk_level(0.25) == "MEDIUM"
    assert model.get_risk_level(0.49) == "MEDIUM"
    assert model.get_risk_level(0.50) == "HIGH"
    assert model.get_risk_level(0.74) == "HIGH"
    assert model.get_risk_level(0.75) == "CRITICAL"
    assert model.get_risk_level(1.0) == "CRITICAL"

    # Reject NaN / Inf
    with pytest.raises(ValueError):
        model.predict_ensemble(scan_id="s1", sample_sha256="a"*64, static_probability=float("nan"), dynamic_probability=0.5)

    with pytest.raises(ValueError):
        model.predict_ensemble(scan_id="s1", sample_sha256="a"*64, static_probability=0.5, dynamic_probability=float("inf"))


def test_ablation_evaluator_smoke(tmp_path):
    """Verify ablation evaluator compares static-only, dynamic-only, and ensemble models."""
    evaluator = EnsembleEvaluator(static_weight=0.5, dynamic_weight=0.5)

    y_true = np.array([0, 0, 1, 1])
    static_probs = np.array([0.1, 0.4, 0.6, 0.8])
    dynamic_probs = np.array([0.2, 0.3, 0.7, 0.9])

    report = evaluator.evaluate_ablation(y_true, static_probs, dynamic_probs, artifacts_dir=tmp_path)

    assert report["dataset_provenance_status"] == "SYNTHETIC_FIXTURE"
    assert report["ablation_status"] == "ENGINEERING_ONLY"
    assert "models" in report
    assert "static_only" in report["models"]
    assert "dynamic_only" in report["models"]
    assert "ensemble" in report["models"]
    assert (tmp_path / "ensemble_evaluation_v1.0.json").exists()
