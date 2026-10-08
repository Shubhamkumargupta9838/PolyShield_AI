"""Unit tests for Ensemble Component Decomposition Explainer (Phase 12)."""

import pytest
from ml.models.prediction_schema import PredictionResult, EnsembleMode
from ml.explainability.ensemble_explainer import EnsembleExplainer
from ml.explainability.schemas import EnsembleDecomposition


def test_both_modalities_ensemble_decomposition():
    """Verify equal-weight component contributions when both modalities are available."""
    explainer = EnsembleExplainer(static_weight=0.5, dynamic_weight=0.5)
    pred = PredictionResult(
        scan_id="test_ens_1",
        sample_sha256="c" * 64,
        static_probability=0.80,
        dynamic_probability=0.60,
        ensemble_probability=0.70,
        static_classification="malware",
        dynamic_classification="malware",
        ensemble_classification="malware",
        ensemble_mode=EnsembleMode.BOTH_MODALITIES,
        risk_level="HIGH",
    )

    decomp: EnsembleDecomposition = explainer.explain_ensemble(pred)

    assert decomp.ensemble_mode == "BOTH_MODALITIES"
    assert decomp.static_weight == 0.5
    assert decomp.static_probability == 0.80
    assert decomp.static_component_contribution == 0.40  # 0.5 * 0.80

    assert decomp.dynamic_weight == 0.5
    assert decomp.dynamic_probability == 0.60
    assert decomp.dynamic_component_contribution == 0.30  # 0.5 * 0.60

    assert decomp.ensemble_probability == 0.70
    assert "Static PE model contributed 0.4000" in decomp.explanation_summary
    assert "Dynamic Sandbox LSTM model contributed 0.3000" in decomp.explanation_summary


def test_static_only_ensemble_decomposition():
    """Verify component contribution when dynamic modality is missing."""
    explainer = EnsembleExplainer(static_weight=0.5, dynamic_weight=0.5)
    pred = PredictionResult(
        scan_id="test_ens_static_only",
        sample_sha256="d" * 64,
        static_probability=0.75,
        dynamic_probability=None,
        ensemble_probability=0.75,
        static_classification="malware",
        dynamic_classification=None,
        ensemble_classification="malware",
        ensemble_mode=EnsembleMode.STATIC_ONLY,
        risk_level="HIGH",
    )

    decomp = explainer.explain_ensemble(pred)

    assert decomp.ensemble_mode == "STATIC_ONLY"
    assert decomp.static_probability == 0.75
    assert decomp.static_component_contribution == 0.75
    assert decomp.dynamic_probability is None
    assert decomp.dynamic_component_contribution is None
    assert "Dynamic sandbox execution telemetry was unavailable" in decomp.explanation_summary
