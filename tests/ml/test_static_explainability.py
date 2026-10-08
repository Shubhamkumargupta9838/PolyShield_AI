"""Unit tests for Static PE SHAP Explainer (Phase 12)."""

import pytest
import numpy as np
from analysis.static.schemas import StaticFeatureVector
from ml.explainability.static_explainer import StaticSHAPExplainer
from ml.explainability.schemas import StaticExplanation, DirectionEnum


def test_static_shap_explainer_initialization():
    """Verify StaticSHAPExplainer loads trained static model and initializes TreeExplainer."""
    explainer = StaticSHAPExplainer()
    assert explainer.model_version == "static_baseline_v2.0"
    assert len(explainer.feature_names) == 17
    assert explainer.tree_explainer is not None


def test_static_shap_explanation_structure():
    """Verify SHAP attributions structural alignment, 17 features, and direction assignments."""
    explainer = StaticSHAPExplainer()
    sample_features = {
        "file_size": 102400.0,
        "number_of_sections": 3.0,
        "dll_count": 5.0,
        "api_count": 42.0,
        "max_section_entropy": 7.82,
        "min_section_entropy": 1.2,
        "mean_section_entropy": 4.5,
        "high_entropy_section_count": 1.0,
        "executable_section_count": 1.0,
        "writable_section_count": 1.0,
        "rwx_section_count": 1.0,
        "unusual_section_count": 0.0,
        "resource_count": 4.0,
        "suspicious_api_count": 3.0,
        "static_indicator_count": 2.0,
        "is_dll": 0.0,
        "is_driver": 0.0,
    }

    res: StaticExplanation = explainer.explain(sample_features, top_k=5)

    assert res.model_version == "static_baseline_v2.0"
    assert res.explainer_type == "SHAP_TreeExplainer"
    assert 0.0 <= res.model_output <= 1.0
    assert len(res.attributions) == 17
    assert len(res.top_k_attributions) == 5

    # Feature order sanity
    features_present = {a.feature for a in res.attributions}
    assert features_present == set(StaticFeatureVector.feature_names())

    # Verify top-k ordering by absolute magnitude
    for i in range(len(res.top_k_attributions) - 1):
        curr_mag = abs(res.top_k_attributions[i].contribution)
        next_mag = abs(res.top_k_attributions[i + 1].contribution)
        assert curr_mag >= next_mag


def test_static_shap_additive_property():
    """Verify base_value + sum(shap_values) ≈ model_output within numerical tolerance."""
    explainer = StaticSHAPExplainer()
    sample_features = {f: 1.0 for f in StaticFeatureVector.feature_names()}
    sample_features["max_section_entropy"] = 6.5

    res = explainer.explain(sample_features)
    expected_output = res.base_value + res.sum_of_attributions
    diff = abs(expected_output - res.model_output)

    # Tolerance check: diff <= 0.05
    assert diff <= 0.05, f"SHAP additive check failed: base({res.base_value}) + sum({res.sum_of_attributions}) = {expected_output} vs model_output({res.model_output})"


def test_non_finite_input_rejection():
    """Verify non-finite inputs (NaN, Inf) raise ValueError."""
    explainer = StaticSHAPExplainer()
    bad_features = {f: 0.0 for f in StaticFeatureVector.feature_names()}
    bad_features["file_size"] = float("nan")

    with pytest.raises(ValueError, match="contains invalid non-finite value"):
        explainer.explain(bad_features)
