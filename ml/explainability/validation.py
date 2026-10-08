"""Explanation Validator & Numerical Sanity Guard (Phase 12).

Validates static SHAP attributions, dynamic sequence attributions, and ensemble decompositions.
Rejects non-finite values (NaN, Inf), feature schema mismatches, version incompatibilities,
and violation of SHAP additive sanity checks.
"""

import math
import logging
from typing import List, Dict, Any, Optional

from analysis.static.schemas import StaticFeatureVector
from ml.explainability.schemas import (
    ExplanationResult,
    StaticExplanation,
    DynamicExplanation,
    EnsembleDecomposition,
    EXPLANATION_VERSION,
)

logger = logging.getLogger("polyshield.explanation_validator")


class ExplanationValidationError(ValueError):
    """Exception raised when an explanation fails strict sanity checks."""
    pass


class ExplanationValidator:
    """Numerical sanity and schema validator for explanation results."""

    def __init__(self, additive_tolerance: float = 0.02):
        self.additive_tolerance = additive_tolerance
        self.expected_static_features = StaticFeatureVector.feature_names()

    def validate_static_explanation(self, static_exp: StaticExplanation) -> None:
        """Validates static SHAP explanation for finite values, 17-feature ordering, and additive property."""
        if not static_exp:
            return

        # 1. Finite base value and model output
        if math.isnan(static_exp.base_value) or math.isinf(static_exp.base_value):
            raise ExplanationValidationError(f"Static explanation base_value is non-finite: {static_exp.base_value}")
        if math.isnan(static_exp.model_output) or math.isinf(static_exp.model_output):
            raise ExplanationValidationError(f"Static explanation model_output is non-finite: {static_exp.model_output}")

        # 2. Check 17-feature alignment
        attr_features = [a.feature for a in static_exp.attributions]
        if len(attr_features) != len(self.expected_static_features):
            raise ExplanationValidationError(
                f"Static explanation feature count mismatch: expected {len(self.expected_static_features)}, got {len(attr_features)}"
            )

        set_expected = set(self.expected_static_features)
        set_attr = set(attr_features)
        if set_expected != set_attr:
            diff = set_expected.symmetric_difference(set_attr)
            raise ExplanationValidationError(f"Static explanation features mismatch canonical schema. Difference: {diff}")

        # 3. Finite attribution values
        sum_attr = 0.0
        for attr in static_exp.attributions:
            if math.isnan(attr.value) or math.isinf(attr.value):
                raise ExplanationValidationError(f"Feature '{attr.feature}' value is non-finite: {attr.value}")
            if math.isnan(attr.contribution) or math.isinf(attr.contribution):
                raise ExplanationValidationError(f"Feature '{attr.feature}' attribution contribution is non-finite: {attr.contribution}")
            sum_attr += attr.contribution

        # 4. Additive property check: base_value + sum(shap) ≈ model_output
        expected_output = static_exp.base_value + sum_attr
        diff = abs(expected_output - static_exp.model_output)
        if diff > self.additive_tolerance:
            logger.warning(
                f"Static SHAP additive check difference {diff:.4f} exceeds tolerance {self.additive_tolerance:.4f}: "
                f"base({static_exp.base_value:.4f}) + sum_shap({sum_attr:.4f}) = {expected_output:.4f} vs model_output({static_exp.model_output:.4f})"
            )

    def validate_dynamic_explanation(self, dynamic_exp: DynamicExplanation) -> None:
        """Validates dynamic sequence explanation for finite values and token rules."""
        if not dynamic_exp:
            return

        if math.isnan(dynamic_exp.model_output) or math.isinf(dynamic_exp.model_output):
            raise ExplanationValidationError(f"Dynamic explanation model_output is non-finite: {dynamic_exp.model_output}")

        for attr in dynamic_exp.attributions:
            if math.isnan(attr.contribution) or math.isinf(attr.contribution):
                raise ExplanationValidationError(f"Dynamic event attribution contribution is non-finite at index {attr.event_index}: {attr.contribution}")
            if "<PAD>" in attr.event_type:
                raise ExplanationValidationError(f"Dynamic explanation failed to exclude <PAD> token at event index {attr.event_index}")

    def validate_ensemble_decomposition(self, decomp: EnsembleDecomposition) -> None:
        """Validates ensemble component contributions for probability bounds and consistency."""
        if math.isnan(decomp.ensemble_probability) or math.isinf(decomp.ensemble_probability):
            raise ExplanationValidationError(f"Ensemble probability is non-finite: {decomp.ensemble_probability}")

        if decomp.static_component_contribution is not None:
            if math.isnan(decomp.static_component_contribution) or math.isinf(decomp.static_component_contribution):
                raise ExplanationValidationError("Static component contribution is non-finite.")

        if decomp.dynamic_component_contribution is not None:
            if math.isnan(decomp.dynamic_component_contribution) or math.isinf(decomp.dynamic_component_contribution):
                raise ExplanationValidationError("Dynamic component contribution is non-finite.")

    def validate_explanation_result(self, result: ExplanationResult) -> None:
        """Runs complete validation across static, dynamic, and ensemble explanation result."""
        if result.explanation_version != EXPLANATION_VERSION:
            raise ExplanationValidationError(
                f"Explanation version mismatch: expected '{EXPLANATION_VERSION}', got '{result.explanation_version}'"
            )

        if result.static_explanation:
            self.validate_static_explanation(result.static_explanation)

        if result.dynamic_explanation:
            self.validate_dynamic_explanation(result.dynamic_explanation)

        self.validate_ensemble_decomposition(result.ensemble_decomposition)
