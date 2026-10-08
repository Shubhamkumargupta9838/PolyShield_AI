"""Multimodal Ensemble Classifier (Phase 11).

Fuses static structural probability (Random Forest / XGBoost) and dynamic behavioral
sequence probability (PyTorch LSTM) with missing-modality handling, telemetry quality gating,
and deterministic risk level mapping.
"""

from typing import Optional, Dict, Any, Tuple
import math

from ml.models.prediction_schema import (
    PredictionResult,
    EnsembleMode,
    DynamicQualityStatus,
    ENSEMBLE_VERSION,
)


class MultimodalEnsembleModel:
    """Multimodal ensemble model combining static structural and dynamic sequence classifiers."""

    def __init__(
        self,
        static_weight: float = 0.5,
        dynamic_weight: float = 0.5,
        default_threshold: float = 0.5,
        version: str = ENSEMBLE_VERSION,
    ):
        if not math.isclose(static_weight + dynamic_weight, 1.0, abs_tol=1e-5):
            raise ValueError(f"Ensemble weights must sum to 1.0. Got static_weight={static_weight}, dynamic_weight={dynamic_weight}")
        self.static_weight = static_weight
        self.dynamic_weight = dynamic_weight
        self.default_threshold = default_threshold
        self.version = version

    @staticmethod
    def get_risk_level(probability: float) -> str:
        """Deterministic risk category mapping from ensemble probability."""
        if probability < 0.25:
            return "LOW"
        elif probability < 0.50:
            return "MEDIUM"
        elif probability < 0.75:
            return "HIGH"
        else:
            return "CRITICAL"

    @staticmethod
    def assess_dynamic_quality(
        raw_events_count: int,
        unknown_event_rate: float,
        is_telemetry_valid: bool = True,
    ) -> DynamicQualityStatus:
        """Assess quality status of dynamic telemetry based on sequence stats."""
        if not is_telemetry_valid:
            return DynamicQualityStatus.INVALID
        if raw_events_count == 0:
            return DynamicQualityStatus.UNAVAILABLE
        if unknown_event_rate > 0.60 or raw_events_count < 2:
            return DynamicQualityStatus.LOW_SIGNAL
        return DynamicQualityStatus.VALID

    def predict_ensemble(
        self,
        scan_id: str,
        sample_sha256: str,
        static_probability: Optional[float] = None,
        dynamic_probability: Optional[float] = None,
        dynamic_sequence_length: int = 0,
        dynamic_unknown_event_rate: float = 0.0,
        is_telemetry_valid: bool = True,
        custom_threshold: Optional[float] = None,
        threshold_source: str = "ENGINEERING_DEFAULT",
        static_version: str = "static_baseline_v2.0",
        dynamic_version: str = "dynamic_lstm_v1.0",
    ) -> PredictionResult:
        """Execute multimodal ensemble prediction handling missing modalities and quality gating."""
        threshold = custom_threshold if custom_threshold is not None else self.default_threshold

        # Validate inputs
        if static_probability is not None and (math.isnan(static_probability) or math.isinf(static_probability)):
            raise ValueError("static_probability cannot be NaN or Infinity.")
        if dynamic_probability is not None and (math.isnan(dynamic_probability) or math.isinf(dynamic_probability)):
            raise ValueError("dynamic_probability cannot be NaN or Infinity.")

        has_static = static_probability is not None
        has_dynamic = dynamic_probability is not None

        # Determine dynamic quality status
        if has_dynamic:
            quality_status = self.assess_dynamic_quality(
                raw_events_count=dynamic_sequence_length,
                unknown_event_rate=dynamic_unknown_event_rate,
                is_telemetry_valid=is_telemetry_valid,
            )
        else:
            quality_status = DynamicQualityStatus.UNAVAILABLE

        # Determine available modalities and ensemble mode
        available_modalities = []
        if has_static:
            available_modalities.append("static")
        if has_dynamic:
            available_modalities.append("dynamic")

        if has_static and has_dynamic:
            mode = EnsembleMode.BOTH_MODALITIES
            ensemble_prob = (
                self.static_weight * static_probability + self.dynamic_weight * dynamic_probability
            )
        elif has_static and not has_dynamic:
            mode = EnsembleMode.STATIC_ONLY
            ensemble_prob = static_probability
        elif not has_static and has_dynamic:
            mode = EnsembleMode.DYNAMIC_ONLY
            ensemble_prob = dynamic_probability
        else:
            mode = EnsembleMode.NONE
            raise ValueError(f"Cannot compute ensemble prediction for scan_id='{scan_id}': neither static nor dynamic probability provided.")

        ensemble_prob = max(0.0, min(1.0, float(ensemble_prob)))

        # Classifications
        static_class = ("malware" if static_probability >= threshold else "benign") if has_static else None
        dynamic_class = ("malware" if dynamic_probability >= threshold else "benign") if has_dynamic else None
        ensemble_class = "malware" if ensemble_prob >= threshold else "benign"

        risk = self.get_risk_level(ensemble_prob)

        return PredictionResult(
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            static_probability=static_probability,
            dynamic_probability=dynamic_probability,
            ensemble_probability=ensemble_prob,
            static_classification=static_class,
            dynamic_classification=dynamic_class,
            ensemble_classification=ensemble_class,
            static_model_version=static_version if has_static else None,
            dynamic_model_version=dynamic_version if has_dynamic else None,
            ensemble_version=self.version,
            available_modalities=available_modalities,
            ensemble_mode=mode,
            dynamic_quality_status=quality_status,
            threshold=threshold,
            threshold_source=threshold_source,
            risk_level=risk,
            evaluation_status="ENGINEERING_SMOKE_EVALUATION",
            dataset_provenance_status="SYNTHETIC_FIXTURE",
        )
