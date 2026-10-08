"""Unified Prediction Schema for Multimodal Malware Classification (Phase 11).

Defines structured schema capturing component model probabilities, modality availability,
dynamic quality status, ensemble decisions, and evaluation disclosures.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator


class EnsembleMode(str, Enum):
    BOTH_MODALITIES = "BOTH_MODALITIES"
    STATIC_ONLY = "STATIC_ONLY"
    DYNAMIC_ONLY = "DYNAMIC_ONLY"
    NONE = "NONE"


class DynamicQualityStatus(str, Enum):
    VALID = "VALID"
    LOW_SIGNAL = "LOW_SIGNAL"
    INVALID = "INVALID"
    UNAVAILABLE = "UNAVAILABLE"


ENSEMBLE_VERSION = "ensemble_v1.0"


class PredictionResult(BaseModel):
    """Container for multimodal static + dynamic ensemble malware classification results."""

    scan_id: str = Field(..., description="Scan UUID")
    sample_sha256: str = Field(..., description="SHA-256 cryptographic identity")

    # Probabilities
    static_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="P(malware) from static model")
    dynamic_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="P(malware) from dynamic LSTM model")
    ensemble_probability: float = Field(..., ge=0.0, le=1.0, description="Final ensemble P(malware)")

    # Classifications
    static_classification: Optional[str] = Field(None, description="Static model classification (malware/benign)")
    dynamic_classification: Optional[str] = Field(None, description="Dynamic model classification (malware/benign)")
    ensemble_classification: str = Field(..., description="Final ensemble classification (malware/benign)")

    # Model Versions
    static_model_version: Optional[str] = Field("static_baseline_v2.0", description="Static model version")
    dynamic_model_version: Optional[str] = Field("dynamic_lstm_v1.0", description="Dynamic model version")
    ensemble_version: str = Field(ENSEMBLE_VERSION, description="Ensemble algorithm version")

    # Modality & Quality Context
    available_modalities: List[str] = Field(default_factory=list, description="List of available modalities e.g. ['static', 'dynamic']")
    ensemble_mode: EnsembleMode = Field(EnsembleMode.BOTH_MODALITIES, description="Ensemble operational mode")
    dynamic_quality_status: DynamicQualityStatus = Field(DynamicQualityStatus.VALID, description="Dynamic telemetry quality status")

    # Threshold & Risk Mapping
    threshold: float = Field(0.5, ge=0.0, le=1.0, description="Decision threshold")
    threshold_source: str = Field("ENGINEERING_DEFAULT", description="Source of threshold selection")
    risk_level: str = Field("LOW", description="Deterministic risk level (LOW, MEDIUM, HIGH, CRITICAL)")

    # Provenance & Disclosure
    evaluation_status: str = Field("ENGINEERING_SMOKE_EVALUATION", description="Evaluation status")
    dataset_provenance_status: str = Field("SYNTHETIC_FIXTURE", description="Dataset provenance declaration")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("static_probability", "dynamic_probability", "ensemble_probability")
    @classmethod
    def validate_probability_bounds(cls, v: Optional[float]) -> Optional[float]:
        """Validate that non-None probabilities fall strictly within [0.0, 1.0]."""
        if v is None:
            return v
        import math
        if math.isnan(v) or math.isinf(v):
            raise ValueError("Probability value cannot be NaN or Infinity.")
        if v < 0.0 or v > 1.0:
            raise ValueError(f"Probability {v} is outside valid range [0.0, 1.0].")
        return round(v, 4)
