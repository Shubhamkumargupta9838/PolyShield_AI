"""Unified Explanation Schemas for PolyShield AI (Phase 12).

Defines structured Pydantic schemas capturing static SHAP attributions, dynamic sequence
attributions, observed evidence, ensemble component decomposition, and explicit limitations.
Enforces strict separation between OBSERVED EVIDENCE, MODEL ATTRIBUTION, and DECISION FUSION.
"""

from enum import Enum
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator


class DirectionEnum(str, Enum):
    POSITIVE = "POSITIVE"  # Pushes prediction toward malware class
    NEGATIVE = "NEGATIVE"  # Pushes prediction toward benign class
    NEUTRAL = "NEUTRAL"   # Zero or negligible contribution


EXPLANATION_VERSION = "explanation_v1.0"


class FeatureAttribution(BaseModel):
    """Local attribution item for tabular static features (SHAP values)."""

    feature: str = Field(..., description="Canonical static-v1 feature name")
    value: float = Field(..., description="Observed numeric value of the feature")
    contribution: float = Field(..., description="SHAP attribution value (marginal contribution toward P(malware))")
    direction: DirectionEnum = Field(..., description="Attribution direction (POSITIVE/NEGATIVE/NEUTRAL)")
    rank: int = Field(..., ge=1, description="Rank ordered by absolute magnitude")


class EventAttribution(BaseModel):
    """Attribution item for dynamic sequence behavioral events."""

    event_index: int = Field(..., ge=0, description="0-indexed position in event sequence")
    relative_time_ms: int = Field(..., ge=0, description="Relative timestamp from execution start")
    event_type: str = Field(..., description="Standardized event name e.g. PROCESS_CREATE")
    event_category: str = Field(..., description="Event category e.g. process, network, filesystem")
    contribution: float = Field(..., description="Sequence attribution value toward LSTM P(malware)")
    direction: DirectionEnum = Field(..., description="Attribution direction (POSITIVE/NEGATIVE/NEUTRAL)")
    rank: int = Field(..., ge=1, description="Rank ordered by absolute magnitude")


class EvidenceItem(BaseModel):
    """Fact observed by static analyzer or sandbox telemetry. NOT a SHAP attribution."""

    metric_name: str = Field(..., description="Name of observed evidence metric")
    metric_value: Any = Field(..., description="Measured evidence value")
    category: str = Field(..., description="Evidence category e.g. static_structural or dynamic_telemetry")
    description: str = Field(..., description="Human-readable description of observed fact")


class EnsembleDecomposition(BaseModel):
    """Component contribution breakdown from multimodal fusion formula."""

    ensemble_mode: str = Field(..., description="Operational mode (BOTH_MODALITIES, STATIC_ONLY, DYNAMIC_ONLY)")
    static_weight: float = Field(..., ge=0.0, le=1.0, description="Static model fusion weight")
    static_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="Static model P(malware)")
    static_component_contribution: Optional[float] = Field(None, ge=0.0, le=1.0, description="w_static * P_static")

    dynamic_weight: float = Field(..., ge=0.0, le=1.0, description="Dynamic model fusion weight")
    dynamic_probability: Optional[float] = Field(None, ge=0.0, le=1.0, description="Dynamic model P(malware)")
    dynamic_component_contribution: Optional[float] = Field(None, ge=0.0, le=1.0, description="w_dynamic * P_dynamic")

    ensemble_probability: float = Field(..., ge=0.0, le=1.0, description="Final ensemble P(malware)")
    explanation_summary: str = Field(..., description="Human-readable description of fusion result")


class StaticExplanation(BaseModel):
    """Explanation container for static tabular PE model (SHAP)."""

    model_version: str = Field("static_baseline_v2.0", description="Static model version")
    explainer_type: str = Field("SHAP_TreeExplainer", description="Explainer engine used")
    base_value: float = Field(..., description="SHAP explainer baseline value (expected value)")
    model_output: float = Field(..., description="Static model predicted P(malware)")
    sum_of_attributions: float = Field(..., description="Sum of all 17 SHAP feature attributions")
    attributions: List[FeatureAttribution] = Field(default_factory=list, description="Complete 17-feature attributions")
    top_k_attributions: List[FeatureAttribution] = Field(default_factory=list, description="Top-5 features by magnitude")


class DynamicExplanation(BaseModel):
    """Explanation container for dynamic sequence LSTM model."""

    model_version: str = Field("dynamic_lstm_v1.0", description="Dynamic LSTM model version")
    explainer_type: str = Field("IntegratedGradients_Occlusion", description="Sequence explainer engine")
    sequence_length: int = Field(..., ge=0, description="Sequence length (excluding PAD)")
    unknown_event_rate: float = Field(..., ge=0.0, le=1.0, description="Rate of UNK tokens in trace")
    model_output: float = Field(..., description="Dynamic LSTM predicted P(malware)")
    attributions: List[EventAttribution] = Field(default_factory=list, description="Sequence event attributions")
    top_k_attributions: List[EventAttribution] = Field(default_factory=list, description="Top-5 events by magnitude")
    temporal_timeline: List[EventAttribution] = Field(default_factory=list, description="Events ordered by timestamp")


class ExplanationLimitations(BaseModel):
    """Mandatory limitation disclosures and scientific disclaimers."""

    causal_claim_policy: str = Field(
        "Model attributions quantify marginal impact on model outputs and do NOT constitute causal proof of malware intent.",
        description="Causal policy disclaimer"
    )
    observed_vs_attribution_distinction: str = Field(
        "Observed evidence represents measured PE features/telemetry. Attributions quantify model weights, not raw facts.",
        description="Evidence vs attribution distinction disclaimer"
    )
    synthetic_dataset_disclosure: str = Field(
        "Attributions are computed from baseline models trained on synthetic engineering fixtures and reflect software validation only.",
        description="Synthetic provenance disclosure"
    )


class ExplanationResult(BaseModel):
    """Top-level container for unified PolyShield AI explanation report."""

    scan_id: str = Field(..., description="Scan UUID")
    sample_sha256: str = Field(..., description="SHA-256 cryptographic identity")
    explanation_version: str = Field(EXPLANATION_VERSION, description="Explanation schema version")

    # Modality Explanations
    static_explanation: Optional[StaticExplanation] = Field(None, description="Static SHAP explanation")
    dynamic_explanation: Optional[DynamicExplanation] = Field(None, description="Dynamic sequence explanation")
    ensemble_decomposition: EnsembleDecomposition = Field(..., description="Ensemble component fusion breakdown")

    # Facts & Decision Context
    observed_evidence: List[EvidenceItem] = Field(default_factory=list, description="Measured PE facts")
    risk_level: str = Field(..., description="Deterministic risk level (LOW/MEDIUM/HIGH/CRITICAL)")
    decision_threshold: float = Field(0.5, description="Classification decision threshold")
    decision_summary: str = Field(..., description="High-level decision synthesis")

    limitations: ExplanationLimitations = Field(default_factory=ExplanationLimitations, description="Disclaimers")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("scan_id", "sample_sha256")
    @classmethod
    def validate_non_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("String identifier cannot be empty.")
        return v
