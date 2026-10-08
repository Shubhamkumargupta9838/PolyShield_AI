"""Ensemble Explainer & Component Decomposition Engine (Phase 12).

Decomposes multimodal static + dynamic ensemble predictions into exact component contributions
(w_static * P_static and w_dynamic * P_dynamic). Explains operational modes and missing modalities cleanly.
"""

import logging
from typing import Optional, Dict, Any

from ml.models.prediction_schema import PredictionResult, EnsembleMode
from ml.explainability.schemas import EnsembleDecomposition

logger = logging.getLogger("polyshield.ensemble_explainer")


class EnsembleExplainer:
    """Decomposes equal-weight multimodal fusion predictions into component contributions."""

    def __init__(self, static_weight: float = 0.5, dynamic_weight: float = 0.5):
        self.static_weight = static_weight
        self.dynamic_weight = dynamic_weight

    def explain_ensemble(
        self,
        prediction: PredictionResult,
    ) -> EnsembleDecomposition:
        """Decomposes a PredictionResult into component contribution metrics and human-readable explanation.

        Args:
            prediction: PredictionResult instance from multimodal ensemble model.

        Returns:
            EnsembleDecomposition schema containing weights, component probabilities, contributions, and summary text.
        """
        mode = prediction.ensemble_mode
        p_static = prediction.static_probability
        p_dynamic = prediction.dynamic_probability
        p_ensemble = prediction.ensemble_probability

        if mode == EnsembleMode.BOTH_MODALITIES:
            static_contrib = round(self.static_weight * p_static, 4) if p_static is not None else None
            dynamic_contrib = round(self.dynamic_weight * p_dynamic, 4) if p_dynamic is not None else None
            summary = (
                f"Multimodal Ensemble decision (P={p_ensemble:.4f}): "
                f"Static PE model contributed {static_contrib:.4f} (weight={self.static_weight:.2f}, P={p_static:.4f}) and "
                f"Dynamic Sandbox LSTM model contributed {dynamic_contrib:.4f} (weight={self.dynamic_weight:.2f}, P={p_dynamic:.4f})."
            )

        elif mode == EnsembleMode.STATIC_ONLY:
            static_contrib = round(p_static, 4) if p_static is not None else None
            dynamic_contrib = None
            summary = (
                f"Static-Only decision (P={p_ensemble:.4f}): "
                f"Static PE model supplied the decision (P={p_static:.4f}). "
                f"Dynamic sandbox execution telemetry was unavailable or not run."
            )

        elif mode == EnsembleMode.DYNAMIC_ONLY:
            static_contrib = None
            dynamic_contrib = round(p_dynamic, 4) if p_dynamic is not None else None
            summary = (
                f"Dynamic-Only decision (P={p_ensemble:.4f}): "
                f"Dynamic Sandbox LSTM model supplied the decision (P={p_dynamic:.4f}). "
                f"Static PE structural analysis was unavailable."
            )

        else:
            static_contrib = None
            dynamic_contrib = None
            summary = "No valid analysis modality available for ensemble decision."

        return EnsembleDecomposition(
            ensemble_mode=mode.value if hasattr(mode, "value") else str(mode),
            static_weight=self.static_weight if mode == EnsembleMode.BOTH_MODALITIES else (1.0 if mode == EnsembleMode.STATIC_ONLY else 0.0),
            static_probability=round(p_static, 4) if p_static is not None else None,
            static_component_contribution=static_contrib,
            dynamic_weight=self.dynamic_weight if mode == EnsembleMode.BOTH_MODALITIES else (1.0 if mode == EnsembleMode.DYNAMIC_ONLY else 0.0),
            dynamic_probability=round(p_dynamic, 4) if p_dynamic is not None else None,
            dynamic_component_contribution=dynamic_contrib,
            ensemble_probability=round(p_ensemble, 4),
            explanation_summary=summary,
        )
