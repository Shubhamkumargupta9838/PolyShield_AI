"""Comparative Ensemble & Ablation Evaluation Pipeline (Phase 11).

Evaluates Static-only, Dynamic-only, and Multimodal Ensemble models on identical sample sets
and exports machine-readable comparison artifacts.
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np

from ml.models.ensemble import MultimodalEnsembleModel
from ml.evaluation.dynamic_metrics import compute_dynamic_metrics


class EnsembleEvaluator:
    """Evaluates comparative performance of component models vs multimodal ensemble."""

    def __init__(self, static_weight: float = 0.5, dynamic_weight: float = 0.5):
        self.ensemble_model = MultimodalEnsembleModel(
            static_weight=static_weight,
            dynamic_weight=dynamic_weight,
        )

    def evaluate_ablation(
        self,
        y_true: np.ndarray,
        static_probs: np.ndarray,
        dynamic_probs: np.ndarray,
        threshold: float = 0.5,
        artifacts_dir: Path | str = "ml/artifacts",
    ) -> Dict[str, Any]:
        """Runs ablation evaluation across Static-only, Dynamic-only, and Multimodal Ensemble."""
        artifacts_path = Path(artifacts_dir)
        artifacts_path.mkdir(parents=True, exist_ok=True)

        # 1. Static-only evaluation
        static_metrics = compute_dynamic_metrics(y_true, static_probs, threshold=threshold)

        # 2. Dynamic-only evaluation
        dynamic_metrics = compute_dynamic_metrics(y_true, dynamic_probs, threshold=threshold)

        # 3. Ensemble evaluation
        ensemble_probs = np.array([
            (self.ensemble_model.static_weight * s + self.ensemble_model.dynamic_weight * d)
            for s, d in zip(static_probs, dynamic_probs)
        ])
        ensemble_metrics = compute_dynamic_metrics(y_true, ensemble_probs, threshold=threshold)

        report = {
            "dataset_version": "dynamic-v1.0",
            "dataset_provenance_status": "SYNTHETIC_FIXTURE",
            "scientific_benchmark_ready": False,
            "evaluation_status": "ENGINEERING_SMOKE_EVALUATION",
            "ablation_status": "ENGINEERING_ONLY",
            "threshold": threshold,
            "weights": {
                "static_weight": self.ensemble_model.static_weight,
                "dynamic_weight": self.ensemble_model.dynamic_weight,
            },
            "sample_count": len(y_true),
            "models": {
                "static_only": static_metrics,
                "dynamic_only": dynamic_metrics,
                "ensemble": ensemble_metrics,
            },
            "scientific_claim_policy": (
                "The multimodal ensemble has been implemented and engineering-validated. "
                "Comparative scientific performance remains unestablished because the current "
                "dataset consists of synthetic engineering fixtures and is not benchmark-ready."
            ),
        }

        output_file = artifacts_path / "ensemble_evaluation_v1.0.json"
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return report
