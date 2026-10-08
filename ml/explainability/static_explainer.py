"""Static PE SHAP Explainer (Phase 12).

Computes local feature attributions using SHAP TreeExplainer on the trained static Random Forest model artifact.
Strictly aligns input features with the canonical 17-dimensional `static-v1` schema and verifies additive property.
"""

import json
import math
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd
import joblib
import shap

from analysis.static.schemas import StaticFeatureVector
from ml.explainability.schemas import (
    StaticExplanation,
    FeatureAttribution,
    DirectionEnum,
)

logger = logging.getLogger("polyshield.static_explainer")


class StaticSHAPExplainer:
    """SHAP TreeExplainer for tabular static PE features."""

    def __init__(
        self,
        artifact_path: str | Path = "ml/artifacts/models/static_baseline_v2.0.joblib",
        metadata_path: str | Path = "ml/artifacts/models/static_baseline_v2.0_metadata.json",
    ):
        self.artifact_path = Path(artifact_path)
        self.metadata_path = Path(metadata_path)

        if not self.artifact_path.exists():
            raise FileNotFoundError(f"Static model artifact not found at: {self.artifact_path}")

        self.model = joblib.load(self.artifact_path)
        self.feature_names = StaticFeatureVector.feature_names()

        if self.metadata_path.exists():
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                self.model_version = meta.get("model_name", meta.get("model_version", "static_baseline_v2.0"))
        else:
            self.model_version = "static_baseline_v2.0"

        # Initialize SHAP TreeExplainer on trained sklearn model
        raw_model = self.model.model if hasattr(self.model, "model") else self.model
        self.tree_explainer = shap.TreeExplainer(raw_model)

    def explain(self, feature_dict: Dict[str, float], top_k: int = 5) -> StaticExplanation:
        """Computes SHAP feature attributions for a single 17-dimensional static feature vector.

        Args:
            feature_dict: Feature name -> float value mapping.
            top_k: Number of top features to rank for summary.

        Returns:
            StaticExplanation containing base value, attributions, rankings, and sanity metrics.
        """
        # 1. Build matrix X aligned strictly with canonical 17-feature order
        x_vec = np.zeros((1, len(self.feature_names)), dtype=np.float64)
        for idx, feat_name in enumerate(self.feature_names):
            val = feature_dict.get(feat_name, 0.0)
            if math.isnan(val) or math.isinf(val):
                raise ValueError(f"Feature '{feat_name}' contains invalid non-finite value: {val}")
            x_vec[0, idx] = float(val)

        x_df = pd.DataFrame(x_vec, columns=self.feature_names)

        # 2. Model prediction P(malware)
        raw_pred = self.model.predict_proba(x_df)
        if isinstance(raw_pred, np.ndarray):
            if raw_pred.ndim == 2 and raw_pred.shape[1] == 2:
                malware_prob = float(raw_pred[0, 1])
            elif raw_pred.ndim == 1:
                malware_prob = float(raw_pred[0])
            else:
                malware_prob = float(raw_pred.ravel()[0])
        else:
            malware_prob = float(raw_pred)

        # 3. Compute SHAP values
        raw_shap = self.tree_explainer.shap_values(x_df)

        # Handle SHAP multi-class vs single array output structure
        if isinstance(raw_shap, list):
            shap_vec = raw_shap[1][0] if len(raw_shap) > 1 else raw_shap[0][0]
            base_val = float(self.tree_explainer.expected_value[1]) if len(self.tree_explainer.expected_value) > 1 else float(self.tree_explainer.expected_value[0])
        elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 3:
            shap_vec = raw_shap[0, :, 1]
            base_val = float(self.tree_explainer.expected_value[1])
        else:
            shap_vec = raw_shap[0]
            base_val = float(self.tree_explainer.expected_value) if np.isscalar(self.tree_explainer.expected_value) else float(self.tree_explainer.expected_value[0])

        sum_shap = float(np.sum(shap_vec))

        # 4. Construct feature attributions
        attributions: List[FeatureAttribution] = []
        raw_items: List[Tuple[str, float, float]] = []

        for idx, feat_name in enumerate(self.feature_names):
            val = float(x_vec[0, idx])
            contrib = float(shap_vec[idx])
            raw_items.append((feat_name, val, contrib))

        # Sort by absolute magnitude descending
        sorted_items = sorted(raw_items, key=lambda item: abs(item[2]), reverse=True)

        for rank, (feat_name, val, contrib) in enumerate(sorted_items, start=1):
            if contrib > 1e-4:
                direction = DirectionEnum.POSITIVE
            elif contrib < -1e-4:
                direction = DirectionEnum.NEGATIVE
            else:
                direction = DirectionEnum.NEUTRAL

            attributions.append(
                FeatureAttribution(
                    feature=feat_name,
                    value=round(val, 4),
                    contribution=round(contrib, 4),
                    direction=direction,
                    rank=rank,
                )
            )

        top_k_items = sorted(attributions, key=lambda item: item.rank)[:top_k]

        return StaticExplanation(
            model_version=self.model_version,
            explainer_type="SHAP_TreeExplainer",
            base_value=round(base_val, 4),
            model_output=round(malware_prob, 4),
            sum_of_attributions=round(sum_shap, 4),
            attributions=attributions,
            top_k_attributions=top_k_items,
        )
