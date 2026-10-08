import os
import json
import joblib
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Optional
from pathlib import Path

from backend.app.core.exceptions import (
    ModelServiceUnavailableException,
    ModelContractValidationException,
    ModelIntegrityException,
    PathTraversalException
)
from backend.app.core.security_config import security_settings
from backend.app.core.security import validate_safe_path
from backend.app.core.logging import logger
from analysis.static.schemas import StaticFeatureVector


class ModelService:
    """
    Model Loading & Inference Abstraction Service for PolyShield Static ML Baseline.
    Loads trained joblib model artifact and metadata, verifies SHA-256 checksums,
    restricts model artifact paths to an internal allowlist, and runs predictions on 17-dim vectors.
    """
    _instance: Optional["ModelService"] = None

    def __init__(
        self,
        model_path: Optional[str] = None,
        metadata_path: Optional[str] = None
    ):
        base_dir = Path(__file__).resolve().parents[3]  # Root directory of workspace
        allowed_models_dir = base_dir / "ml" / "artifacts" / "models"

        # Safe-root path resolution: model paths MUST reside in allowed_models_dir
        if model_path:
            candidate = Path(model_path).resolve()
            try:
                candidate.relative_to(allowed_models_dir.resolve())
                self.model_path = candidate
            except ValueError:
                raise PathTraversalException(str(model_path))
        else:
            self.model_path = allowed_models_dir / "static_baseline_v2.0.joblib"

        if metadata_path:
            if ".." in str(metadata_path):
                self.metadata_path = validate_safe_path(Path(metadata_path), allowed_models_dir)
            else:
                self.metadata_path = Path(metadata_path).resolve()
        else:
            self.metadata_path = allowed_models_dir / "static_baseline_v2.0_metadata.json"

        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.is_initialized = False

    def verify_model_integrity(self) -> str:
        """
        Computes SHA-256 checksum of the model file and validates against expected hash if configured.
        """
        if not self.model_path.exists():
            raise ModelServiceUnavailableException(f"Artifact missing: {self.model_path}")

        hasher = hashlib.sha256()
        with open(self.model_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        computed_sha256 = hasher.hexdigest()

        expected = security_settings.STATIC_MODEL_EXPECTED_SHA256
        if expected and expected.lower() != computed_sha256.lower():
            logger.critical(f"MODEL_INTEGRITY_FAILURE: Expected SHA-256 '{expected}', computed '{computed_sha256}'")
            raise ModelIntegrityException(f"Static model SHA-256 mismatch for {self.model_path.name}")

        return computed_sha256

    def load_model(self) -> None:
        """Loads model weights and metadata from disk after verifying integrity and contract."""
        if not self.model_path.exists():
            logger.error(f"Model artifact not found at: {self.model_path}")
            raise ModelServiceUnavailableException(f"Artifact missing: {self.model_path}")

        if not self.metadata_path.exists():
            logger.error(f"Model metadata not found at: {self.metadata_path}")
            raise ModelServiceUnavailableException(f"Metadata missing: {self.metadata_path}")

        # 1. Verify model artifact SHA-256 checksum integrity
        sha256_hash = self.verify_model_integrity()

        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)
        except Exception as e:
            raise ModelContractValidationException(f"Failed to parse metadata JSON: {str(e)}")

        self.validate_contract()

        # 2. Safe joblib loading boundary
        try:
            self.model = joblib.load(self.model_path)
        except Exception as e:
            raise ModelServiceUnavailableException(f"Failed to load joblib model: {str(e)}")

        self.is_initialized = True
        logger.info(
            f"Loaded static ML model '{self.metadata.get('model_name')}' "
            f"(schema={self.metadata.get('feature_schema_version')}, sha256={sha256_hash[:12]}) successfully."
        )

    def validate_contract(self) -> None:
        """Validates model metadata against canonical PolyShield static-v1 schema expectations."""
        expected_features = StaticFeatureVector.feature_names()
        
        dataset_version = self.metadata.get("dataset_version")
        schema_version = self.metadata.get("feature_schema_version")
        feature_count = self.metadata.get("feature_count")
        feature_names = self.metadata.get("feature_names", [])
        threshold = self.metadata.get("classification_threshold", 0.5)

        if dataset_version != "v2.0":
            raise ModelContractValidationException(f"Expected dataset_version 'v2.0', got '{dataset_version}'")

        if schema_version != "static-v1":
            raise ModelContractValidationException(f"Expected feature_schema_version 'static-v1', got '{schema_version}'")

        if feature_count != 17 or len(feature_names) != 17:
            raise ModelContractValidationException(f"Expected 17 features, got feature_count={feature_count}, len(feature_names)={len(feature_names)}")

        if feature_names != expected_features:
            raise ModelContractValidationException(
                f"Feature ordering mismatch!\nExpected: {expected_features}\nGot: {feature_names}"
            )

        if abs(threshold - 0.5) > 1e-5:
            raise ModelContractValidationException(f"Expected default classification threshold 0.5, got {threshold}")

    def predict(self, feature_vector: StaticFeatureVector) -> Dict[str, Any]:
        """
        Executes static ML model prediction on a canonical 17-feature vector.
        Validates numeric input sanity (rejects NaN/Inf).
        """
        if not self.is_initialized or self.model is None:
            self.load_model()

        vector_dict = feature_vector.to_dict()
        expected_names = StaticFeatureVector.feature_names()
        
        # Check non-finite numbers
        for name in expected_names:
            val = vector_dict.get(name, 0.0)
            if not np.isfinite(val):
                raise ValueError(f"Feature '{name}' has non-finite value '{val}'.")

        row_dict = {name: float(vector_dict[name]) for name in expected_names}
        X = pd.DataFrame([row_dict], columns=expected_names)

        if hasattr(self.model, "predict_proba"):
            raw_proba = self.model.predict_proba(X)
            
            if isinstance(raw_proba, np.ndarray):
                if raw_proba.ndim == 2 and raw_proba.shape[1] == 2:
                    benign_score = float(raw_proba[0, 0])
                    malware_score = float(raw_proba[0, 1])
                else:
                    malware_score = float(raw_proba.flat[0])
                    benign_score = float(1.0 - malware_score)
            else:
                malware_score = float(raw_proba)
                benign_score = float(1.0 - malware_score)
        else:
            raw_pred = int(self.model.predict(X)[0])
            malware_score = 1.0 if raw_pred == 1 else 0.0
            benign_score = 1.0 - malware_score

        threshold = float(self.metadata.get("classification_threshold", 0.5))
        prediction = 1 if malware_score >= threshold else 0
        prediction_label = "MALWARE" if prediction == 1 else "BENIGN"

        return {
            "model_name": self.metadata.get("model_name", "static_baseline_v2.0"),
            "model_type": self.metadata.get("model_type", "random_forest"),
            "model_version": self.metadata.get("model_version", "static-baseline-v1"),
            "prediction": prediction,
            "prediction_label": prediction_label,
            "malware_score": round(malware_score, 4),
            "benign_score": round(benign_score, 4),
            "threshold": threshold,
            "feature_schema_version": self.metadata.get("feature_schema_version", "static-v1"),
            "dataset_version": self.metadata.get("dataset_version", "v2.0"),
            "dataset_provenance_status": self.metadata.get("dataset_provenance_status", "SYNTHETIC_FIXTURE"),
            "evaluation_status": self.metadata.get("evaluation_status", "ENGINEERING_SMOKE_EVALUATION"),
            "scientific_benchmark": bool(self.metadata.get("scientific_benchmark", False)),
            "synthetic_dataset_warning": self.metadata.get(
                "synthetic_dataset_warning",
                "Engineering Evaluation Model: Trained using synthetic/safe PE fixtures. Not real-world validated."
            )
        }


def get_model_service() -> ModelService:
    """Singleton instance accessor for ModelService."""
    if ModelService._instance is None:
        ModelService._instance = ModelService()
        ModelService._instance.load_model()
    return ModelService._instance
