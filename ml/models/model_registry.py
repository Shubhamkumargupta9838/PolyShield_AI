import os
import json
import joblib
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, DEFAULT_DATASET_VERSION

MODEL_VERSION = "static-baseline-v1"


class ModelRegistry:
    """
    Model serialization, metadata binding, and artifact persistence manager.
    """

    @staticmethod
    def save_model(
        output_dir: str,
        model_name: str,
        model_obj: Any,
        model_type: str,
        hyperparameters: Dict[str, Any],
        threshold: float,
        train_count: int,
        val_count: int,
        test_count: int,
        dataset_version: str = DEFAULT_DATASET_VERSION,
        feature_schema_version: str = FEATURE_SCHEMA_VERSION,
        model_version: str = MODEL_VERSION,
        evaluation_status: str = "VALID",
        dataset_type: str = "synthetic_fixture",
        dataset_provenance_status: str = "SYNTHETIC_FIXTURE",
        dataset_fingerprint: str = "",
        scientific_benchmark_available: bool = False,
        structurally_valid: bool = True,
        scientifically_benchmark_ready: bool = False,
        statistically_powerful: bool = False,
        train_class_dist: Dict[str, int] = None,
        val_class_dist: Dict[str, int] = None,
        test_class_dist: Dict[str, int] = None,
    ) -> Dict[str, str]:
        """
        Saves joblib weights and corresponding JSON metadata.
        """
        os.makedirs(output_dir, exist_ok=True)

        model_filename = f"{model_name}.joblib"
        meta_filename = f"{model_name}_metadata.json"

        model_path = os.path.join(output_dir, model_filename)
        meta_path = os.path.join(output_dir, meta_filename)

        # Save weights
        joblib.dump(model_obj, model_path)

        synthetic_warning = (
            "WARNING: This evaluation uses 20 synthetic/safe PE engineering fixtures. "
            "The results validate the ML pipeline and implementation only. "
            "They must NOT be interpreted as real-world malware detection performance."
        )

        # Prepare metadata
        metadata = {
            "model_name": model_name,
            "model_type": model_type,
            "model_version": model_version,
            "dataset_version": dataset_version,
            "feature_schema_version": feature_schema_version,
            "feature_names": FEATURE_NAMES,
            "feature_count": len(FEATURE_NAMES),
            "random_seed": hyperparameters.get("random_state", 42),
            "hyperparameters": hyperparameters,
            "classification_threshold": float(threshold),
            "training_sample_count": train_count,
            "validation_sample_count": val_count,
            "test_sample_count": test_count,
            "training_class_distribution": train_class_dist or {},
            "validation_class_distribution": val_class_dist or {},
            "test_class_distribution": test_class_dist or {},
            "dataset_type": dataset_type,
            "dataset_provenance_status": dataset_provenance_status,
            "dataset_fingerprint": dataset_fingerprint,
            "structurally_valid": structurally_valid,
            "scientifically_benchmark_ready": scientifically_benchmark_ready,
            "statistically_powerful": statistically_powerful,
            "scientific_benchmark_available": scientific_benchmark_available,
            "scientific_benchmark": scientifically_benchmark_ready,
            "statistical_benchmark": statistically_powerful,
            "evaluation_status": evaluation_status,
            "synthetic_dataset_warning": synthetic_warning,
            "training_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return {
            "model_path": model_path,
            "metadata_path": meta_path,
        }

    @staticmethod
    def load_model(output_dir: str, model_name: str) -> Tuple[Any, Dict[str, Any]]:
        """
        Loads joblib model weights and metadata JSON.
        """
        model_path = os.path.join(output_dir, f"{model_name}.joblib")
        meta_path = os.path.join(output_dir, f"{model_name}_metadata.json")

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found at '{model_path}'")
        if not os.path.exists(meta_path):
            raise FileNotFoundError(f"Metadata file not found at '{meta_path}'")

        model_obj = joblib.load(model_path)
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        # Invariant checks
        if metadata.get("feature_schema_version") != FEATURE_SCHEMA_VERSION:
            raise ValueError(
                f"Incompatible feature schema version: expected '{FEATURE_SCHEMA_VERSION}', "
                f"got '{metadata.get('feature_schema_version')}'"
            )
        if metadata.get("feature_names") != FEATURE_NAMES:
            raise ValueError("Model feature names do not match canonical FEATURE_NAMES ordering.")

        return model_obj, metadata
