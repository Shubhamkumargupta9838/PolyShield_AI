"""Dynamic Model Service for LSTM Inference (Phase 10).

Manages model initialization, artifact schema validation, and sequence inference execution.
"""

import logging
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import numpy as np

from ml.data.dynamic_vocab import EventVocabulary
from ml.data.dynamic_dataset_builder import DynamicDatasetBuilder
from ml.models.lstm import DynamicLSTMModel, MODEL_VERSION

logger = logging.getLogger("polyshield.dynamic_model_service")


class DynamicModelService:
    """Service for dynamic LSTM sequence model loading and prediction."""

    _instance: Optional["DynamicModelService"] = None

    def __init__(self, artifacts_dir: Path | str = "ml/artifacts"):
        self.artifacts_dir = Path(artifacts_dir)
        self.models_dir = self.artifacts_dir / "models"
        self.weights_file = self.models_dir / f"{MODEL_VERSION}.pt"
        self.meta_file = self.models_dir / f"{MODEL_VERSION}.json"
        self.vocab_file = self.artifacts_dir / "dynamic_vocab_v1.json"

        self.model: Optional[DynamicLSTMModel] = None
        self.vocab: Optional[EventVocabulary] = None
        self.builder: Optional[DynamicDatasetBuilder] = None

        self.threshold: float = 0.5
        self.evaluation_status: str = "ENGINEERING_SMOKE_EVALUATION"
        self.is_loaded: bool = False

        # Attempt to load model artifact if available
        self._load_artifacts()

    @classmethod
    def get_instance(cls, artifacts_dir: Path | str = "ml/artifacts") -> "DynamicModelService":
        """Singleton accessor for DynamicModelService."""
        if cls._instance is None:
            cls._instance = cls(artifacts_dir=artifacts_dir)
        return cls._instance

    def _load_artifacts(self) -> bool:
        """Load vocabulary, dataset builder, and PyTorch model artifact if present."""
        try:
            # 1. Load vocabulary if exists, otherwise fallback to default
            if self.vocab_file.exists():
                self.vocab = EventVocabulary.load_json(self.vocab_file)
            else:
                self.vocab = EventVocabulary()

            # 2. Check model files
            if not self.weights_file.exists() or not self.meta_file.exists():
                # Train a minimal default model if artifact doesn't exist yet
                logger.info("Dynamic LSTM artifact not found. Initializing untrained baseline model.")
                self.model = DynamicLSTMModel(vocab_size=len(self.vocab))
                self.builder = DynamicDatasetBuilder(max_sequence_length=256, vocab=self.vocab)
                self.threshold = 0.5
                self.evaluation_status = "ENGINEERING_SMOKE_EVALUATION"
                self.is_loaded = True
                return True

            # 3. Load model artifact
            self.model = DynamicLSTMModel.load_artifact(self.weights_file, self.meta_file)

            # Load metadata threshold and max_sequence_length
            import json
            with open(self.meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            max_seq_len = meta.get("max_sequence_length", 256)
            self.threshold = meta.get("threshold", 0.5)
            self.evaluation_status = meta.get("evaluation_status", "ENGINEERING_SMOKE_EVALUATION")

            self.builder = DynamicDatasetBuilder(max_sequence_length=max_seq_len, vocab=self.vocab)
            self.is_loaded = True
            logger.info(f"Loaded Dynamic LSTM artifact version={MODEL_VERSION}, threshold={self.threshold}")
            return True

        except Exception as e:
            logger.error(f"Failed to load Dynamic LSTM artifact: {e}")
            self.is_loaded = False
            return False

    def predict_dynamic_telemetry(self, dynamic_result: Any) -> Dict[str, Any]:
        """Perform dynamic LSTM sequence inference on normalized dynamic telemetry.

        Returns prediction dictionary containing classification, probabilities, and sequence stats.
        """
        if not self.is_loaded or self.model is None or self.builder is None:
            self._load_artifacts()
            if self.model is None or self.builder is None:
                return {
                    "model_version": MODEL_VERSION,
                    "classification": "unknown",
                    "malware_probability": 0.5,
                    "benign_probability": 0.5,
                    "threshold": 0.5,
                    "evaluation_status": "DYNAMIC_MODEL_UNAVAILABLE",
                    "sequence_length": 0,
                    "unknown_event_rate": 0.0,
                }

        # Convert dynamic result to sequence representation
        sample_sha256 = getattr(dynamic_result, "sample_sha256", None) or "0" * 64
        sequence = self.builder.convert_result_to_sequence(
            dynamic_result,
            sample_sha256=sample_sha256,
        )

        # Encode sequence
        vector, stats = self.builder.encode_sequence(sequence)

        # Forward pass
        probs = self.model.predict_proba(vector)
        malware_prob = float(probs[0])
        benign_prob = float(1.0 - malware_prob)

        classification = "malware" if malware_prob >= self.threshold else "benign"

        return {
            "model_version": MODEL_VERSION,
            "classification": classification,
            "malware_probability": round(malware_prob, 4),
            "benign_probability": round(benign_prob, 4),
            "threshold": self.threshold,
            "evaluation_status": self.evaluation_status,
            "sequence_length": stats["raw_length"],
            "unknown_event_rate": round(stats["unknown_rate"], 4),
        }


def get_dynamic_model_service() -> DynamicModelService:
    """Dependency provider for DynamicModelService."""
    return DynamicModelService.get_instance()
