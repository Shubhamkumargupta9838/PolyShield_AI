"""Explanation Artifact Serializer (Phase 12).

Exports ExplanationResult objects and machine-readable explanation benchmarks
to `ml/artifacts/explanations/explanation_v1.0.json`.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from ml.explainability.schemas import ExplanationResult, EXPLANATION_VERSION


class ExplanationSerializer:
    """Serializes explanation objects into machine-readable JSON artifacts."""

    @staticmethod
    def serialize_to_dict(result: ExplanationResult) -> Dict[str, Any]:
        """Converts ExplanationResult to JSON-compatible dictionary."""
        return result.model_dump(mode="json")

    @staticmethod
    def save_artifact(
        result: ExplanationResult,
        output_dir: Path | str = "ml/artifacts/explanations",
        filename: str = "explanation_v1.0.json",
    ) -> Path:
        """Saves ExplanationResult as structured JSON artifact."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        file_path = out_path / filename

        data_dict = ExplanationSerializer.serialize_to_dict(result)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data_dict, f, indent=2)

        return file_path
