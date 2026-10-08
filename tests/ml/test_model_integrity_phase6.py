import json
from pathlib import Path
from analysis.static.schemas import StaticFeatureVector


def test_approved_model_contract_integrity():
    base_dir = Path(__file__).resolve().parents[2]
    meta_path = base_dir / "ml" / "artifacts" / "models" / "static_baseline_v2.0_metadata.json"

    assert meta_path.exists(), f"Approved model metadata missing at: {meta_path}"

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta.get("dataset_version") == "v2.0"
    assert meta.get("feature_schema_version") == "static-v1"
    assert meta.get("feature_count") == 17
    assert meta.get("feature_names") == StaticFeatureVector.feature_names()
    assert meta.get("classification_threshold") == 0.5
    assert meta.get("dataset_provenance_status") == "SYNTHETIC_FIXTURE"
    assert meta.get("scientific_benchmark") is False
    assert meta.get("evaluation_status") in ("VALID", "ENGINEERING_SMOKE_EVALUATION")
