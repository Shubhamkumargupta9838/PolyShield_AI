import os
import json
import pytest
import numpy as np
import pandas as pd
from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ml.models.model_registry import ModelRegistry
from ml.training.train_static import train_static_baseline, verify_data_integrity_and_leakage
from ml.data.preprocessing import DatasetPreprocessor


@pytest.fixture
def temp_dataset_and_model_dirs(tmp_path):
    dataset_dir = tmp_path / "dataset"
    models_dir = tmp_path / "models"
    dataset_dir.mkdir()
    models_dir.mkdir()

    np.random.seed(42)
    
    def create_synthetic_split(filename, count, start_id, label_pattern="alternate"):
        rows = []
        for i in range(count):
            sid = f"sample_{start_id + i}"
            sha = f"sha256_hash_{start_id + i:04d}"
            lbl = 0 if label_pattern == "benign_only" else (i % 2)
            feat_values = list(np.random.rand(17))
            meta = [sid, f"{sid}.exe", sha, lbl, "benign" if lbl==0 else "malware", "synthetic", "fam_a", "grp_a", True, "", "v1.0_test", FEATURE_SCHEMA_VERSION]
            rows.append(meta + feat_values)
        cols = ["sample_id", "filename", "sha256", "label", "label_name", "source", "family", "group_id", "analysis_success", "analysis_error", "dataset_version", "feature_schema_version"] + FEATURE_NAMES
        df = pd.DataFrame(rows, columns=cols)
        df.to_csv(dataset_dir / filename, index=False)
        return df

    # Create balanced train, but single-class val & test
    train_df = create_synthetic_split("train_v1.0_test.csv", 20, 100, label_pattern="alternate")
    val_df = create_synthetic_split("validation_v1.0_test.csv", 10, 200, label_pattern="benign_only")
    test_df = create_synthetic_split("test_v1.0_test.csv", 10, 300, label_pattern="benign_only")

    return str(dataset_dir), str(models_dir)


def test_verify_data_integrity_and_leakage(temp_dataset_and_model_dirs):
    dataset_dir, _ = temp_dataset_and_model_dirs
    train_df = pd.read_csv(os.path.join(dataset_dir, "train_v1.0_test.csv"))
    val_df = pd.read_csv(os.path.join(dataset_dir, "validation_v1.0_test.csv"))
    test_df = pd.read_csv(os.path.join(dataset_dir, "test_v1.0_test.csv"))

    preprocessor = DatasetPreprocessor()
    (X_tr, y_tr), (X_va, y_va), (X_te, y_te) = verify_data_integrity_and_leakage(train_df, val_df, test_df, preprocessor)

    assert X_tr.shape == (20, 17)
    assert X_va.shape == (10, 17)
    assert X_te.shape == (10, 17)
    assert list(X_tr.columns) == FEATURE_NAMES


def test_train_static_baseline_pipeline_engineering_mode(temp_dataset_and_model_dirs):
    dataset_dir, models_dir = temp_dataset_and_model_dirs

    results = train_static_baseline(
        dataset_dir=dataset_dir,
        output_dir=models_dir,
        dataset_version="v1.0_test",
        random_state=42,
        strict_evaluation=False
    )

    assert "winner_name" in results
    assert "paths" in results

    paths = results["paths"]
    assert os.path.exists(paths["model_path"])
    assert os.path.exists(paths["metadata_path"])
    assert os.path.exists(paths["rf_model_path"])
    assert os.path.exists(paths["xgb_model_path"])
    assert os.path.exists(paths["comparison_path"])

    # Load metadata and check synthetic_dataset_warning and feature count
    model_name = f"static_baseline_v1.0_test"
    loaded_model, metadata = ModelRegistry.load_model(models_dir, model_name)
    assert metadata["feature_count"] == 17
    assert "synthetic_dataset_warning" in metadata
    assert "WARNING: This evaluation uses 20 synthetic/safe PE engineering fixtures" in metadata["synthetic_dataset_warning"]

    # Verify comparison JSON
    with open(paths["comparison_path"], "r", encoding="utf-8") as f:
        comp_json = json.load(f)
        assert comp_json["dataset_version"] == "v1.0_test"
        assert "synthetic_dataset_warning" in comp_json
        assert "statistical_disclaimer" in comp_json


def test_train_static_baseline_pipeline_strict_evaluation_fails(temp_dataset_and_model_dirs):
    dataset_dir, models_dir = temp_dataset_and_model_dirs

    with pytest.raises(ValueError) as exc_info:
        train_static_baseline(
            dataset_dir=dataset_dir,
            output_dir=models_dir,
            dataset_version="v1.0_test",
            random_state=42,
            strict_evaluation=True
        )
    assert "Strict evaluation mode enabled" in str(exc_info.value)

