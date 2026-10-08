import pytest
import pandas as pd
from ml.data.dataset_quality import inspect_split_quality, inspect_dataset_quality, EvaluationStatus


def test_inspect_split_quality_single_class():
    df = pd.DataFrame({
        "sha256": ["hash_1", "hash_2"],
        "label": [0, 0],
        "group_id": ["grp_a", "grp_a"],
        "family": ["fam_a", "fam_a"],
    })
    quality = inspect_split_quality(df, "validation")
    assert quality["sample_count"] == 2
    assert quality["benign_count"] == 2
    assert quality["malware_count"] == 0
    assert quality["contains_benign"] is True
    assert quality["contains_malware"] is False
    assert quality["has_both_classes"] is False


def test_inspect_split_quality_both_classes():
    df = pd.DataFrame({
        "sha256": ["hash_1", "hash_2"],
        "label": [0, 1],
        "group_id": ["grp_a", "grp_b"],
        "family": ["fam_a", "fam_b"],
    })
    quality = inspect_split_quality(df, "train")
    assert quality["sample_count"] == 2
    assert quality["benign_count"] == 1
    assert quality["malware_count"] == 1
    assert quality["contains_benign"] is True
    assert quality["contains_malware"] is True
    assert quality["has_both_classes"] is True


def test_inspect_dataset_quality_overall():
    train_df = pd.DataFrame({"label": [0, 1], "sha256": ["h1", "h2"]})
    val_df = pd.DataFrame({"label": [0, 0], "sha256": ["h3", "h4"]})
    test_df = pd.DataFrame({"label": [0, 0], "sha256": ["h5", "h6"]})

    quality = inspect_dataset_quality(train_df, val_df, test_df)
    assert quality["scientific_benchmark_available"] is False
    assert quality["evaluation_status"] == EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE.value
    assert quality["dataset_type"] == "synthetic_fixture"
    assert len(quality["warnings"]) > 0
