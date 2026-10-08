import pytest
import pandas as pd
import numpy as np
from ml.data.dataset_builder import DatasetBuilder
from ml.data.preprocessing import DatasetPreprocessor
from ml.data.splitting import DatasetSplitter
from ml.data.constants import FEATURE_NAMES
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes

EXPECTED_FEATURE_NAMES = [
    "file_size",
    "number_of_sections",
    "dll_count",
    "api_count",
    "max_section_entropy",
    "min_section_entropy",
    "mean_section_entropy",
    "high_entropy_section_count",
    "executable_section_count",
    "writable_section_count",
    "rwx_section_count",
    "unusual_section_count",
    "resource_count",
    "suspicious_api_count",
    "static_indicator_count",
    "is_dll",
    "is_driver",
]


def test_preprocessor_extracts_x_and_y():
    pe_bytes = build_minimal_pe_bytes()
    samples = [
        ("sample_1.exe", pe_bytes, 0, None, None),
        ("sample_2.exe", pe_bytes, 1, None, None)
    ]
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list(samples)

    preprocessor = DatasetPreprocessor()
    X, y = preprocessor.extract_features_and_target(df)

    assert X.shape == (2, 17)
    assert X.shape[1] == 17
    assert list(X.columns) == EXPECTED_FEATURE_NAMES
    assert y.tolist() == [0, 1]
    assert "label" not in X.columns
    assert "sha256" not in X.columns
    assert "sample_id" not in X.columns
    assert "filename" not in X.columns
    assert list(X.columns).count("file_size") == 1


def test_splitter_hash_deduplication_prevents_leakage():
    pe_bytes_1 = build_minimal_pe_bytes()
    # Modify 1 byte to make pe_bytes_2 distinct
    pe_bytes_2 = bytearray(pe_bytes_1)
    pe_bytes_2[0x40] = 0xFF
    pe_bytes_2 = bytes(pe_bytes_2)

    # Create dataset with duplicate copies of bytes_1 and bytes_2
    samples = [
        ("s1_a.exe", pe_bytes_1, 0, None, None),
        ("s1_b.exe", pe_bytes_1, 0, None, None),
        ("s1_c.exe", pe_bytes_1, 0, None, None),
        ("s2_a.exe", pe_bytes_2, 1, None, None),
        ("s2_b.exe", pe_bytes_2, 1, None, None),
        ("s2_c.exe", pe_bytes_2, 1, None, None),
    ]
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list(samples)

    splitter = DatasetSplitter(random_state=42)
    train_df, val_df, test_df, split_info = splitter.split_dataset(df)

    train_hashes = set(train_df["sha256"])
    val_hashes = set(val_df["sha256"])
    test_hashes = set(test_df["sha256"])

    # Assert 0 hash leakage across split boundaries
    assert len(train_hashes.intersection(val_hashes)) == 0
    assert len(train_hashes.intersection(test_hashes)) == 0
    assert len(val_hashes.intersection(test_hashes)) == 0
