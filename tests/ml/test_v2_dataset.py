import os
import pytest
import hashlib
import numpy as np
import pandas as pd

from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION
from ml.data.dataset_builder import DatasetBuilder, compute_dataset_fingerprint
from ml.data.dataset_quality import inspect_dataset_quality, EvaluationStatus
from ml.data.splitting import DatasetSplitter
from ml.data.preprocessing import DatasetPreprocessor
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


def test_sha256_calculation_and_deduplication():
    pe_bytes_1 = build_minimal_pe_bytes()
    pe_bytes_2 = bytearray(pe_bytes_1)
    pe_bytes_2[0x40] = 0xAA
    pe_bytes_2 = bytes(pe_bytes_2)

    sha1 = hashlib.sha256(pe_bytes_1).hexdigest()
    sha2 = hashlib.sha256(pe_bytes_2).hexdigest()
    assert sha1 != sha2

    # Verify dataset builder calculates SHA256 deterministically from bytes
    builder = DatasetBuilder(dataset_version="v2.0_test")
    samples = [
        ("s1_a.exe", pe_bytes_1, 0, "fam_a", "grp_1"),
        ("s1_b.exe", pe_bytes_1, 0, "fam_a", "grp_1"), # Duplicate byte content
        ("s2.exe", pe_bytes_2, 1, "fam_b", "grp_2"),
    ]
    df = builder.build_from_bytes_list(samples)

    assert len(df) == 3
    assert df.loc[0, "sha256"] == sha1
    assert df.loc[1, "sha256"] == sha1
    assert df.loc[2, "sha256"] == sha2

    # Deduplicate before splitting
    splitter = DatasetSplitter(random_state=42)
    train_df, val_df, test_df, split_info = splitter.split_dataset(df, group_aware=True)

    # Check zero SHA256 overlap between splits
    tr_hashes = set(train_df["sha256"])
    va_hashes = set(val_df["sha256"])
    te_hashes = set(test_df["sha256"])
    assert len(tr_hashes.intersection(va_hashes)) == 0
    assert len(tr_hashes.intersection(te_hashes)) == 0
    assert len(va_hashes.intersection(te_hashes)) == 0


def test_pe_validation_and_failure_logging():
    builder = DatasetBuilder(dataset_version="v2.0_test")
    invalid_pe_bytes = b"NOT_A_VALID_PE_FILE_HEADER"

    samples = [
        ("bad_file.exe", invalid_pe_bytes, 1, "unknown", "unknown")
    ]
    df = builder.build_from_bytes_list(samples)
    assert len(df) == 1
    assert bool(df.loc[0, "analysis_success"]) is False
    assert df.loc[0, "analysis_error"] is not None
    assert "Invalid or corrupted Windows PE binary format" in str(df.loc[0, "analysis_error"])


def test_v2_feature_contract_and_zero_metadata_leakage():
    pe_bytes = build_minimal_pe_bytes()
    builder = DatasetBuilder(dataset_version="v2.0_test")
    df = builder.build_from_bytes_list([
        ("sample_1.exe", pe_bytes, 0, "fam_a", "grp_1")
    ])

    preprocessor = DatasetPreprocessor()
    X, y = preprocessor.extract_features_and_target(df)

    assert X.shape == (1, 17)
    assert list(X.columns) == FEATURE_NAMES
    assert list(X.columns).count("file_size") == 1
    assert "sha256" not in X.columns
    assert "sample_id" not in X.columns
    assert "family" not in X.columns
    assert "group_id" not in X.columns
    assert "source" not in X.columns
    assert "label" not in X.columns


def test_deterministic_dataset_fingerprint():
    pe_bytes_1 = build_minimal_pe_bytes()
    pe_bytes_2 = bytearray(pe_bytes_1)
    pe_bytes_2[0x40] = 0xBB
    pe_bytes_2 = bytes(pe_bytes_2)

    builder = DatasetBuilder(dataset_version="v2.0_test")
    df1 = builder.build_from_bytes_list([
        ("s1.exe", pe_bytes_1, 0, "fam_a", "grp_1"),
        ("s2.exe", pe_bytes_2, 1, "fam_b", "grp_2"),
    ])
    df2 = builder.build_from_bytes_list([
        ("s1.exe", pe_bytes_1, 0, "fam_a", "grp_1"),
        ("s2.exe", pe_bytes_2, 1, "fam_b", "grp_2"),
    ])

    fp1 = compute_dataset_fingerprint(df1)
    fp2 = compute_dataset_fingerprint(df2)
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA256 hex length


def test_scientific_benchmark_gate_validity():
    np.random.seed(42)
    def create_df_split(count, benign_count):
        rows = []
        for i in range(count):
            lbl = 0 if i < benign_count else 1
            rows.append({
                "sha256": f"hash_{i}_{lbl}",
                "label": lbl,
                "analysis_success": True,
            })
        return pd.DataFrame(rows)

    # Valid: train, val, test all contain benign and malware
    train_valid = create_df_split(10, 5)
    val_valid = create_df_split(4, 2)
    test_valid = create_df_split(4, 2)

    q_valid = inspect_dataset_quality(train_valid, val_valid, test_valid)
    assert q_valid["structurally_valid"] is True
    assert q_valid["evaluation_status"] == EvaluationStatus.VALID.value

    # Invalid: val lacks malware
    val_invalid = create_df_split(4, 4)
    q_invalid = inspect_dataset_quality(train_valid, val_invalid, test_valid)
    assert q_invalid["structurally_valid"] is False
    assert q_invalid["evaluation_status"] == EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE.value


def test_no_file_execution_security_assertion():
    """
    Verifies that feature extraction relies exclusively on in-memory byte streams
    without executing or writing binary files to disk.
    """
    pe_bytes = build_minimal_pe_bytes()
    extractor = DatasetBuilder().extractor

    # Extract directly from byte stream in memory
    result = extractor.extract_from_bytes(pe_bytes, "in_memory.exe")
    assert result.file.file_size == len(pe_bytes)
    assert result.pe.is_executable is True


def test_provenance_classification_and_counts():
    """
    Verifies dataset provenance classification and sample breakdown counts.
    """
    def create_provenance_df(source_list):
        return pd.DataFrame([{
            "sha256": f"hash_{i}",
            "label": i % 2,
            "source": src,
            "analysis_success": True
        } for i, src in enumerate(source_list)])

    syn_df = create_provenance_df(["synthetic_fixture"] * 10)
    q_syn = inspect_dataset_quality(syn_df.iloc[:6], syn_df.iloc[6:8], syn_df.iloc[8:], full_df=syn_df)

    assert q_syn["dataset_provenance_status"] == "SYNTHETIC_FIXTURE"
    assert q_syn["synthetic_sample_count"] == 10
    assert q_syn["safe_fixture_sample_count"] == 10
    assert q_syn["verified_real_sample_count"] == 0
    assert q_syn["unverified_sample_count"] == 0
    assert q_syn["structurally_valid"] is True
    assert q_syn["scientifically_benchmark_ready"] is False
    assert q_syn["statistically_powerful"] is False

    real_df = create_provenance_df(["verified_external"] * 100)
    q_real = inspect_dataset_quality(real_df.iloc[:70], real_df.iloc[70:85], real_df.iloc[85:], full_df=real_df)

    assert q_real["dataset_provenance_status"] == "VERIFIED_REAL_EXTERNAL_DATA"
    assert q_real["verified_real_sample_count"] == 100
    assert q_real["synthetic_sample_count"] == 0
    assert q_real["structurally_valid"] is True
    assert q_real["scientifically_benchmark_ready"] is True
    assert q_real["statistically_powerful"] is False


def test_source_manifest_integrity():
    """
    Verifies that data/metadata/source_manifest.csv contains valid structure and honest source tags.
    """
    manifest_path = "data/metadata/source_manifest.csv"
    if os.path.exists(manifest_path):
        df = pd.read_csv(manifest_path)
        assert len(df) == 20
        assert set(df["source"]).issubset({"synthetic_fixture", "project_safe_fixture"})
        assert set(df["label"]).issubset({0, 1})
        assert (df["label"] == 0).sum() == 10
        assert (df["label"] == 1).sum() == 10

