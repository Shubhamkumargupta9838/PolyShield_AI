import pytest
import pandas as pd
from ml.data.dataset_builder import DatasetBuilder
from ml.data.validation import DatasetValidator, DatasetValidationError
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


def test_builder_in_memory_success():
    pe_bytes = build_minimal_pe_bytes()
    samples = [
        ("benign_1.exe", pe_bytes, 0, None, None),
        ("malware_1.exe", pe_bytes, 1, "family_a", "group_1")
    ]
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list(samples)

    assert len(df) == 2
    assert (df["analysis_success"] == True).all()
    assert df.loc[0, "label"] == 0
    assert df.loc[1, "label"] == 1
    assert df.loc[1, "family"] == "family_a"


def test_builder_analyzer_failure_logging():
    invalid_bytes = b"CORRUPTED NON PE HEADER"
    samples = [
        ("corrupted.exe", invalid_bytes, 1, None, None)
    ]
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list(samples)

    assert len(df) == 1
    assert df.loc[0, "analysis_success"] == False
    assert df.loc[0, "analysis_error"] is not None
    assert "Invalid or corrupted" in df.loc[0, "analysis_error"]


def test_validator_detects_nan_and_entropy_out_of_range():
    pe_bytes = build_minimal_pe_bytes()
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list([("sample.exe", pe_bytes, 0, None, None)])

    # Corrupt entropy out of range
    df.loc[0, "max_section_entropy"] = 9.5

    with pytest.raises(DatasetValidationError, match="out of range"):
        DatasetValidator.validate_dataset(df, strict=True)


def test_validator_detects_duplicate_sha256():
    pe_bytes = build_minimal_pe_bytes()
    samples = [
        ("sample_copy_1.exe", pe_bytes, 0, None, None),
        ("sample_copy_2.exe", pe_bytes, 0, None, None)
    ]
    builder = DatasetBuilder()
    df = builder.build_from_bytes_list(samples)

    report = DatasetValidator.validate_dataset(df, strict=False)
    assert report["duplicate_sha256_groups"] == 1
    assert report["duplicate_records_count"] == 2
