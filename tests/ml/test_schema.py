import pytest
from analysis.static.schemas import StaticFeatureVector
from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION

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


def test_schema_feature_count_and_uniqueness():
    assert len(EXPECTED_FEATURE_NAMES) == 17, "EXPECTED_FEATURE_NAMES must contain exactly 17 features."
    assert len(set(EXPECTED_FEATURE_NAMES)) == 17, "All 17 feature names must be unique."
    assert len(FEATURE_NAMES) == 17, "FEATURE_NAMES must contain exactly 17 features."
    assert len(set(FEATURE_NAMES)) == 17, "All 17 feature names must be unique."
    assert FEATURE_SCHEMA_VERSION == "static-v1"


def test_schema_source_of_truth_binding():
    # Verify StaticFeatureVector.feature_names() matches EXPECTED_FEATURE_NAMES and FEATURE_NAMES exactly
    vector_names = StaticFeatureVector.feature_names()
    assert vector_names == EXPECTED_FEATURE_NAMES, "StaticFeatureVector.feature_names() must match canonical features."
    assert vector_names == FEATURE_NAMES, "StaticFeatureVector.feature_names() must match FEATURE_NAMES exactly."


def test_schema_canonical_feature_ordering():
    assert FEATURE_NAMES == EXPECTED_FEATURE_NAMES, "FEATURE_NAMES ordering has deviated from canonical static-v1 schema."
    assert FEATURE_NAMES[0] == "file_size", "Feature #1 must be file_size."
    assert FEATURE_NAMES.count("file_size") == 1, "file_size must appear exactly once in FEATURE_NAMES."
