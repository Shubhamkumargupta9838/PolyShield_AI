import pytest
from analysis.static.extractor import StaticFeatureExtractor
from analysis.static.schemas import StaticFeatureVector
from ml.data.dataset_builder import DatasetBuilder
from ml.data.preprocessing import DatasetPreprocessor
from ml.data.constants import FEATURE_NAMES
from tests.analysis.test_static_analyzer import build_minimal_pe_bytes


def test_mandatory_phase3_to_phase4_integration_pipeline():
    """
    Mandatory Phase 3 -> Phase 4 integration proof:
    Safe PE Fixture -> Phase 3 Static Extractor -> StaticFeatureVector -> Phase 4 DatasetBuilder -> 17-column X Matrix
    """
    # Step 1: Safe PE Fixture
    pe_bytes = build_minimal_pe_bytes()
    filename = "integration_test_sample.exe"

    # Step 2: Phase 3 Static Feature Extractor
    extractor = StaticFeatureExtractor()
    static_result = extractor.extract_from_bytes(pe_bytes, filename)
    vec = extractor.vectorize(static_result)

    assert isinstance(vec, StaticFeatureVector)
    vec_dict = vec.to_dict()
    assert len(vec_dict) == 17, f"StaticFeatureVector must contain exactly 17 entries, got {len(vec_dict)}"

    # Step 3: Phase 4 Dataset Builder
    builder = DatasetBuilder(dataset_version="v1.0_test")
    dataset_df = builder.build_from_bytes_list([
        (filename, pe_bytes, 1, "malware_family_x", "group_alpha")
    ])

    assert len(dataset_df) == 1
    assert dataset_df.loc[0, "analysis_success"] == True
    assert dataset_df.loc[0, "label"] == 1

    # Step 4: Phase 4 Dataset Preprocessor
    preprocessor = DatasetPreprocessor()
    X, y = preprocessor.extract_features_and_target(dataset_df)

    # Step 5: Verification of 17-column invariants
    assert X.shape == (1, 17), f"Expected X shape (1, 17), got {X.shape}"
    assert list(X.columns) == FEATURE_NAMES, "X.columns must match canonical FEATURE_NAMES ordering."
    assert X.columns[0] == "file_size", "Feature column #1 must be file_size."
    assert "label" not in X.columns
    assert "sha256" not in X.columns
    assert "sample_id" not in X.columns
