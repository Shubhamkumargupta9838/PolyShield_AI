import pytest
from analysis.static.schemas import StaticFeatureVector
from backend.app.services.model_service import ModelService, get_model_service
from backend.app.core.exceptions import (
    ModelServiceUnavailableException,
    ModelContractValidationException
)


def create_sample_feature_vector() -> StaticFeatureVector:
    return StaticFeatureVector(
        file_size=50000.0,
        number_of_sections=4.0,
        dll_count=3.0,
        api_count=25.0,
        max_section_entropy=6.5,
        min_section_entropy=1.2,
        mean_section_entropy=4.1,
        high_entropy_section_count=0.0,
        executable_section_count=1.0,
        writable_section_count=1.0,
        rwx_section_count=0.0,
        unusual_section_count=0.0,
        resource_count=2.0,
        suspicious_api_count=1.0,
        static_indicator_count=0.0,
        is_dll=0.0,
        is_driver=0.0
    )


def test_model_service_load_and_contract():
    service = ModelService()
    service.load_model()
    assert service.is_initialized is True
    assert service.metadata.get("feature_count") == 17
    assert service.metadata.get("feature_schema_version") == "static-v1"
    assert service.metadata.get("dataset_version") == "v2.0"
    assert service.metadata.get("classification_threshold") == 0.5


def test_model_service_predict():
    service = get_model_service()
    vec = create_sample_feature_vector()
    
    result = service.predict(vec)
    
    assert "prediction" in result
    assert result["prediction"] in (0, 1)
    assert result["prediction_label"] in ("BENIGN", "MALWARE")
    assert 0.0 <= result["malware_score"] <= 1.0
    assert 0.0 <= result["benign_score"] <= 1.0
    assert abs((result["malware_score"] + result["benign_score"]) - 1.0) < 0.01
    assert result["threshold"] == 0.5
    assert result["feature_schema_version"] == "static-v1"
    assert result["dataset_version"] == "v2.0"
    assert result["dataset_provenance_status"] == "SYNTHETIC_FIXTURE"
    assert "synthetic/safe PE" in result["synthetic_dataset_warning"] or "Engineering Evaluation Model" in result["synthetic_dataset_warning"]


def test_model_service_contract_validation_failures(tmp_path):
    invalid_meta_path = tmp_path / "invalid_meta.json"

    # 1. Test feature count mismatch
    invalid_meta = {
        "dataset_version": "v2.0",
        "feature_schema_version": "static-v1",
        "feature_count": 16,
        "feature_names": StaticFeatureVector.feature_names()[:16],
        "classification_threshold": 0.5
    }
    invalid_meta_path.write_text(pytest.importorskip("json").dumps(invalid_meta))

    service = ModelService(metadata_path=str(invalid_meta_path))
    with pytest.raises(ModelContractValidationException):
        service.load_model()

    # 2. Test schema version mismatch
    invalid_meta["feature_count"] = 17
    invalid_meta["feature_names"] = StaticFeatureVector.feature_names()
    invalid_meta["feature_schema_version"] = "static-v0"
    invalid_meta_path.write_text(pytest.importorskip("json").dumps(invalid_meta))

    service = ModelService(metadata_path=str(invalid_meta_path))
    with pytest.raises(ModelContractValidationException):
        service.load_model()
