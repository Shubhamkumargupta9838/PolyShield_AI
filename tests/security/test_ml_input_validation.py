import pytest
import numpy as np
from analysis.static.schemas import StaticFeatureVector
from backend.app.services.model_service import ModelService


def test_model_service_non_finite_input_rejection():
    svc = ModelService()

    # Craft feature vector with NaN / Inf
    invalid_dict = {name: 0.0 for name in StaticFeatureVector.feature_names()}
    invalid_dict["file_size"] = float("nan")

    invalid_vector = StaticFeatureVector(**invalid_dict)

    with pytest.raises(ValueError) as exc_info:
        svc.predict(invalid_vector)
    assert "non-finite" in str(exc_info.value).lower()
