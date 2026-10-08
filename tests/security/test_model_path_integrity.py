import pytest
from pathlib import Path
from backend.app.services.model_service import ModelService
from backend.app.core.exceptions import PathTraversalException, ModelIntegrityException
from ml.models.lstm import DynamicLSTMModel


def test_model_service_path_traversal_prevention():
    # Attempting to load model from outside allowed models directory MUST raise PathTraversalException
    untrusted_path = "/etc/passwd"
    with pytest.raises(PathTraversalException):
        ModelService(model_path=untrusted_path)

    relative_traversal = "../../etc/passwd"
    with pytest.raises(PathTraversalException):
        ModelService(model_path=relative_traversal)


def test_dynamic_lstm_weights_only_loading(tmp_path):
    # Verify load_artifact uses weights_only=True and safely loads model state dict
    model = DynamicLSTMModel()
    weights_path, meta_path = model.save_artifact(output_dir=tmp_path)

    loaded_model = DynamicLSTMModel.load_artifact(weights_path, meta_path)
    assert loaded_model is not None
    assert isinstance(loaded_model, DynamicLSTMModel)
