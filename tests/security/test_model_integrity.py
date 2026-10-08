import pytest
from backend.app.services.model_service import ModelService
from backend.app.core.exceptions import ModelIntegrityException, PathTraversalException


def test_model_service_checksum_computation():
    svc = ModelService()
    sha256 = svc.verify_model_integrity()
    assert len(sha256) == 64
    assert isinstance(sha256, str)


def test_model_service_path_traversal_rejection():
    with pytest.raises(PathTraversalException):
        ModelService(model_path="../../tmp/attacker_model.joblib")
