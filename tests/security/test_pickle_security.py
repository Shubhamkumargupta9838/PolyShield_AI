import pytest
from pathlib import Path
from backend.app.services.model_service import ModelService
from backend.app.core.exceptions import PathTraversalException


def test_pickle_joblib_trust_boundary_enforcement():
    """
    Verifies that ModelService will refuse to load joblib/pickle files from outside the internal
    ml/artifacts/models/ registry directory.
    """
    external_path = Path("/tmp/untrusted_model.joblib")
    with pytest.raises(PathTraversalException):
        ModelService(model_path=str(external_path))
