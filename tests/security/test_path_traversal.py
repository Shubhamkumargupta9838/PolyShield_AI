import pytest
from pathlib import Path
from backend.app.core.security import validate_safe_path
from backend.app.core.exceptions import PathTraversalException
from backend.app.services.storage_service import LocalStorageService


def test_safe_path_validation_allowed():
    allowed_root = Path(__file__).resolve().parents[2] / "data" / "storage"
    candidate = allowed_root / "scan_123" / "input"
    validated = validate_safe_path(candidate, allowed_root)
    assert validated == candidate.resolve()


def test_safe_path_validation_traversal_escapes():
    allowed_root = Path(__file__).resolve().parents[2] / "data" / "storage"
    candidate = allowed_root / ".." / ".." / "etc" / "passwd"

    with pytest.raises(PathTraversalException):
        validate_safe_path(candidate, allowed_root)


def test_local_storage_service_path_traversal_rejection():
    svc = LocalStorageService()
    with pytest.raises(PathTraversalException):
        svc.get_path_for_scan("../../../etc/passwd")

    with pytest.raises(PathTraversalException):
        svc.get_path_for_scan("..\\..\\Windows\\System32\\config")
