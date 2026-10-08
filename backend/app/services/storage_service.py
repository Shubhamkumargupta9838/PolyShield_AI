import os
import shutil
from abc import ABC, abstractmethod
from typing import Optional
from pathlib import Path
from backend.app.core.logging import logger
from backend.app.core.security import validate_safe_path
from backend.app.core.exceptions import PathTraversalException


class BaseStorageService(ABC):
    """Storage Service interface for handling uploaded PE executable binaries safely."""
    @abstractmethod
    def save_sample(self, scan_id: str, file_bytes: bytes, filename: str) -> str:
        pass

    @abstractmethod
    def get_sample(self, sample_reference: str) -> Optional[bytes]:
        pass

    @abstractmethod
    def delete_sample(self, sample_reference: str) -> bool:
        pass

    @abstractmethod
    def exists(self, sample_reference: str) -> bool:
        pass


class LocalStorageService(BaseStorageService):
    """
    Isolated local filesystem storage service.
    Stores uploaded untrusted PE binaries safely in `data/storage/<scan_id>/input`.
    Enforces strict safe-root path resolution and zero execution permissions.
    """
    def __init__(self, base_dir: Optional[str] = None):
        if base_dir:
            self.storage_dir = Path(base_dir).resolve()
        else:
            env_dir = os.getenv("STORAGE_DIR")
            if env_dir:
                self.storage_dir = Path(env_dir).resolve()
            else:
                # Default storage path outside source trees
                workspace_root = Path(__file__).resolve().parents[3]
                self.storage_dir = workspace_root / "data" / "storage"
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _clean_scan_id(self, ref: str) -> str:
        clean = ref.replace("file_storage://", "").replace("storage://", "").strip()
        if not clean or ".." in clean or "/" in clean or "\\" in clean or "\x00" in clean:
            raise PathTraversalException(ref)
        return os.path.basename(clean).strip()

    def get_path_for_scan(self, scan_id: str) -> Path:
        clean_id = self._clean_scan_id(scan_id)
        candidate = self.storage_dir / clean_id / "input"
        return validate_safe_path(candidate, self.storage_dir)

    def save_sample(self, scan_id: str, file_bytes: bytes, filename: str) -> str:
        file_path = self.get_path_for_scan(scan_id)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "wb") as f:
            f.write(file_bytes)

        logger.info(f"Saved binary sample for scan_id='{scan_id}' ({len(file_bytes)} bytes)")
        return f"file_storage://{self._clean_scan_id(scan_id)}"

    def get_sample(self, sample_reference: str) -> Optional[bytes]:
        try:
            file_path = self.get_path_for_scan(sample_reference)
            if not file_path.exists():
                logger.warning(f"Sample file not found for reference: {sample_reference}")
                return None
            with open(file_path, "rb") as f:
                return f.read()
        except PathTraversalException:
            raise
        except Exception as e:
            logger.error(f"Error reading sample reference '{sample_reference}': {str(e)}")
            return None

    def delete_sample(self, sample_reference: str) -> bool:
        try:
            file_path = self.get_path_for_scan(sample_reference)
            scan_dir = file_path.parent
            if scan_dir.exists():
                shutil.rmtree(scan_dir)
                logger.info(f"Deleted storage directory for '{sample_reference}'")
                return True
            return False
        except PathTraversalException:
            raise
        except Exception as e:
            logger.error(f"Error deleting sample '{sample_reference}': {str(e)}")
            return False

    def exists(self, sample_reference: str) -> bool:
        try:
            file_path = self.get_path_for_scan(sample_reference)
            return file_path.exists()
        except Exception:
            return False


class MockStorageService(BaseStorageService):
    """
    In-memory storage service for fast isolated unit testing.
    """
    def __init__(self):
        self._mock_store = {}

    def save_sample(self, scan_id: str, file_bytes: bytes, filename: str) -> str:
        ref = f"storage://samples/{scan_id}"
        self._mock_store[ref] = file_bytes
        self._mock_store[scan_id] = file_bytes
        return ref

    def get_sample(self, sample_reference: str) -> Optional[bytes]:
        clean = sample_reference.replace("file_storage://", "").replace("storage://samples/", "").replace("storage://", "")
        return self._mock_store.get(sample_reference) or self._mock_store.get(clean)

    def delete_sample(self, sample_reference: str) -> bool:
        clean = sample_reference.replace("file_storage://", "").replace("storage://samples/", "").replace("storage://", "")
        deleted = False
        if sample_reference in self._mock_store:
            del self._mock_store[sample_reference]
            deleted = True
        if clean in self._mock_store:
            del self._mock_store[clean]
            deleted = True
        return deleted

    def exists(self, sample_reference: str) -> bool:
        clean = sample_reference.replace("file_storage://", "").replace("storage://samples/", "").replace("storage://", "")
        return sample_reference in self._mock_store or clean in self._mock_store
