import hashlib
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SampleTransferService:
    """
    Controlled sample transfer service.
    Verifies cryptographic identity (SHA-256), size boundaries, and path traversal protection
    before registering untrusted PE metadata inside sandbox execution environment boundaries.
    STRICT BOUNDARY: Does NOT execute binary or share host directories/secrets.
    """

    def __init__(self, max_sample_size_bytes: int = 52428800):
        self.max_sample_size_bytes = max_sample_size_bytes

    def verify_and_prepare_transfer(
        self,
        scan_id: str,
        sample_bytes: bytes,
        expected_sha256: str,
        filename: str = "sample.exe"
    ) -> Dict[str, Any]:
        """
        Validates sample integrity before registering transfer.
        Returns transfer metadata dict if verification passes.
        Raises ValueError if verification or path traversal checks fail.
        """
        # 1. Path traversal protection on input filename
        if ".." in filename or "/" in filename or "\\" in filename:
            logger.warning(f"[SampleTransfer] Directory traversal pattern detected in filename '{filename}'")
            # Strip path elements to force safe basename
            import os
            filename = os.path.basename(filename.replace("\\", "/"))

        # 2. Sample size validation
        if not sample_bytes:
            raise ValueError("Cannot transfer empty 0-byte sample payload.")
        if len(sample_bytes) > self.max_sample_size_bytes:
            raise ValueError(f"Sample size ({len(sample_bytes)} bytes) exceeds maximum upload limit ({self.max_sample_size_bytes} bytes).")

        # 3. PE Magic Header check
        if not sample_bytes.startswith(b"MZ"):
            raise ValueError("Sample payload missing Windows Portable Executable magic header ('MZ').")

        # 4. Cryptographic SHA-256 verification
        calculated_sha256 = hashlib.sha256(sample_bytes).hexdigest()
        if expected_sha256 and calculated_sha256.lower() != expected_sha256.lower():
            err_msg = f"Sample SHA-256 integrity mismatch! Expected: {expected_sha256}, Calculated: {calculated_sha256}"
            logger.error(f"[SampleTransfer] {err_msg}")
            raise ValueError(err_msg)

        transfer_meta = {
            "scan_id": scan_id,
            "sample_sha256": calculated_sha256,
            "sample_size": len(sample_bytes),
            "safe_filename": filename,
            "verified": True
        }
        logger.info(f"[SampleTransfer] Sample transfer integrity verified for scan '{scan_id}' (SHA256={calculated_sha256[:10]}...).")
        return transfer_meta
