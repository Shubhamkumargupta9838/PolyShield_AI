import hashlib
import pytest
from sandbox.services.sample_transfer import SampleTransferService


def test_sample_transfer_verification_success():
    service = SampleTransferService()
    pe_bytes = b"MZ" + b"\x90" * 100
    expected_hash = hashlib.sha256(pe_bytes).hexdigest()

    meta = service.verify_and_prepare_transfer(
        scan_id="scan_trans_1",
        sample_bytes=pe_bytes,
        expected_sha256=expected_hash,
        filename="test_sample.exe"
    )

    assert meta["scan_id"] == "scan_trans_1"
    assert meta["sample_sha256"] == expected_hash
    assert meta["verified"] is True
    assert meta["safe_filename"] == "test_sample.exe"


def test_sample_transfer_path_traversal_sanitization():
    service = SampleTransferService()
    pe_bytes = b"MZ" + b"\x90" * 100
    expected_hash = hashlib.sha256(pe_bytes).hexdigest()

    meta = service.verify_and_prepare_transfer(
        scan_id="scan_trans_2",
        sample_bytes=pe_bytes,
        expected_sha256=expected_hash,
        filename="../../malicious.exe"
    )

    assert meta["safe_filename"] == "malicious.exe"


def test_sample_transfer_sha256_mismatch_rejection():
    service = SampleTransferService()
    pe_bytes = b"MZ" + b"\x90" * 100

    with pytest.raises(ValueError, match="integrity mismatch"):
        service.verify_and_prepare_transfer(
            scan_id="scan_trans_3",
            sample_bytes=pe_bytes,
            expected_sha256="0" * 64,
            filename="sample.exe"
        )


def test_sample_transfer_missing_mz_header_rejection():
    service = SampleTransferService()
    non_pe_bytes = b"NOT_PE_HEADER_CONTENT"
    expected_hash = hashlib.sha256(non_pe_bytes).hexdigest()

    with pytest.raises(ValueError, match="Executable magic header"):
        service.verify_and_prepare_transfer(
            scan_id="scan_trans_4",
            sample_bytes=non_pe_bytes,
            expected_sha256=expected_hash,
            filename="sample.exe"
        )
