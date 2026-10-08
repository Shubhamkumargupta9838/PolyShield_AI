"""
Malformed PE & Corrupted Input Handling Test Suite for PolyShield AI (Phase 14).

Verifies that the static feature extractor gracefully handles corrupted,
truncated, non-PE, and malformed inputs with safe exceptions without host subprocess calls.
"""

import pytest
from analysis.static.extractor import StaticFeatureExtractor
from tests.fixtures.safe_pe_fixtures import (
    create_truncated_pe_bytes,
    create_non_pe_bytes,
    create_minimal_pe_bytes
)


def test_empty_file_content_raises_value_error():
    """Verify that 0-byte file input raises ValueError."""
    extractor = StaticFeatureExtractor()
    with pytest.raises(ValueError) as exc_info:
        extractor.extract_from_bytes(b"", "empty_file.exe")
    assert "content is empty" in str(exc_info.value).lower()


def test_non_pe_binary_raises_value_error():
    """Verify non-PE binary bytes raise ValueError safely."""
    extractor = StaticFeatureExtractor()
    non_pe_bytes = create_non_pe_bytes()
    with pytest.raises(ValueError) as exc_info:
        extractor.extract_from_bytes(non_pe_bytes, "random_data.bin")
    assert "invalid or corrupted windows pe" in str(exc_info.value).lower()


def test_truncated_pe_header_raises_value_error():
    """Verify truncated PE header raises ValueError gracefully."""
    extractor = StaticFeatureExtractor()
    truncated_bytes = create_truncated_pe_bytes()
    with pytest.raises(ValueError) as exc_info:
        extractor.extract_from_bytes(truncated_bytes, "truncated.exe")
    assert "invalid or corrupted" in str(exc_info.value).lower()


def test_minimal_safe_synthetic_pe_extracts_cleanly():
    """Verify valid minimal synthetic PE binary extracts without error."""
    extractor = StaticFeatureExtractor()
    pe_bytes = create_minimal_pe_bytes()
    result = extractor.extract_from_bytes(pe_bytes, "minimal_test.exe")
    assert result.file.filename == "minimal_test.exe"
    assert result.file.file_size == len(pe_bytes)
    assert result.pe.number_of_sections >= 1
