"""
Shannon Entropy Mathematical Bounding & Safety Test Suite for PolyShield AI (Phase 14).

Verifies mathematical invariants:
1. 0.0 <= calculate_shannon_entropy(data) <= 8.0 for all byte inputs.
2. Uniform byte sequences return 0.0000.
3. Perfect uniform 256-byte distribution returns 8.0000.
4. Empty byte input returns 0.0000 without ZeroDivisionError.
"""

import os
import pytest
from analysis.static.entropy import calculate_shannon_entropy, calculate_entropy_stats


def test_empty_bytes_returns_zero_entropy():
    """Verify empty bytes returns 0.0 cleanly."""
    assert calculate_shannon_entropy(b"") == 0.0


def test_uniform_single_byte_sequence_returns_zero_entropy():
    """Verify uniform byte array (e.g., 1000 zero bytes) has 0 entropy."""
    zeros = b"\x00" * 1024
    ffs = b"\xFF" * 1024
    assert calculate_shannon_entropy(zeros) == 0.0
    assert calculate_shannon_entropy(ffs) == 0.0


def test_perfectly_uniform_256_byte_distribution_returns_eight():
    """Verify perfectly uniform 256-byte distribution produces max theoretical entropy of 8.0."""
    uniform_256 = bytes(range(256)) * 4  # Each byte 0..255 repeated 4 times
    entropy = calculate_shannon_entropy(uniform_256)
    assert entropy == 8.0


@pytest.mark.parametrize("length", [1, 16, 256, 1024, 4096])
def test_random_bytes_entropy_bounds(length: int):
    """Verify entropy is strictly within [0.0, 8.0] for random synthetic byte streams."""
    random_data = os.urandom(length)
    entropy = calculate_shannon_entropy(random_data)
    assert 0.0 <= entropy <= 8.0


def test_entropy_stats_empty_sections():
    """Verify calculate_entropy_stats handles empty list without exception."""
    stats = calculate_entropy_stats([])
    assert stats.max == 0.0
    assert stats.min == 0.0
    assert stats.mean == 0.0
    assert stats.high_entropy_sections_count == 0
