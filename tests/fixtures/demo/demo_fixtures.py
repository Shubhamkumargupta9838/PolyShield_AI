"""PolyShield AI — Safe Synthetic Demo PE Fixtures (Phase 16).

Provides deterministic, non-executable in-memory PE byte streams for live platform demonstrations.
All fixtures are safe engineering data structures. ZERO HOST EXECUTION.

Dataset Provenance: SYNTHETIC_FIXTURE
Scientific Benchmark Ready: FALSE
"""

from tests.fixtures.safe_pe_fixtures import (
    create_minimal_pe_bytes,
    create_dll_pe_bytes,
    create_rwx_pe_bytes,
    create_high_entropy_pe_bytes,
)

DEMO_FIXTURES = {
    "demo_minimal_pe.exe": {
        "description": "Standard safe synthetic 32-bit benign PE binary fixture",
        "generator": create_minimal_pe_bytes,
        "expected_risk_band": "LOW",
        "provenance": "SYNTHETIC_FIXTURE",
    },
    "demo_dll_pe.dll": {
        "description": "Safe synthetic dynamic link library (DLL) binary fixture",
        "generator": create_dll_pe_bytes,
        "expected_risk_band": "LOW",
        "provenance": "SYNTHETIC_FIXTURE",
    },
    "demo_rwx_pe.exe": {
        "description": "Synthetic PE fixture containing Read-Write-Execute (RWX) section flags",
        "generator": create_rwx_pe_bytes,
        "expected_risk_band": "HIGH",
        "provenance": "SYNTHETIC_FIXTURE",
    },
    "demo_high_entropy_pe.exe": {
        "description": "Synthetic PE fixture with high-entropy section payload (packing simulation)",
        "generator": create_high_entropy_pe_bytes,
        "expected_risk_band": "CRITICAL",
        "provenance": "SYNTHETIC_FIXTURE",
    },
}


def get_demo_fixture(name: str) -> bytes:
    """Retrieves safe synthetic PE byte stream for demo fixture by name."""
    if name not in DEMO_FIXTURES:
        raise ValueError(f"Unknown demo fixture '{name}'. Available: {list(DEMO_FIXTURES.keys())}")
    return DEMO_FIXTURES[name]["generator"]()
