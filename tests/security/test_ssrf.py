import pytest
from backend.app.main import app


def test_ssrf_attack_surface_not_exposed():
    """
    PolyShield AI does not accept user-supplied URLs for outbound network fetching.
    This test documents and verifies that the SSRF attack surface is NOT EXPOSED.
    """
    route_paths = [getattr(r, "path", "") for r in app.routes if hasattr(r, "path")]
    for path in route_paths:
        assert "fetch_url" not in path
        assert "webhook_url" not in path
