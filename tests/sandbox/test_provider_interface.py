import pytest
from sandbox.interfaces.sandbox_provider import ISandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus
from sandbox.providers.mock_provider import MockSandboxProvider


def test_isandbox_provider_interface_contract():
    """Verifies that MockSandboxProvider properly implements ISandboxProvider contract."""
    provider = MockSandboxProvider()
    assert isinstance(provider, ISandboxProvider)

    # Inspect abstract methods
    methods = [
        "create_environment",
        "submit_sample",
        "start_analysis",
        "collect_artifacts",
        "stop_analysis",
        "destroy_environment",
        "get_status",
    ]
    for method in methods:
        assert hasattr(provider, method)
        assert callable(getattr(provider, method))


def test_provider_raises_on_invalid_interface_instantiation():
    """Verifies that direct instantiation of ISandboxProvider fails."""
    with pytest.raises(TypeError):
        ISandboxProvider()
