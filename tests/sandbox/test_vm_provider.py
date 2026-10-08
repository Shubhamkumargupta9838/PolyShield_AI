import pytest
from sandbox.providers.vm_provider import VmSandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus


def test_vm_sandbox_provider_unavailable_handling():
    """Verifies that VmSandboxProvider safely returns PROVIDER_UNAVAILABLE when hypervisor is missing."""
    provider = VmSandboxProvider()
    job = SandboxJob(
        job_id="job_vm_1",
        scan_id="scan_vm_1",
        sample_sha256="a" * 64
    )

    with pytest.raises(RuntimeError, match="PROVIDER_UNAVAILABLE"):
        provider.create_environment(job)

    with pytest.raises(RuntimeError, match="PROVIDER_UNAVAILABLE"):
        provider.submit_sample("vm_env_001", "a" * 64)

    with pytest.raises(RuntimeError, match="PROVIDER_UNAVAILABLE"):
        provider.start_analysis("vm_env_001")

    with pytest.raises(RuntimeError, match="PROVIDER_UNAVAILABLE"):
        provider.collect_artifacts("vm_env_001")

    assert provider.stop_analysis("vm_env_001") is False
    assert provider.destroy_environment("vm_env_001") is False
    assert provider.get_status("vm_env_001") == SandboxJobStatus.FAILED
