import pytest
from sandbox.providers.mock_provider import MockSandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus
from sandbox.models.artifact import SandboxArtifact, ArtifactType


def test_mock_provider_lifecycle():
    provider = MockSandboxProvider()
    job = SandboxJob(
        job_id="job_test_1",
        scan_id="scan_test_1",
        sample_sha256="a" * 64
    )

    # 1. Create environment
    env_id = provider.create_environment(job)
    assert env_id.startswith("mock_env_")
    assert provider.get_status(env_id) == SandboxJobStatus.ENVIRONMENT_PREPARED

    # 2. Submit sample reference
    assert provider.submit_sample(env_id, job.sample_sha256) is True
    assert provider.get_status(env_id) == SandboxJobStatus.READY

    # 3. Start analysis
    assert provider.start_analysis(env_id) is True
    assert provider.get_status(env_id) == SandboxJobStatus.RUNNING

    # 4. Collect artifacts
    artifacts = provider.collect_artifacts(env_id)
    assert len(artifacts) == 2
    assert all(isinstance(art, SandboxArtifact) for art in artifacts)
    assert artifacts[0].artifact_type == ArtifactType.PROCESS_TRACE
    assert artifacts[1].artifact_type == ArtifactType.NETWORK_PCAP
    assert artifacts[0].is_executable is False
    assert provider.get_status(env_id) == SandboxJobStatus.COLLECTING

    # 5. Stop analysis
    assert provider.stop_analysis(env_id) is True
    assert provider.get_status(env_id) == SandboxJobStatus.CLEANUP

    # 6. Destroy environment
    assert provider.destroy_environment(env_id) is True
    assert provider.get_status(env_id) == SandboxJobStatus.DESTROYED


def test_mock_provider_non_existent_environment_handling():
    provider = MockSandboxProvider()
    with pytest.raises(ValueError):
        provider.submit_sample("non_existent_env", "a" * 64)

    assert provider.stop_analysis("non_existent_env") is False
    assert provider.destroy_environment("non_existent_env") is False
    assert provider.get_status("non_existent_env") == SandboxJobStatus.DESTROYED
