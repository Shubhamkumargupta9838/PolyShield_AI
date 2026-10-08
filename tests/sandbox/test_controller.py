import pytest
from sandbox.controller.sandbox_controller import SandboxController
from sandbox.providers.mock_provider import MockSandboxProvider
from sandbox.models.sandbox_job import SandboxJobStatus, CleanupStatus


def test_sandbox_controller_job_creation():
    controller = SandboxController()
    job = controller.create_job(scan_id="scan_123", sample_sha256="b" * 64)

    assert job.job_id.startswith("sb_job_")
    assert job.scan_id == "scan_123"
    assert job.sample_sha256 == "b" * 64
    assert job.provider == "mock"
    assert job.status == SandboxJobStatus.CREATED
    assert len(controller.get_audit_log()) == 1


def test_sandbox_controller_successful_lifecycle_execution():
    controller = SandboxController()
    job = controller.create_job(scan_id="scan_456", sample_sha256="c" * 64)
    result = controller.execute_job_lifecycle(job.job_id)

    assert result.job_id == job.job_id
    assert result.status == SandboxJobStatus.COMPLETED
    assert result.cleanup_status == CleanupStatus.COMPLETED
    assert result.artifact_count == 2
    assert result.error is None
    assert "MockSandboxProvider used" in result.synthetic_disclosure


def test_sandbox_controller_timeout_simulation_and_cleanup():
    controller = SandboxController()
    job = controller.create_job(scan_id="scan_789", sample_sha256="d" * 64, timeout_seconds=10)
    result = controller.simulate_timeout(job.job_id)

    assert result.status == SandboxJobStatus.TIMEOUT
    assert result.cleanup_status == CleanupStatus.COMPLETED
    assert "timed out" in result.error
    assert result.artifact_count == 0


def test_sandbox_controller_stale_job_reconciliation():
    controller = SandboxController()
    job = controller.create_job(scan_id="scan_stale", sample_sha256="e" * 64)

    # Manually simulate running job started in the past
    job.status = SandboxJobStatus.RUNNING
    from datetime import datetime, timezone, timedelta
    job.started_at = datetime.now(timezone.utc) - timedelta(seconds=700)

    # Reconcile stale jobs exceeding 600s
    reconciled = controller.reconcile_stale_jobs(max_stale_seconds=600)
    assert reconciled == 1
    assert job.status == SandboxJobStatus.FAILED
    assert job.cleanup_status == CleanupStatus.COMPLETED
