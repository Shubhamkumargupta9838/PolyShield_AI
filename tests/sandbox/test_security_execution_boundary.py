import pytest
from unittest.mock import patch
from sandbox.controller.sandbox_controller import SandboxController
from sandbox.providers.mock_provider import MockSandboxProvider


def test_security_assertion_zero_host_subprocess_execution():
    """
    SECURITY BOUNDARY ASSERTION:
    Verifies that zero subprocess calls (subprocess.Popen, subprocess.run, os.system)
    are invoked during sandbox creation, execution, artifact collection, or cleanup.
    """
    controller = SandboxController(provider=MockSandboxProvider())

    with patch("subprocess.Popen") as mock_popen, \
         patch("subprocess.run") as mock_run, \
         patch("os.system") as mock_os_system:

        job = controller.create_job(scan_id="scan_sec_assert", sample_sha256="f" * 64)
        result = controller.execute_job_lifecycle(job.job_id)

        # Assert no process execution calls were initiated
        mock_popen.assert_not_called()
        mock_run.assert_not_called()
        mock_os_system.assert_not_called()

        assert result.status.value == "COMPLETED"


def test_security_assertion_prohibit_sample_binary_payloads_in_jobs():
    """
    SECURITY BOUNDARY ASSERTION:
    Verifies that raw PE executable byte payloads cannot be stored inside SandboxJob fields.
    """
    controller = SandboxController()
    job = controller.create_job(scan_id="scan_no_payload", sample_sha256="1234567890abcdef" * 4)

    # Verify job attributes only contain metadata and policy models
    job_dict_keys = set(job.model_dump().keys())
    forbidden_keys = {"raw_bytes", "sample_payload", "binary_content", "pe_bytes"}

    assert forbidden_keys.intersection(job_dict_keys) == set()
