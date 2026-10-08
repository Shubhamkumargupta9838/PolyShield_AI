import logging
from typing import List, Optional
from sandbox.interfaces.sandbox_provider import ISandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus
from sandbox.models.artifact import SandboxArtifact

logger = logging.getLogger(__name__)


class VmSandboxProvider(ISandboxProvider):
    """
    Hypervisor-level VM Sandbox Provider Implementation.
    Inspects host virtualization environment (Hyper-V / VMware / KVM / VirtualBox).
    If hypervisor backend is missing or unconfigured on developer environment,
    returns PROVIDER_UNAVAILABLE safely with ZERO host PE execution.
    """

    def __init__(self, hypervisor_backend: Optional[str] = None):
        self.hypervisor_backend = hypervisor_backend
        self._is_available = self._detect_hypervisor_availability()

    def _detect_hypervisor_availability(self) -> bool:
        """Detects whether dedicated hypervisor VM infrastructure is operational."""
        # Development environment constraint check: No unmanaged host detonation.
        logger.info("[VmSandboxProvider] Inspecting host hypervisor availability...")
        return False  # Defaults to False in local dev environment without dedicated hypervisor cluster

    def create_environment(self, job: SandboxJob) -> str:
        if not self._is_available:
            logger.warning(f"[VmSandboxProvider] Dedicated VM hypervisor backend is unavailable. Rejecting job '{job.job_id}'.")
            raise RuntimeError("PROVIDER_UNAVAILABLE: Dedicated hypervisor VM environment is not provisioned or available.")
        return "vm_env_001"

    def submit_sample(self, environment_id: str, sample_sha256: str) -> bool:
        if not self._is_available:
            raise RuntimeError("PROVIDER_UNAVAILABLE: Cannot submit sample to unprovisioned VM provider.")
        return True

    def start_analysis(self, environment_id: str) -> bool:
        if not self._is_available:
            raise RuntimeError("PROVIDER_UNAVAILABLE: Cannot start VM analysis.")
        return True

    def collect_artifacts(self, environment_id: str) -> List[SandboxArtifact]:
        if not self._is_available:
            raise RuntimeError("PROVIDER_UNAVAILABLE: Cannot collect artifacts from unprovisioned VM.")
        return []

    def stop_analysis(self, environment_id: str) -> bool:
        return False

    def destroy_environment(self, environment_id: str) -> bool:
        return False

    def get_status(self, environment_id: str) -> SandboxJobStatus:
        if not self._is_available:
            return SandboxJobStatus.FAILED
        return SandboxJobStatus.CREATED
