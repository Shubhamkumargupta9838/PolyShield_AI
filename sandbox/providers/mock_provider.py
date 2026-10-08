import uuid
import hashlib
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

from sandbox.interfaces.sandbox_provider import ISandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus
from sandbox.models.artifact import SandboxArtifact, ArtifactType

logger = logging.getLogger(__name__)


class MockSandboxProvider(ISandboxProvider):
    """
    Mock implementation of ISandboxProvider for Phase 8 Architecture Foundation.
    Simulates environment lifecycle transitions and returns synthetic telemetry metadata.
    STRICT SECURITY RULE: Absolutely ZERO PE sample execution, subprocess invocation, or host execution.
    """

    def __init__(self):
        self._environments: Dict[str, Dict[str, Any]] = {}

    def create_environment(self, job: SandboxJob) -> str:
        """Simulates allocation of isolated VM environment."""
        env_id = f"mock_env_{uuid.uuid4().hex[:8]}"
        self._environments[env_id] = {
            "env_id": env_id,
            "job_id": job.job_id,
            "scan_id": job.scan_id,
            "sample_sha256": job.sample_sha256,
            "status": SandboxJobStatus.ENVIRONMENT_PREPARED,
            "created_at": datetime.now(timezone.utc),
            "sample_submitted": False
        }
        logger.info(f"[MockSandboxProvider] Created mock isolated environment: {env_id}")
        return env_id

    def submit_sample(self, environment_id: str, sample_sha256: str) -> bool:
        """Simulates transferring sample metadata reference (no binary execution)."""
        if environment_id not in self._environments:
            raise ValueError(f"Environment '{environment_id}' not found.")
        env = self._environments[environment_id]
        env["sample_submitted"] = True
        env["status"] = SandboxJobStatus.READY
        logger.info(f"[MockSandboxProvider] Sample SHA-256 metadata reference {sample_sha256[:10]}... registered in {environment_id}")
        return True

    def start_analysis(self, environment_id: str) -> bool:
        """Simulates starting analysis lifecycle."""
        if environment_id not in self._environments:
            raise ValueError(f"Environment '{environment_id}' not found.")
        env = self._environments[environment_id]
        env["status"] = SandboxJobStatus.RUNNING
        logger.info(f"[MockSandboxProvider] Simulated analysis started in {environment_id}")
        return True

    def collect_artifacts(self, environment_id: str) -> List[SandboxArtifact]:
        """Generates synthetic mock telemetry artifacts clearly marked as non-executed mock data."""
        if environment_id not in self._environments:
            raise ValueError(f"Environment '{environment_id}' not found.")
        env = self._environments[environment_id]
        env["status"] = SandboxJobStatus.COLLECTING

        job_id = env["job_id"]
        scan_id = env["scan_id"]
        now = datetime.now(timezone.utc)

        # Create safe, synthetic mock artifact records
        mock_trace_bytes = b"MOCK_PROCESS_TRACE: simulated process tree analysis"
        mock_pcap_bytes = b"MOCK_NETWORK_PCAP: simulated network telemetry"

        artifact_1 = SandboxArtifact(
            artifact_id=f"art_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            scan_id=scan_id,
            artifact_type=ArtifactType.PROCESS_TRACE,
            sha256=hashlib.sha256(mock_trace_bytes).hexdigest(),
            size_bytes=len(mock_trace_bytes),
            timestamp=now,
            source="mock_sandbox_provider",
            storage_reference=f"data/storage/{scan_id}/artifacts/mock_proc_trace.json",
            is_executable=False,
            metadata={"note": "Synthetic mock telemetry log. No binary executed."}
        )

        artifact_2 = SandboxArtifact(
            artifact_id=f"art_{uuid.uuid4().hex[:8]}",
            job_id=job_id,
            scan_id=scan_id,
            artifact_type=ArtifactType.NETWORK_PCAP,
            sha256=hashlib.sha256(mock_pcap_bytes).hexdigest(),
            size_bytes=len(mock_pcap_bytes),
            timestamp=now,
            source="mock_sandbox_provider",
            storage_reference=f"data/storage/{scan_id}/artifacts/mock_network.pcap",
            is_executable=False,
            metadata={"note": "Synthetic mock network PCAP. No actual network traffic generated."}
        )

        logger.info(f"[MockSandboxProvider] Collected 2 synthetic mock artifacts for environment {environment_id}")
        return [artifact_1, artifact_2]

    def stop_analysis(self, environment_id: str) -> bool:
        """Simulates stopping analysis process."""
        if environment_id not in self._environments:
            return False
        env = self._environments[environment_id]
        env["status"] = SandboxJobStatus.CLEANUP
        logger.info(f"[MockSandboxProvider] Simulated analysis stopped in {environment_id}")
        return True

    def destroy_environment(self, environment_id: str) -> bool:
        """Simulates destruction / snapshot revert of VM instance."""
        if environment_id not in self._environments:
            return False
        env = self._environments[environment_id]
        env["status"] = SandboxJobStatus.DESTROYED
        logger.info(f"[MockSandboxProvider] Simulated environment {environment_id} destroyed/reverted cleanly.")
        return True

    def get_status(self, environment_id: str) -> SandboxJobStatus:
        """Returns status of specified mock environment."""
        if environment_id not in self._environments:
            return SandboxJobStatus.DESTROYED
        return self._environments[environment_id]["status"]
