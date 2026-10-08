import uuid
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from sandbox.interfaces.sandbox_provider import ISandboxProvider
from sandbox.providers.mock_provider import MockSandboxProvider
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus, CleanupStatus
from sandbox.models.sandbox_result import SandboxResult
from sandbox.models.artifact import SandboxArtifact

logger = logging.getLogger(__name__)


class SandboxController:
    """
    Controller responsible for Sandbox job validation, provider orchestration, lifecycle execution,
    timeout handling, artifact collection integrity, cleanup guarantees, and stale-job watchdog reconciliation.
    STRICT BOUNDARY: Does NOT execute PE files. Uses MockSandboxProvider by default.
    """

    def __init__(self, provider: Optional[ISandboxProvider] = None):
        self.provider: ISandboxProvider = provider or MockSandboxProvider()
        self._jobs: Dict[str, SandboxJob] = {}
        self._audit_log: List[Dict[str, Any]] = []

    def _log_event(self, job_id: str, event_type: str, details: Dict[str, Any]):
        """Records structured security audit event."""
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": job_id,
            "event_type": event_type,
            "details": details
        }
        self._audit_log.append(audit_entry)
        logger.info(f"[SandboxAudit] Job '{job_id}' Event: {event_type} - {details}")

    def create_job(self, scan_id: str, sample_sha256: str, timeout_seconds: int = 300) -> SandboxJob:
        """Validates parameters and initializes new SandboxJob."""
        if not scan_id or not sample_sha256:
            raise ValueError("scan_id and sample_sha256 are required to create SandboxJob.")

        job_id = f"sb_job_{uuid.uuid4().hex[:12]}"
        job = SandboxJob(
            job_id=job_id,
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            provider="mock",
            status=SandboxJobStatus.CREATED,
            timeout_seconds=timeout_seconds
        )

        # Enforce security policy validations
        job.isolation_policy.validate_policy()
        job.network_policy.validate_policy()
        job.resource_policy.validate_policy()
        job.cleanup_policy.validate_policy()

        self._jobs[job_id] = job
        self._log_event(job_id, "JOB_CREATED", {"scan_id": scan_id, "sha256": sample_sha256})
        return job

    def execute_job_lifecycle(self, job_id: str) -> SandboxResult:
        """
        Executes complete sandbox lifecycle safely:
        CREATED -> QUEUED -> ENVIRONMENT_PREPARED -> READY -> RUNNING -> COLLECTING -> COMPLETED -> CLEANUP -> DESTROYED.
        Enforces cleanup guarantees on success, error, or timeout.
        """
        if job_id not in self._jobs:
            raise ValueError(f"Job ID '{job_id}' not found.")

        job = self._jobs[job_id]
        job.started_at = datetime.now(timezone.utc)
        job.status = SandboxJobStatus.QUEUED
        self._log_event(job_id, "JOB_QUEUED", {})

        artifacts: List[SandboxArtifact] = []
        error_msg: Optional[str] = None

        try:
            # 1. Allocate isolated environment
            env_id = self.provider.create_environment(job)
            job.environment_id = env_id
            job.status = SandboxJobStatus.ENVIRONMENT_PREPARED
            self._log_event(job_id, "ENVIRONMENT_PREPARED", {"environment_id": env_id})

            # 2. Transfer sample reference metadata
            self.provider.submit_sample(env_id, job.sample_sha256)
            job.status = SandboxJobStatus.READY
            self._log_event(job_id, "SAMPLE_REGISTERED", {"environment_id": env_id})

            # 3. Start analysis
            self.provider.start_analysis(env_id)
            job.status = SandboxJobStatus.RUNNING
            self._log_event(job_id, "ANALYSIS_STARTED", {"environment_id": env_id})

            # 4. Collect telemetry artifacts
            artifacts = self.provider.collect_artifacts(env_id)
            job.status = SandboxJobStatus.COLLECTING
            job.artifact_references = [art.storage_reference for art in artifacts]
            self._log_event(job_id, "ARTIFACTS_COLLECTED", {"count": len(artifacts)})

            # 5. Complete analysis phase
            job.status = SandboxJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            self._log_event(job_id, "ANALYSIS_COMPLETED", {})

        except Exception as e:
            error_msg = str(e)
            job.status = SandboxJobStatus.FAILED
            job.error = error_msg
            self._log_event(job_id, "ANALYSIS_FAILED", {"error": error_msg})

        finally:
            # Guaranteed cleanup execution path
            self._perform_guaranteed_cleanup(job)

        execution_duration = (
            (job.completed_at - job.started_at).total_seconds()
            if job.completed_at and job.started_at
            else 0.0
        )

        result = SandboxResult(
            job_id=job.job_id,
            scan_id=job.scan_id,
            sample_sha256=job.sample_sha256,
            provider=job.provider,
            status=job.status,
            cleanup_status=job.cleanup_status,
            started_at=job.started_at,
            completed_at=job.completed_at,
            execution_duration_seconds=execution_duration,
            artifacts=artifacts,
            artifact_count=len(artifacts),
            error=job.error,
            synthetic_disclosure="MockSandboxProvider used. Architecture foundation phase. Zero host PE execution."
        )

        return result

    def simulate_timeout(self, job_id: str) -> SandboxResult:
        """Simulates execution timeout and guarantees cleanup."""
        if job_id not in self._jobs:
            raise ValueError(f"Job ID '{job_id}' not found.")

        job = self._jobs[job_id]
        job.started_at = datetime.now(timezone.utc)
        job.status = SandboxJobStatus.TIMEOUT
        job.error = f"Execution timed out after exceeding resource limit of {job.timeout_seconds} seconds."
        self._log_event(job_id, "EXECUTION_TIMEOUT", {"timeout_seconds": job.timeout_seconds})

        # Perform mandatory cleanup after timeout
        self._perform_guaranteed_cleanup(job)

        job.completed_at = datetime.now(timezone.utc)

        return SandboxResult(
            job_id=job.job_id,
            scan_id=job.scan_id,
            sample_sha256=job.sample_sha256,
            provider=job.provider,
            status=SandboxJobStatus.TIMEOUT,
            cleanup_status=job.cleanup_status,
            started_at=job.started_at,
            completed_at=job.completed_at,
            execution_duration_seconds=float(job.timeout_seconds),
            artifacts=[],
            artifact_count=0,
            error=job.error,
            synthetic_disclosure="MockSandboxProvider timeout simulation. Zero host PE execution."
        )

    def _perform_guaranteed_cleanup(self, job: SandboxJob):
        """Enforces environment destruction and verifies cleanup status."""
        job.cleanup_status = CleanupStatus.IN_PROGRESS
        self._log_event(job.job_id, "CLEANUP_STARTED", {"environment_id": job.environment_id})

        if job.environment_id:
            try:
                self.provider.stop_analysis(job.environment_id)
                destroyed = self.provider.destroy_environment(job.environment_id)

                if destroyed:
                    job.cleanup_status = CleanupStatus.COMPLETED
                    self._log_event(job.job_id, "ENVIRONMENT_DESTROYED", {"status": "SUCCESS"})
                else:
                    job.cleanup_status = CleanupStatus.FAILED
                    self._log_event(job.job_id, "ENVIRONMENT_DESTROYED", {"status": "FAILED"})
            except Exception as e:
                job.cleanup_status = CleanupStatus.FAILED
                self._log_event(job.job_id, "CLEANUP_ERROR", {"error": str(e)})
        else:
            job.cleanup_status = CleanupStatus.COMPLETED
            self._log_event(job.job_id, "CLEANUP_SKIPPED", {"reason": "no_environment_allocated"})

    def reconcile_stale_jobs(self, max_stale_seconds: int = 600) -> int:
        """
        Watchdog reconciliation mechanism: Scans for active jobs exceeding max_stale_seconds
        and forces cleanup / destruction of stale environments.
        """
        reconciled_count = 0
        now = datetime.now(timezone.utc)

        for job_id, job in self._jobs.items():
            if job.status in (SandboxJobStatus.RUNNING, SandboxJobStatus.QUEUED, SandboxJobStatus.ENVIRONMENT_PREPARED):
                if job.started_at:
                    elapsed = (now - job.started_at).total_seconds()
                    if elapsed > max_stale_seconds:
                        logger.warning(f"[SandboxWatchdog] Stale job detected: '{job_id}' (elapsed={elapsed}s). Forcing cleanup.")
                        job.status = SandboxJobStatus.FAILED
                        job.error = f"Stale job reconciled by watchdog after {elapsed}s."
                        self._perform_guaranteed_cleanup(job)
                        reconciled_count += 1

        logger.info(f"[SandboxWatchdog] Reconciled {reconciled_count} stale sandbox jobs.")
        return reconciled_count

    def get_job(self, job_id: str) -> Optional[SandboxJob]:
        return self._jobs.get(job_id)

    def get_audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit_log)
