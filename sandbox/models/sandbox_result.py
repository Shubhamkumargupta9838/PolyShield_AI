from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from sandbox.models.sandbox_job import SandboxJobStatus, CleanupStatus
from sandbox.models.artifact import SandboxArtifact
from sandbox.models.telemetry import (
    ProcessEvent,
    NetworkEvent,
    DNSEvent,
    FilesystemEvent,
    RegistryEvent,
    ApiEvent,
)


class SandboxResult(BaseModel):
    """
    Result model for Sandbox Analysis Job execution.
    Contains collected untrusted artifact references, status metrics, and disclosures.
    """
    job_id: str
    scan_id: str
    sample_sha256: str
    provider: str
    status: SandboxJobStatus
    cleanup_status: CleanupStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    execution_duration_seconds: float = 0.0
    artifacts: List[SandboxArtifact] = Field(default_factory=list)
    artifact_count: int = 0
    error: Optional[str] = None
    synthetic_disclosure: str = "Mock sandbox provider used. Zero host PE execution performed."


class DynamicAnalysisResult(BaseModel):
    """
    Normalized result model summarizing all dynamic behavioral telemetry events,
    execution metrics, and artifact references produced by an isolated sandbox analysis job.
    Directly consumed by Phase 9 feature extraction and Phase 10 sequence models.
    """
    job_id: str
    scan_id: str
    sample_sha256: str
    provider: str
    environment_id: Optional[str] = None
    status: SandboxJobStatus = SandboxJobStatus.COMPLETED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0

    process_events: List[ProcessEvent] = Field(default_factory=list)
    network_events: List[NetworkEvent] = Field(default_factory=list)
    dns_events: List[DNSEvent] = Field(default_factory=list)
    filesystem_events: List[FilesystemEvent] = Field(default_factory=list)
    registry_events: List[RegistryEvent] = Field(default_factory=list)
    api_events: List[ApiEvent] = Field(default_factory=list)

    artifacts: List[SandboxArtifact] = Field(default_factory=list)
    artifact_references: List[str] = Field(default_factory=list)
    telemetry_sha256: Optional[str] = None
    error: Optional[str] = None
