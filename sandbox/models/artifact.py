from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    PROCESS_TRACE = "PROCESS_TRACE"
    NETWORK_PCAP = "NETWORK_PCAP"
    DNS_LOG = "DNS_LOG"
    FILESYSTEM_EVENT = "FILESYSTEM_EVENT"
    REGISTRY_EVENT = "REGISTRY_EVENT"
    MEMORY_METADATA = "MEMORY_METADATA"
    DROPPED_FILE_METADATA = "DROPPED_FILE_METADATA"
    SCREENSHOT = "SCREENSHOT"
    EXECUTION_LOG = "EXECUTION_LOG"


class SandboxArtifact(BaseModel):
    """
    Metadata representation of runtime telemetry artifact collected from isolated VM environment.
    All collected artifacts are treated as UNTRUSTED DATA and marked explicitly with SHA-256 identity.
    Raw execution of dropped binaries is strictly forbidden.
    """
    artifact_id: str
    job_id: str
    scan_id: str
    artifact_type: ArtifactType
    sha256: str = Field(..., description="SHA-256 cryptographic identity of the artifact byte stream")
    size_bytes: int = Field(..., ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "mock_environment"
    storage_reference: str
    is_executable: bool = Field(False, description="Flag marking if artifact is binary/executable file")
    metadata: Dict[str, Any] = Field(default_factory=dict)
