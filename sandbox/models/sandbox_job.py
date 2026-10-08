from enum import Enum
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from sandbox.security.isolation_policy import IsolationPolicy
from sandbox.security.network_policy import NetworkPolicy
from sandbox.security.resource_policy import ResourcePolicy
from sandbox.security.cleanup_policy import CleanupPolicy


class SandboxJobStatus(str, Enum):
    CREATED = "CREATED"
    QUEUED = "QUEUED"
    ENVIRONMENT_PREPARED = "ENVIRONMENT_PREPARED"
    READY = "READY"
    RUNNING = "RUNNING"
    COLLECTING = "COLLECTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CLEANUP = "CLEANUP"
    DESTROYED = "DESTROYED"


class CleanupStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class SandboxJob(BaseModel):
    """
    Structured model representing a Sandbox Analysis Job lifecycle state.
    References untrusted samples ONLY via safe scan_id and SHA-256 identity.
    Raw PE bytes are NEVER stored or transmitted within job objects.
    """
    job_id: str
    scan_id: str
    sample_sha256: str
    provider: str = "mock"
    environment_id: Optional[str] = None
    status: SandboxJobStatus = SandboxJobStatus.CREATED
    cleanup_status: CleanupStatus = CleanupStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int = 300
    resource_policy: ResourcePolicy = Field(default_factory=ResourcePolicy)
    network_policy: NetworkPolicy = Field(default_factory=NetworkPolicy)
    isolation_policy: IsolationPolicy = Field(default_factory=IsolationPolicy)
    cleanup_policy: CleanupPolicy = Field(default_factory=CleanupPolicy)
    artifact_references: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
