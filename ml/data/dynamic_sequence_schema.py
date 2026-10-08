"""Behavioral Sequence Schema for Dynamic Analysis Telemetry (Phase 10).

Defines the canonical sequence representation converting normalized telemetry events
into structured, model-ready sequence objects.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


DYNAMIC_SEQUENCE_SCHEMA_VERSION = "1.0.0"


class DynamicEventToken(BaseModel):
    """Canonical single behavioral event within a sequence."""

    relative_time_ms: int = Field(..., ge=0, description="Milliseconds since analysis start")
    delta_time_ms: int = Field(0, ge=0, description="Milliseconds since previous event in sequence")
    event_type: str = Field(..., description="Canonical event string e.g. PROCESS_CREATE, NETWORK_CONNECT")
    event_category: str = Field(..., description="Event domain e.g. process, network, filesystem, registry, api")
    process_id: Optional[int] = Field(None, description="Monitored process ID associated with event")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Safe metadata context (NOT model inputs)")


class DynamicBehavioralSequence(BaseModel):
    """Complete behavioral sequence container for a single PE sample/scan."""

    sample_id: Optional[str] = Field(None, description="Sample identifier")
    scan_id: Optional[str] = Field(None, description="Scan UUID")
    sample_sha256: str = Field(..., description="SHA-256 cryptographic identity of sample")
    label: int = Field(0, ge=0, le=1, description="Binary classification label (0=benign, 1=malware)")
    family: Optional[str] = Field("unknown", description="Malware family metadata if available")
    group_id: Optional[str] = Field(None, description="Group ID for group-aware splitting")
    dataset_version: str = Field("dynamic-v1.0", description="Dataset schema version")
    sequence_schema_version: str = Field(DYNAMIC_SEQUENCE_SCHEMA_VERSION, description="Sequence schema version")
    events: List[DynamicEventToken] = Field(default_factory=list, description="Ordered list of event tokens")

    def to_dict(self) -> Dict[str, Any]:
        """Convert sequence object to dictionary."""
        return self.model_dump()
