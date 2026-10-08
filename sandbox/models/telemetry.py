from enum import Enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class ProcessEventType(str, Enum):
    PROCESS_CREATE = "PROCESS_CREATE"
    PROCESS_EXIT = "PROCESS_EXIT"
    PROCESS_INJECT = "PROCESS_INJECT"
    PROCESS_TERMINATE = "PROCESS_TERMINATE"


class ProcessEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0, description="Milliseconds elapsed since analysis start")
    pid: int = Field(..., ge=0)
    parent_pid: Optional[int] = Field(None, ge=0)
    image_name: str
    command_line: Optional[str] = None
    event_type: ProcessEventType
    exit_code: Optional[int] = None
    integrity_level: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkAction(str, Enum):
    CONNECT = "CONNECT"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    BLOCKED = "BLOCKED"


class NetworkEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0)
    protocol: str = "TCP"  # TCP, UDP, ICMP, HTTP, HTTPS
    direction: str = "outbound"  # inbound, outbound
    src_ip: Optional[str] = "192.168.56.10"
    src_port: Optional[int] = 49152
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    bytes_sent: int = Field(0, ge=0)
    bytes_received: int = Field(0, ge=0)
    action: NetworkAction = NetworkAction.BLOCKED
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DNSEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0)
    query: str
    record_type: str = "A"
    response: Optional[str] = None
    action: str = "sinkholed"  # sinkholed, resolved, blocked
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FilesystemOperation(str, Enum):
    CREATE = "CREATE"
    WRITE = "WRITE"
    READ = "READ"
    DELETE = "DELETE"
    RENAME = "RENAME"


class FilesystemEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0)
    operation: FilesystemOperation
    path: str
    process_id: Optional[int] = None
    result: str = "SUCCESS"
    sha256: Optional[str] = None
    size: Optional[int] = Field(None, ge=0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RegistryOperation(str, Enum):
    CREATE_KEY = "CREATE_KEY"
    SET_VALUE = "SET_VALUE"
    DELETE_KEY = "DELETE_KEY"
    OPEN_KEY = "OPEN_KEY"


class RegistryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0)
    operation: RegistryOperation
    key: str
    value_name: Optional[str] = None
    value_type: Optional[str] = None
    process_id: Optional[int] = None
    result: str = "SUCCESS"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApiCategory(str, Enum):
    PROCESS = "PROCESS"
    MEMORY = "MEMORY"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    NETWORK = "NETWORK"
    CRYPTO = "CRYPTO"
    SERVICE = "SERVICE"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE = "PRIVILEGE"
    INJECTION = "INJECTION"


class ApiEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    relative_time_ms: int = Field(..., ge=0)
    process_id: int
    module: str
    api_name: str
    category: ApiCategory
    arguments_hash: Optional[str] = None
    result: str = "SUCCESS"
    metadata: Dict[str, Any] = Field(default_factory=dict)
