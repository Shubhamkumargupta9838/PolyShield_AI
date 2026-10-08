# PolyShield AI — Sandbox Architecture Specification (Phase 8)

## 1. Overview

This document specifies the architectural foundation for dynamic analysis in PolyShield AI. The architecture establishes a provider abstraction layer, declarative security policies, a state machine controller, artifact integrity models, and guaranteed cleanup workflows.

---

## 2. Dynamic Sandbox Architecture Diagram

```text
[ FastAPI Upload ] ──► [ LocalStorageService ] ──► [ MongoDB (Scan = QUEUED) ]
                                                            │
                                                            ▼
                                                     [ Celery Worker ]
                                                            │
                                                            ▼
                                                  [ Sandbox Controller ]
                                                            │
                                                            ▼
                                                [ ISandboxProvider Interface ]
                                                            │
                                             ┌──────────────┴──────────────┐
                                             ▼                             ▼
                                   [ MockSandboxProvider ]      [ Future Real VM Provider ]
                                   (Phase 8 Enabled)               (Future Phases)
                                             │                             │
                                             ▼                             ▼
                                     [ Synthetic Mock ]          [ Air-gapped VM Guest ]
```

---

## 3. Provider Abstraction Layer (`sandbox/interfaces/sandbox_provider.py`)

All sandbox implementations adhere to the `ISandboxProvider` abstract interface:

```python
class ISandboxProvider(ABC):
    @abstractmethod
    def create_environment(self, job: SandboxJob) -> str: ...
    @abstractmethod
    def submit_sample(self, environment_id: str, sample_sha256: str) -> bool: ...
    @abstractmethod
    def start_analysis(self, environment_id: str) -> bool: ...
    @abstractmethod
    def collect_artifacts(self, environment_id: str) -> List[SandboxArtifact]: ...
    @abstractmethod
    def stop_analysis(self, environment_id: str) -> bool: ...
    @abstractmethod
    def destroy_environment(self, environment_id: str) -> bool: ...
    @abstractmethod
    def get_status(self, environment_id: str) -> SandboxJobStatus: ...
```

---

## 4. Sandbox Job State Machine

```text
       CREATED
          │
          ▼
        QUEUED
          │
          ▼
ENVIRONMENT_PREPARED
          │
          ▼
        READY
          │
          ▼
       RUNNING ────────────────► TIMEOUT (Resource Limit Exceeded)
          │                         │
          ▼                         ▼
      COLLECTING                 CLEANUP
          │                         │
          ▼                         ▼
      COMPLETED                 DESTROYED
          │
          ▼
       CLEANUP
          │
          ▼
      DESTROYED
```

---

## 5. Declarative Security Policies

### A. Isolation Policy (`sandbox.security.IsolationPolicy`)
- `deny_host_filesystem = True`
- `deny_host_processes = True`
- `deny_docker_socket = True`
- `deny_shared_folders = True`
- `deny_shared_clipboard = True`
- `deny_usb_passthrough = True`
- `deny_secret_access = True`

### B. Resource Policy (`sandbox.security.ResourcePolicy`)
- `cpu_limit_cores = 2.0`
- `memory_limit_mb = 4096`
- `disk_limit_mb = 20480`
- `timeout_seconds = 300`
- `max_process_count = 100`
- `max_artifact_size_mb = 500`

### C. Network Policy (`sandbox.security.NetworkPolicy`)
- `internet_access = False`
- `network_mode = "isolated"`
- `dns_policy = "sinkhole"`
- `inbound_policy = "deny_all"`
- `outbound_policy = "deny_all"`

### D. Cleanup Policy (`sandbox.security.CleanupPolicy`)
- `auto_destroy_on_completion = True`
- `auto_destroy_on_failure = True`
- `auto_destroy_on_timeout = True`
- `verify_destruction = True`

---

## 7. Dynamic Telemetry & Feature Extraction (Phase 9)

Phase 9 introduces normalized dynamic telemetry ingestion and `dynamic-v1` feature extraction:

### Telemetry Normalizers (`sandbox/telemetry/`)
- `ProcessTelemetryParser`: Normalizes process tree creation, execution flags, and suspicious parent-child relations.
- `NetworkTelemetryParser`: Captures connection attempts, outbound IP/ports, and protocol details.
- `FilesystemTelemetryParser`: Tracks file creation, modifications, writes, and deletions in system directories.
- `RegistryTelemetryParser`: Identifies persistence key modifications (`Run`, `RunOnce`, Services).
- `ApiTelemetryParser`: Categorizes win32/NT system calls (injection, memory protection, thread creation).

### Canonical 14-Feature Dynamic Vector (`dynamic-v1`)
The `DynamicFeatureExtractor` compiles raw normalized events into a 14-dimensional float vector:
1. `process_count`
2. `child_process_count`
3. `network_connection_count`
4. `dns_query_count`
5. `blocked_network_attempt_count`
6. `filesystem_write_count`
7. `filesystem_delete_count`
8. `registry_write_count`
9. `api_event_count`
10. `injection_event_count`
11. `persistence_event_count`
12. `service_creation_count`
13. `suspicious_process_count`
14. `dropped_file_count`

### Environment Readiness & Fallback
- `VmSandboxProvider`: Validates local hypervisor availability (`virsh`, `VBoxManage`). If unavailable, returns `PROVIDER_UNAVAILABLE` status safely without crashing host operations.
- `SampleTransferService`: Enforces SHA-256 integrity check and size bounds prior to guest staging.

