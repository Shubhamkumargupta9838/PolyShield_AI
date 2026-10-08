# PolyShield AI — Phase 9 Completion Report: Dynamic Sandbox & Behavioral Telemetry

## Executive Summary

Phase 9 of **PolyShield AI** has been successfully completed. This phase establishes the first normalized dynamic-analysis and behavioral telemetry foundation for the platform. Building upon the Phase 8 sandbox isolation architecture, Phase 9 delivers typed event schema models, domain-specific telemetry parsers, a canonical 14-dimensional dynamic feature extractor (`dynamic-v1`), a hypervisor-safe provider (`VmSandboxProvider`), secure sample staging (`SampleTransferService`), FastAPI REST endpoints, Celery async background processing, Mongo/In-Memory persistence, and a React frontend telemetry dashboard.

Throughout Phase 9, the **STRICT SECURITY BOUNDARY** was strictly enforced: **ABSOLUTE ZERO HOST PE EXECUTION**. Untrusted binaries are treated exclusively as read-only byte streams.

---

## Key Achievements & Implementation Details

### 1. Telemetry Event & Dynamic Result Models (`sandbox/models/`)
- **Typed Event Models**: Created structured Pydantic event schemas in `sandbox/models/telemetry.py`:
  - `ProcessEvent`: Process creation, PID/PPID tree structure, command lines, image paths, integrity levels.
  - `NetworkEvent`: Source/destination IPs, ports, protocol, connection status, byte counts.
  - `DNSEvent`: Queried domain, query type, resolved IPs, sinkhole status.
  - `FilesystemEvent`: Action types (`CREATE`, `WRITE`, `DELETE`, `MODIFY`), target path, file size.
  - `RegistryEvent`: Registry operation (`SET_VALUE`, `DELETE_KEY`, etc.), key path, value name, value type.
  - `ApiEvent`: System call category (`INJECTION`, `MEMORY_PROTECTION`, `PROCESS_CREATION`, `THREAD_CREATION`, `SERVICE_MANIPULATION`, `PERSISTENCE`), API name, parameters.
- **Dynamic Analysis Result Model**: Created `DynamicAnalysisResult` (`sandbox/models/sandbox_result.py`) encapsulating `scan_id`, `provider_name`, `status`, event lists, normalized summaries, `execution_time_seconds`, and cryptographic SHA-256 telemetry identity.

### 2. Telemetry Normalization Pipeline (`sandbox/telemetry/`)
- **Relative Event Timestamps**: Calculated relative offsets (`relative_time_ms`) from execution start timestamp for deterministic temporal sequence alignment.
- **Domain Parsers**: Implemented modular parsers:
  - `ProcessTelemetryParser`: Extracts parent-child process relationships and identifies suspicious processes.
  - `NetworkTelemetryParser`: Aggregates active connections, DNS queries, and blocked outbound attempts.
  - `FilesystemTelemetryParser`: Tracks file creation, modifications, writes, and deletions.
  - `RegistryTelemetryParser`: Identifies persistence key modifications (`Run`, `RunOnce`, Services).
  - `ApiTelemetryParser`: Categorizes win32/NT API calls into security-relevant threat vectors.
- **Telemetry Hash Fingerprint**: `TelemetryNormalizer.compute_telemetry_hash()` generates a SHA-256 identity string over normalized telemetry data.

### 3. Canonical 14-Feature Dynamic Schema (`dynamic-v1`)
The `DynamicFeatureExtractor` (`analysis/features/dynamic_features.py`) compiles raw normalized events into a canonical 14-dimensional float vector:
1. `process_count`: Total spawned processes
2. `child_process_count`: Total child processes spawned
3. `network_connection_count`: Total network socket connections attempted
4. `dns_query_count`: Total DNS domain resolutions
5. `blocked_network_attempt_count`: Total network connections blocked by network policy
6. `filesystem_write_count`: Total file write operations
7. `filesystem_delete_count`: Total file deletion operations
8. `registry_write_count`: Total registry write/modifications
9. `api_event_count`: Total monitored API calls
10. `injection_event_count`: Process injection & memory manipulation API calls
11. `persistence_event_count`: Registry/startup persistence API calls
12. `service_creation_count`: System service creation API calls
13. `suspicious_process_count`: Spawned processes with suspicious indicators (cmd.exe, powershell.exe, wscript.exe, regsvr32.exe, etc.)
14. `dropped_file_count`: Total dropped files extracted during execution

### 4. Provider Architecture & Hypervisor Safety
- `VmSandboxProvider` (`sandbox/providers/vm_provider.py`): Checks host hypervisor availability (`virsh`, `VBoxManage`). When a real hypervisor is missing, returns `PROVIDER_UNAVAILABLE` status safely without crashing host operations.
- `MockSandboxProvider` (`sandbox/providers/mock_provider.py`): Retained as the default safe simulation provider for development, testing, and CI pipelines.

### 5. Secure Sample Transfer Service (`sandbox/services/sample_transfer.py`)
- Validates file existence and maximum file size bounds (50MB default).
- Computes SHA-256 hash before and after staging to verify byte integrity.
- Sanitizes file paths and enforces strict path traversal shielding (`..`, `/`, `\`).

### 6. Asynchronous Execution Infrastructure & REST API
- **Celery Async Task**: Implemented `run_dynamic_analysis_task` (`backend/app/workers/analysis_tasks.py`) executing dynamic sandbox analysis, event normalization, dynamic feature extraction, and report persistence in worker background thread pools.
- **FastAPI Router** (`backend/app/api/dynamic_analysis.py`): Registered in `backend/app/main.py`:
  - `POST /api/v1/scans/{scan_id}/dynamic-analysis`: Triggers async analysis, updates status to `QUEUED`, returns HTTP 202 Accepted.
  - `GET /api/v1/scans/{scan_id}/dynamic-analysis`: Returns completed `DynamicAnalysisResult` and telemetry summaries.
  - `GET /api/v1/scans/{scan_id}/dynamic-analysis/artifacts`: Returns list of collected telemetry artifacts.

### 7. Persistence & Scan Repository Layer
- Extended `BaseScanRepository` interface in `backend/app/repositories/scan_repository.py` with `save_dynamic_analysis` and `get_dynamic_analysis_by_scan_id`.
- Implemented persistent storage in `MongoScanRepository` (using Motor async driver) and transient testing storage in `InMemoryScanRepository`.

### 8. React Dashboard Integration
- Updated `frontend/src/services/api.js` with `triggerDynamicAnalysis`, `getDynamicAnalysis`, and `getDynamicAnalysisArtifacts`.
- Enhanced `DashboardOverview.jsx` with a **Dynamic Sandbox Analysis** action button, asynchronous status polling, and a telemetry metrics grid displaying process, network, filesystem, registry, and API counters along with raw telemetry event counts.

---

## Test Strategy & Verification Results

### Automated Pytest Suite
Ran full test suite across all application modules (`tests/backend`, `tests/analysis`, `tests/ml`, `tests/sandbox`):
```text
============================= 86 passed in 20.88s =============================
```
- **86 / 86 tests passed (100% pass rate)**.
- Includes API route tests, Celery worker eager mode execution, dynamic feature extraction validation, telemetry normalization, sample transfer verification, and execution boundary assertions.

### Frontend Production Build
Executed production Vite build:
```bash
npm --prefix frontend run build
```
```text
✓ 1473 modules transformed.
dist/index.html                   0.95 kB │ gzip:  0.54 kB
dist/assets/index-B9C0vzot.css   21.01 kB │ gzip:  4.64 kB
dist/assets/index-MyGo3EQ4.js   182.21 kB │ gzip: 54.91 kB
✓ built in 6.89s
```
- **Zero build errors or warning breaks**.

---

## Security Audit & Execution Boundary Assertions

- **Host Execution Check**: Conducted global codebase grep search for dangerous host execution patterns (`subprocess`, `Popen`, `os.system`, `exec`). Zero untrusted binary execution paths were identified.
- **Sanitizing & Transfer**: Sample transfer strictly validates SHA-256 digests before and after staging.
- **Provider Fallback Safety**: Missing hypervisors gracefully fall back to `PROVIDER_UNAVAILABLE` or `MockSandboxProvider` without executing code on host.

---

## Phase Status Matrix

| Phase Component | Status | Notes |
| :--- | :---: | :--- |
| **Telemetry Event Models** | ✅ Complete | `ProcessEvent`, `NetworkEvent`, `DNSEvent`, `FilesystemEvent`, `RegistryEvent`, `ApiEvent` |
| **Dynamic Analysis Result Schema** | ✅ Complete | `DynamicAnalysisResult` model with SHA-256 fingerprinting |
| **Telemetry Normalizers** | ✅ Complete | Modular parsers with relative timestamps (`relative_time_ms`) |
| **14-Feature Dynamic Schema (`dynamic-v1`)** | ✅ Complete | Deterministic vector extraction via `DynamicFeatureExtractor` |
| **Provider Architecture** | ✅ Complete | `VmSandboxProvider` with hypervisor checks & safe fallback |
| **Sample Transfer Service** | ✅ Complete | Cryptographic SHA-256 verification & path traversal protection |
| **FastAPI REST Router** | ✅ Complete | Endpoints registered under `/api/v1/scans/{id}/dynamic-analysis` |
| **Celery Background Worker Task** | ✅ Complete | `run_dynamic_analysis_task` with shared in-memory repo support |
| **Mongo & In-Memory Repositories** | ✅ Complete | Persistent storage of dynamic analysis reports |
| **React Dashboard Integration** | ✅ Complete | Interactive trigger button & telemetry metrics panel |
| **Pytest Test Suite** | ✅ Complete | 86/86 passed cleanly (100% pass rate) |
| **Frontend Production Build** | ✅ Complete | Clean Vite production build compilation |
| **Security Execution Boundary Audit** | ✅ Complete | Confirmed zero host PE execution paths |

---

## Scope Compliance & Next Phase Readiness

### Strict Boundary Adherence
- **NO LSTM model training or inference**: Explicitly excluded per Phase 9 specification.
- **NO Static + Dynamic Ensemble Model**: Preserved for future phase.
- **NO SHAP explainability calculations**: Preserved for future phase.
- **NO Internet-enabled malware detonation**: Network policy defaulted to `internet_access = False`.

Phase 9 is complete, fully verified, and ready for review.
