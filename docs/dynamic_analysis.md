# PolyShield AI — Dynamic Analysis Architecture Specification (Phase 9)

## 1. Executive Summary

Phase 9 establishes the dynamic analysis foundation for PolyShield AI. This architecture provides an isolated, disposable sandbox environment for behavioral telemetry collection, event normalization, `dynamic-v1` feature extraction, and artifact integrity tracking.

---

## 2. Dynamic Pipeline Lifecycle

```text
[ PE Upload ] ──► [ SHA-256 Verification ] ──► [ LocalStorageService ]
                                                       │
                                                       ▼
                                            [ Dynamic Scan Request ]
                                                       │ (HTTP 202 Accepted)
                                                       ▼
                                             [ Celery Worker Task ]
                                                       │
                                                       ▼
                                            [ SampleTransferService ]
                                                       │
                                                       ▼
                                            [ Sandbox Controller ]
                                                       │
                                                       ▼
                                            [ Provider Abstraction ]
                                            (Mock / VmSandboxProvider)
                                                       │
                                                       ▼
                                            [ Telemetry Normalizer ]
                                                       │
                                                       ▼
                                           [ DynamicFeatureExtractor ]
                                           (Schema: dynamic-v1)
                                                       │
                                                       ▼
                                          [ Persisted MongoDB Record ]
```

---

## 3. Dynamic Feature Vector Schema (`dynamic-v1`)

The dynamic feature extraction module (`analysis/features/dynamic_features.py`) extracts a canonical 14-dimensional feature vector:

| Feature Name | Description | Data Type |
| :--- | :--- | :--- |
| `process_count` | Total processes created during execution | `float` |
| `child_process_count` | Count of spawned child processes | `float` |
| `network_connection_count` | Total network connection attempts | `float` |
| `dns_query_count` | Total DNS queries performed | `float` |
| `blocked_network_attempt_count` | Count of blocked network connection attempts | `float` |
| `filesystem_write_count` | Total file creation and modification operations | `float` |
| `filesystem_delete_count` | Total file deletion operations | `float` |
| `registry_write_count` | Total registry key/value writes | `float` |
| `api_event_count` | Total API trace calls captured | `float` |
| `injection_event_count` | Observed process injection API events | `float` |
| `persistence_event_count` | Observed registry/autostart persistence events | `float` |
| `service_creation_count` | Observed Windows service creation API calls | `float` |
| `suspicious_process_count` | Observed command execution tool invocations (cmd/powershell) | `float` |
| `dropped_file_count` | Total dropped executable/payload artifacts | `float` |

---

## 4. API Endpoints

- **POST `/api/v1/scans/{scan_id}/dynamic-analysis`**: Enqueues dynamic sandbox job asynchronously. Returns **HTTP 202 Accepted**.
- **GET `/api/v1/scans/{scan_id}/dynamic-analysis`**: Retrieves normalized dynamic telemetry summary and extracted `dynamic-v1` feature vector.
- **GET `/api/v1/scans/{scan_id}/dynamic-analysis/artifacts`**: Retrieves dynamic artifact metadata and storage references.
