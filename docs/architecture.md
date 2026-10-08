# PolyShield AI Architecture & Analysis Pipeline Specification

PolyShield AI is an enterprise-grade cybersecurity and machine learning platform built to detect and analyze **polymorphic malware** targeting Windows Portable Executable (PE) binaries.

---

# 1. System Architecture Overview

```text
                          TRUSTED ZONE
+---------------------------------------------------------------+
|                                                               |
|  [ React Dashboard ] <---> [ FastAPI REST API ]              |
|                                |               \              |
|                                v                v             |
|                           [ MongoDB ]       [ Redis ]         |
|                                                 |             |
|                                                 v             |
|                                           [ Celery Worker ]   |
|                                                 |             |
+-------------------------------------------------|-------------+
                                                  |
                                                  v
                                          UNTRUSTED ZONE
                                +----------------------------------+
                                |  [ Sandbox Isolation Layer ]     |
                                |       |                          |
                                |       v                          |
                                |  [ Windows VM Sandbox (CAPE) ]   |
                                |       |                          |
                                |       v                          |
                                |  [ Behavioral Artifact Logger ]  |
                                +----------------------------------+
```

---

# 2. Static PE Analysis Engine & ML Inference (Phase 6)

The Static Analysis & ML Inference Engine operates purely in-memory in the **Trusted Zone** without invoking shell execution, subprocesses, or binary execution.

```text
[ Uploaded PE File ] ──► [ Upload Validation & SHA-256 ] ──► [ In-Memory pefile Parsing ]
                                                                      │
        ┌───────────────────┬───────────────────┬─────────────────────┼──────────────────┐
        ▼                   ▼                   ▼                     ▼                  ▼
 [ PE Headers ]     [ Section Analysis ] [ Import Telemetry ] [ Resource Metadata ] [ Shannon Entropy ]
        │                   │                   │                     │                  │
        └───────────────────┴───────────────────┼─────────────────────┴──────────────────┘
                                                ▼
                                    [ Static Indicator Engine ]
                                                │
                                                ▼
                                   [ 17 Static-v1 Features ]
                                                │
                                                ▼
                                  [ Model Service (joblib) ]
                                                │
                                                ▼
                                [ P(malware) & P(benign) Score ]
                                                │
                                                ▼
                                 [ Risk Assessment (LOW-CRITICAL) ]
                                                │
                                                ▼
                                [ Analysis Report & Persistence ]
```

---

# 3. Shannon Entropy Methodology

Entropy is calculated per byte sequence using Shannon's formula:

$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

- **Output Range**: $0.0000 \rightarrow 8.0000$
- **Interpretation**: Values $\ge 7.0000$ indicate high randomness (e.g. packed code, encrypted sections, or compressed resources).
- **Stat Aggregation**: Calculates min, max, mean, and count of high-entropy sections per binary.

---

# 4. Deterministic Risk Assessment Layer

The risk assessment layer maps model output probability $P(\text{malware})$ to risk categories using a deterministic rule separate from binary classification:

| $P(\text{malware})$ Range | Risk Category | Interpretation |
| :--- | :--- | :--- |
| $0.00 - 0.24$ | `LOW` | Minimal security concern observed |
| $0.25 - 0.49$ | `MEDIUM` | Moderate static anomaly or indicator presence |
| $0.50 - 0.74$ | `HIGH` | High probability of malicious characteristics |
| $0.75 - 1.00$ | `CRITICAL` | Severe malware probability based on static baseline |

---

# 5. Static Feature Vector (ML Schema)

The static analysis pipeline converts raw PE attributes into a deterministic 17-dimensional numeric dictionary for ML classifiers:

```json
{
  "file_size": 102400.0,
  "number_of_sections": 1.0,
  "dll_count": 5.0,
  "api_count": 42.0,
  "max_section_entropy": 6.4521,
  "min_section_entropy": 2.1104,
  "mean_section_entropy": 4.8210,
  "high_entropy_section_count": 0.0,
  "executable_section_count": 1.0,
  "writable_section_count": 1.0,
  "rwx_section_count": 0.0,
  "unusual_section_count": 0.0,
  "resource_count": 3.0,
  "suspicious_api_count": 2.0,
  "static_indicator_count": 1.0,
  "is_dll": 0.0,
  "is_driver": 0.0
}
```

---

# 6. API Endpoints

### POST `/api/v1/scans/{scan_id}/analyze` (Phase 7 Asynchronous Non-Blocking Upload)
- **Request**: Multipart file upload (`file: UploadFile`).
- **Operation**: Performs upload validation, saves PE binary sample safely to `LocalStorageService` (`data/storage/<scan_id>/input`), updates scan status to `QUEUED`, enqueues Celery background task passing ONLY `scan_id` string over Redis, and returns immediately.
- **Response**: HTTP 202 Accepted with `ScanResponse` JSON (`status: "QUEUED"`).

### GET `/api/v1/scans/{scan_id}`
- **Request**: Path param `scan_id`.
- **Operation**: Polls scan lifecycle status (`QUEUED` $\rightarrow$ `STATIC_ANALYSIS` $\rightarrow$ `ML_INFERENCE` $\rightarrow$ `REPORT_GENERATION` $\rightarrow$ `COMPLETED` / `FAILED`).
- **Response**: `ScanResponse` JSON.

### GET `/api/v1/scans/{scan_id}/report`
- **Request**: Path param `scan_id`.
- **Operation**: Retrieves persisted analysis report including static evidence, ML scores, risk category, and synthetic model disclosures once scan state is `COMPLETED`.
- **Response**: `AnalysisReportResponse` JSON.

---

# 7. Asynchronous Analysis Infrastructure (Phase 7)

```text
[ React Dashboard ]
       │
       │ 1. POST /api/v1/scans/{scan_id}/analyze (Binary Upload)
       ▼
[ FastAPI Server ] ────► [ LocalStorageService ] (data/storage/<scan_id>/input)
       │
       │ 2. Set Scan Status = QUEUED in MongoDB
       │ 3. analyze_scan_task.delay(scan_id)
       ▼
  [ Redis Broker ]
       │
       │ 4. Pop Task (scan_id)
       ▼
[ Celery Worker Process ]
       │
       ├──► 5. Update Status: STATIC_ANALYSIS
       ├──► 6. Execute Static PE Extraction & Vectorization
       ├──► 7. Update Status: ML_INFERENCE
       ├──► 8. Model Prediction (RandomForest / XGBoost)
       ├──► 9. Risk Assessment Calculation
       ├──► 10. Update Status: REPORT_GENERATION
       ├──► 11. Persist Analysis Report to MongoDB
       └──► 12. Update Status: COMPLETED
```

### Key Infrastructure Principles
1. **Zero Binary Payload in Redis**: Only safe, sanitized `scan_id` UUID strings pass through the Redis message broker. PE bytes reside strictly in `LocalStorageService` isolated storage.
2. **MongoDB Single Source of Truth**: Scan state transitions and analysis reports are persisted in MongoDB.
3. **Idempotency & Retries**: Re-analyzing completed scans returns cached results without duplicate processing. Failed tasks retry up to 3 times with exponential backoff before transitioning state to `FAILED`.
4. **React Polling Lifecycle**: Frontend polls `GET /api/v1/scans/{scan_id}` every 2.5s while scan status is pending, switching seamlessly to fetch `/report` upon completion.

---

# 8. Sandbox Architecture & Provider Abstraction (Phase 8)

Phase 8 defines the provider abstraction layer (`ISandboxProvider`), security isolation policies, resource caps, network containment, sandbox job state machine, and artifact integrity specifications for future dynamic analysis.

```text
[ Sandbox Controller ] ──► [ ISandboxProvider Interface ]
                                    │
                     ┌──────────────┴──────────────┐
                     ▼                             ▼
           [ MockSandboxProvider ]      [ Future Real VM Provider ]
           (Phase 8 Active)                (Future Phases)
                     │                             │
                     ▼                             ▼
             (Mock Simulation)            (Disposable Guest VM)
```

- **Default Provider**: `MockSandboxProvider` (Zero host PE execution).
- **Default Network Containment**: `internet_access = False`, `network_mode = "isolated"`, sinkhole DNS.
- **Cleanup Guarantee**: Mandatory snapshot revert / environment destruction on completion, failure, timeout, or crash.

---

# 9. Dynamic Sandbox & Telemetry Pipeline (Phase 9)

```text
[ React Dashboard ]
       │
       │ 1. POST /api/v1/scans/{scan_id}/dynamic-analysis (HTTP 202 Accepted)
       ▼
[ FastAPI Router ]
       │
       │ 2. run_dynamic_analysis_task.delay(scan_id)
       ▼
  [ Redis Broker ]
       │
       │ 3. Celery Worker (run_dynamic_analysis_task)
       ▼
[ Sandbox Controller ]
       │
       ├──► 4. Check Provider (VmSandboxProvider / MockSandboxProvider)
       ├──► 5. Stage Sample via SampleTransferService (SHA-256 verification)
       ├──► 6. Execute Sandbox Session & Collect Telemetry Logs
       ├──► 7. Telemetry Normalizers (Process, Network, Filesystem, Registry, API)
       ├──► 8. Dynamic Feature Extractor -> 14-Dim Vector (dynamic-v1)
       └──► 9. Persist Dynamic Analysis Result to Mongo / In-Memory Repo
```

### Dynamic Feature Schema (`dynamic-v1`)
Extracts 14 numeric features: `process_count`, `child_process_count`, `network_connection_count`, `dns_query_count`, `blocked_network_attempt_count`, `filesystem_write_count`, `filesystem_delete_count`, `registry_write_count`, `api_event_count`, `injection_event_count`, `persistence_event_count`, `service_creation_count`, `suspicious_process_count`, `dropped_file_count`.

---

# 10. Multimodal Static + Dynamic Ensemble Engine (Phase 11)

```text
[ React Dashboard ] ──► POST /api/v1/scans/{scan_id}/ensemble-inference
                                │
                                ▼
                     [ EnsembleService ]
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
[ Static Report (malware_score) ]   [ Dynamic LSTM Inference (P_malware) ]
             │                                     │
             └──────────────────┬──────────────────┘
                                ▼
                  [ MultimodalEnsembleModel ]
                     P_ens = 0.5*Ps + 0.5*Pd
                                │
                                ▼
                   [ Risk Level & Persistence ]
                                │
                                ▼
                     [ React Dashboard UI ]
```

### Key Integration Points
1. **API Endpoints**: `POST /api/v1/scans/{scan_id}/ensemble-inference` and `GET /api/v1/scans/{scan_id}/ensemble-inference`.
2. **Missing Modality Gating**: Dynamically switches operational modes (`BOTH_MODALITIES`, `STATIC_ONLY`, `DYNAMIC_ONLY`).
3. **Telemetry Quality Gating**: Evaluates telemetry trace signal quality (`VALID`, `LOW_SIGNAL`, `INVALID`, `UNAVAILABLE`).
4. **Persistence Layer**: Saved to Mongo `ensemble_inference_results` collection or `InMemoryScanRepository`.

---

# 7. Explainable AI & Attribution Pipeline (Phase 12)

Phase 12 integrates model explainability (`explanation_v1.0`) across all modalities:

```text
Static Feature Vector ──► StaticSHAPExplainer (TreeExplainer) ────► StaticAttributions (top-k)
                                                                            │
Dynamic Telemetry ─────► DynamicSequenceExplainer (Captum IG) ──► DynamicAttributions (top-k)
                                                                            │
Ensemble Output ───────► EnsembleExplainer (Component Fusion) ─► ComponentContributions (w*P)
                                                                            │
                                                                            v
                                                                [ ExplanationResult JSON ]
```

### Key Integration Points
1. **API Endpoints**: `POST /api/v1/scans/{scan_id}/explanation` and `GET /api/v1/scans/{scan_id}/explanation`.
2. **Celery Worker Task**: `run_explanation_task(scan_id)` enqueued for asynchronous worker execution.
3. **Observed vs Attribution Distinction**: Measured metrics (raw facts) are strictly separated from SHAP / Captum feature weights.
4. **Persistence Layer**: Saved to Mongo `explanation_results` collection or `InMemoryScanRepository` and serialized to `ml/artifacts/explanations/explanation_v1.0.json`.


