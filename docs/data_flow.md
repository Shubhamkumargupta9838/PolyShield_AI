# PolyShield AI — Data Flow Architecture

## 1. End-to-End Data Pipeline

```text
PE Upload
   ↓
Header & Size Validation (Max 50MB)
   ↓
SHA-256 Checksum Generation
   ↓
Safe Storage (Storage Path Validation)
   ↓
Scan Record Created (MongoDB: Status QUEUED)
   ↓
Task Enqueued (Redis Broker)
   ↓
Celery Worker Dequeue
   ↓
 ┌───────────────────────────┴───────────────────────────┐
 │                                                       │
Static PE Analysis                               Dynamic Telemetry Normalization
 │                                                       │
17 Canonical Features (static-v1)               14 Features + Sequence (len <= 256)
 │                                                       │
Random Forest / XGBoost Inference               PyTorch LSTM Inference
 ($P_{static}$)                                          ($P_{dynamic}$)
 └───────────────────────────┬───────────────────────────┘
                             ↓
              Multimodal Ensemble Fusion
          $P_{ensemble} = 0.5 P_s + 0.5 P_d$
                             ↓
            Risk Band Mapping (LOW..CRITICAL)
                             ↓
          Explainable AI (SHAP & Captum)
                             ↓
           Report Persisted to MongoDB
```

---

## 2. Step-by-Step Processing Steps

1. **Upload Phase**: Analyst submits a PE sample via `POST /api/v1/scans`. FastAPI validates file extension, null bytes, and 50MB size limit, then computes SHA-256 checksum.
2. **Persistence Phase**: Scan record is stored in MongoDB with status `QUEUED`. Job ID is pushed to Redis broker.
3. **Static Analysis**: Celery worker parses PE headers, sections, imports, exports, and calculates section entropy (min, max, mean, RWX count, high-entropy section count).
4. **Dynamic Normalization**: Execution event logs are normalized to standard schema (`dynamic-v1`), and indexed into a 256-step integer event sequence with zero-padding.
5. **ML Inference**:
   - `P_static` computed by Random Forest / XGBoost model on 17 static features.
   - `P_dynamic` computed by PyTorch LSTM model on 256-step event sequence.
   - `P_ensemble = 0.5 * P_static + 0.5 * P_dynamic`.
6. **XAI Computation**:
   - Static TreeExplainer computes SHAP feature attributions.
   - Dynamic LayerIntegratedGradients computes sequence event attributions.
7. **Report Persistence**: Combined results, risk band, evidence breakdown, and XAI plots are saved to MongoDB, updating status to `COMPLETED`.
