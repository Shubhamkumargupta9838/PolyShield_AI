# PolyShield AI — Phase 10 Completion Report: Behavioral Sequence Dataset + LSTM Model

## Executive Summary

Phase 10 of **PolyShield AI** has been successfully completed. This phase implements the dynamic machine-learning layer of the platform, transforming normalized dynamic telemetry events into reproducible behavioral sequences and training/evaluating an LSTM-based sequence classifier (`dynamic_lstm_v1.0`).

Building upon the Phase 9 telemetry normalization engine, Phase 10 introduces typed behavioral sequence schemas, a deterministic event vocabulary (`dynamic_vocab_v1.json`), strict metadata leakage shielding, deduplication by SHA-256, a PyTorch LSTM sequence model (`DynamicLSTMModel`), validation-based threshold selection, safe evaluation metric calculation (`compute_dynamic_metrics`), FastAPI REST endpoints (`POST /api/v1/scans/{id}/dynamic-inference`), Celery async worker task (`run_dynamic_inference_task`), and React UI dashboard integration.

Throughout Phase 10, the **CRITICAL SCIENTIFIC & SECURITY BOUNDARIES** were strictly maintained:
- **Zero Host PE Execution**: Telemetry sequences are read-only JSON data; no untrusted binary was executed on the host server.
- **Scientific Disclosure**: The dataset uses synthetic PE engineering fixtures; metrics are explicitly marked as `ENGINEERING_SMOKE_EVALUATION` with `dataset_provenance_status = "SYNTHETIC_FIXTURE"` and `scientific_benchmark_ready = False`.

---

## Behavioral Sequence Architecture

1. **Sequence Representation** (`ml/data/dynamic_sequence_schema.py`):
   - `DynamicEventToken`: Captures `relative_time_ms`, `delta_time_ms`, `event_type`, `event_category`, `process_id`, and safe `metadata`.
   - `DynamicBehavioralSequence`: Encapsulates sequence events with `sample_sha256`, `label`, `family`, `group_id`, `dataset_version`, `sequence_schema_version`.

2. **Deterministic Vocabulary** (`ml/data/dynamic_vocab.py`):
   - Maps normalized event strings to integer IDs: `<PAD>` = 0, `<UNK>` = 1, and 26 canonical process, network, filesystem, registry, and API categories.
   - Normalizes event string variations (`ProcessCreate`, `PROCESS_CREATE`, `process_create`) to canonical uppercase tokens.
   - Tracks unknown events (`unknown_event_count`, `unknown_event_rate`). Exported to `dynamic_vocab_v1.json`.

3. **Dataset Builder & Sequence Encoding** (`ml/data/dynamic_dataset_builder.py`):
   - Encodes sequences into $X \in \mathbb{R}^{N \times 256}$ integer arrays and $y \in \{0, 1\}^N$.
   - Enforces SHA-256 deduplication and 70/15/15 group-aware or sample-level dataset splits.
   - Computes balanced class weights dynamically (`class_weight = {0: ..., 1: ...}`).
   - **Strict Metadata Shielding**: Identifiers (`sample_sha256`, `filename`, `scan_id`, `family`, `source`, `group_id`) are kept strictly separate from input feature matrix $X$.

---

## PyTorch LSTM Architecture & Model Artifacts

1. **Model Architecture** (`ml/models/lstm.py`):
   - `Embedding(num_embeddings=vocab_size, embedding_dim=64, padding_idx=0)`
   - `LSTM(input_size=64, hidden_size=64, batch_first=True)` with dynamic length packing
   - `Dropout(p=0.3)`
   - `Linear(64, 32)` + `ReLU`
   - `Linear(32, 1)` + `Sigmoid`

2. **Padding Masking Invariance**:
   - Verification suite (`tests/ml/test_dynamic_lstm.py`) proves that modifying trailing `<PAD>` tokens does not alter sequence prediction output.

3. **Training & Threshold Selection** (`ml/training/dynamic_training_pipeline.py`):
   - Adam optimizer, binary cross-entropy loss, early stopping on validation loss.
   - Threshold selected strictly from validation data (`threshold = 0.50`).

4. **Model Artifacts**:
   - Weights: `ml/artifacts/models/dynamic_lstm_v1.0.pt`
   - Metadata: `ml/artifacts/models/dynamic_lstm_v1.0.json`
   - Dataset Report: `ml/artifacts/dynamic_dataset_report_v1.0.json`
   - Training Report: `ml/artifacts/dynamic_training_report_v1.0.json`

---

## Backend & Frontend Integration

1. **Dynamic Model Service** (`backend/app/services/dynamic_model_service.py`):
   - Validates model version, dataset version, sequence schema, and vocabulary compatibility before running inference.

2. **REST API & Celery Task**:
   - `POST /api/v1/scans/{scan_id}/dynamic-inference`: Executes sequence inference on pre-collected telemetry.
   - `GET /api/v1/scans/{scan_id}/dynamic-inference`: Retrieves stored sequence prediction.
   - `run_dynamic_inference_task` in `backend/app/workers/analysis_tasks.py`.

3. **React Dashboard**:
   - Rendered **Dynamic Behavioral Model — PyTorch LSTM** panel displaying classification, P(malware) probability, sequence length, unknown event rate, and evaluation status disclosure banner (`ENGINEERING_SMOKE_EVALUATION`).

---

## Test & Verification Results

### Automated Pytest Suite
Ran full test suite across all modules (`tests/backend`, `tests/analysis`, `tests/ml`, `tests/sandbox`):
```text
============================= 97 passed in 38.73s =============================
```
- **97 / 97 tests passed (100% pass rate)**.
- Validates sequence schema, deterministic vocabulary, zero-padding masking invariance, training pipeline, API routers, and Celery tasks.

### Frontend Production Build
Executed production Vite build:
```bash
npm --prefix frontend run build
```
```text
✓ 1473 modules transformed.
dist/index.html                   0.95 kB │ gzip:  0.54 kB
dist/assets/index-6pO07Zqt.css   21.28 kB │ gzip:  4.69 kB
dist/assets/index-DQZutXzW.js   183.60 kB │ gzip: 55.04 kB
✓ built in 7.69s
```
- **Zero build errors or warning breaks**.

---

## Security Audit & Execution Boundary Assertions

- **Host Execution Search**: Grep search for `subprocess.Popen`, `subprocess.run`, `subprocess.call`, `os.system`, `os.popen`, `shell=True`. **Zero host execution paths found**.
- **Sample Boundary**: Unaltered raw binaries remain untrusted byte streams; the LSTM consumes telemetry JSON tokens only.

---

## Phase Status Matrix

| Phase Component | Status | Notes |
| :--- | :---: | :--- |
| **Behavioral Sequence Schema** | ✅ Complete | `DynamicEventToken` & `DynamicBehavioralSequence` |
| **Event Vocabulary** | ✅ Complete | Deterministic token mapping (`PAD=0`, `UNK=1`), `dynamic_vocab_v1.json` |
| **Dynamic Dataset Builder** | ✅ Complete | $X \in \mathbb{R}^{N \times 256}$ encoding, metadata shielding, deduplication, 70/15/15 splits |
| **PyTorch LSTM Model** | ✅ Complete | `DynamicLSTMModel` with zero-padding masking & reproducible seeds |
| **Dynamic Metrics** | ✅ Complete | `compute_dynamic_metrics` with safe single-class fallback |
| **Training Pipeline** | ✅ Complete | Early stopping, validation threshold selection, report generation |
| **Dynamic Model Service** | ✅ Complete | `DynamicModelService` with schema compatibility validation |
| **FastAPI REST Router** | ✅ Complete | `POST/GET /api/v1/scans/{id}/dynamic-inference` |
| **Celery Background Worker Task** | ✅ Complete | `run_dynamic_inference_task` |
| **React Dashboard Integration** | ✅ Complete | Dynamic LSTM Model prediction card & sequence metrics |
| **Pytest Test Suite** | ✅ Complete | 97/97 passed cleanly (100% pass rate) |
| **Frontend Production Build** | ✅ Complete | Clean Vite production build compilation |
| **Security Execution Boundary Audit** | ✅ Complete | Confirmed zero host PE execution paths |

---

## Limitations & Scope Compliance (Phase 11 Readiness)

Explicitly NOT implemented (preserved for future Phase 11):
- **Static + Dynamic Ensemble Model**: NOT IMPLEMENTED
- **SHAP Explainability**: NOT IMPLEMENTED
- **Automated Remediation**: NOT IMPLEMENTED

Phase 10 is complete, fully verified, and ready for review.
