# PolyShield AI

> **AI-Powered Polymorphic Malware Detection & Analysis Platform**

PolyShield AI is a security-engineered malware analysis platform combining static Portable Executable (PE) structural analysis, dynamic behavioral telemetry processing, machine learning (Random Forest, XGBoost, PyTorch LSTM), multimodal ensemble probability fusion, and Explainable AI (SHAP & Captum).

---

## 🌟 Key Features

- **Dual-Modality Analysis Engine**: Fuses static PE byte-stream properties (`static-v1` 17 canonical features) with dynamic event sequences (`dynamic-v1` 256-step execution sequences).
- **Multimodal Machine Learning**: Evaluates static classifiers (Random Forest / XGBoost) and a dynamic Recurrent Neural Network (PyTorch LSTM).
- **Explainable AI (XAI)**: Visualizes top static risk indicators via SHAP TreeExplainer and dynamic event step attributions via Captum LayerIntegratedGradients.
- **Strict Host Boundary Security**: Zero host sample execution policy, safe-root path resolution (`PathTraversalException`), JWT RBAC authentication, and NoSQL injection protection.
- **Containerized Infrastructure**: Multi-stage Docker packaging, non-root application containers (`polyshield` UID 10001), `cap_drop: ALL`, and internal bridge network isolation.
- **Comprehensive Verification**: 191 backend unit/integration tests passing, Vitest frontend tests passing, and 0 unmitigated security audit findings.

---

## 🏗 High-Level Architecture

```text
User / Analyst
      │
 [React UI] (Nginx Edge Proxy)
      │
[FastAPI API Server] (4 Uvicorn Workers)
      │
 ┌────┴────┐
 │         │
[MongoDB] [Redis] (Celery Message Broker)
           │
     [Celery Worker]
           │
 ┌─────────┼─────────┐
 │         │         │
[Static] [Dynamic] [ML & XAI]
```

---

## 🔒 Security Architecture & Boundaries

- **Zero Host Sample Execution**: Uploaded PE files operate strictly as raw in-memory byte buffers or static file artifacts. No `subprocess`, `Popen`, `os.system`, or shell execution is permitted on host.
- **Authentication & Authorization**: JWT tokens enforcing `exp`, `iat`, `iss`, `aud` claims. Alg `none` explicitly rejected. RBAC roles (`ANALYST`, `ADMIN`) and scan ownership assertions enforced.
- **Path Traversal Protection**: Candidate file paths validated against allowed roots via `validate_safe_path`.
- **Model Weight Security**: SHA-256 model checksum verification and PyTorch `torch.load(..., weights_only=True)` loading.

---

## 📊 Scientific Provenance & Limitations Disclosure

```text
dataset_provenance_status = SYNTHETIC_FIXTURE
scientifically_benchmark_ready = false
DOCKER_RUNTIME_VERIFICATION = NOT_PERFORMED (Docker CLI unavailable on local dev host)
```

> **Note**: PolyShield AI models are trained on safe synthetic PE fixtures for engineering smoke validation and pipeline verification. Real-world benchmark validity requires future evaluation on verified real-world malware corpora (e.g., BODS/EMBER).

---

## 🛠 Quick Start & Local Execution

### 1. Backend Server (FastAPI)
```powershell
.\.venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --reload --port 8000
```
- API Documentation: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/api/v1/health`

### 2. Celery Worker Service
```powershell
.\.venv\Scripts\Activate.ps1
celery -A backend.app.workers.celery_app worker --loglevel=INFO
```

### 3. Frontend Dashboard (React + Vite)
```bash
cd frontend
npm run dev
```

### 4. Running Verification Test Suite
```powershell
.\.venv\Scripts\pytest.exe tests/backend tests/analysis tests/ml tests/sandbox tests/security tests/integration tests/performance tests/e2e
npm --prefix frontend run test
python scripts/security_audit.py
```

---

## 📚 Complete Documentation Index

For detailed architectural, security, ML, deployment, and placement preparation documentation, refer to [`docs/README.md`](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/README.md):

- 📐 [Final System Architecture](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/final_architecture.md)
- 🔄 [Data Flow Architecture](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/data_flow.md)
- 🛡 [Security Architecture & Controls Matrix](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/security_architecture.md)
- 🎯 [Final Threat Model & Risk Analysis](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/final_threat_model.md)
- 🧠 [Machine Learning Methodology](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/final_ml_methodology.md)
- 🧪 [Dataset Provenance & Methodology](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/final_dataset_methodology.md)
- 🔍 [Explainable AI (SHAP & Captum)](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/explainability.md)
- 🎬 [3-Minute Demonstration Script](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/demo_script.md)
- ❓ [Technical Interview Preparation Guide](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/interview_questions.md)
- 📄 [Resume & Portfolio Descriptions](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/resume_project_description.md)
- 📈 [Project Scorecard](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/project_scorecard.md)
