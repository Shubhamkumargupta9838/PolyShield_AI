# PolyShield AI — Technical Interview Preparation Guide

## 1. System Architecture & Engineering Questions

### Q1: Can you explain the overall architecture of PolyShield AI?
**Answer**: PolyShield AI is a containerized microservices platform. The frontend is built with React 18 and Vite, served via Nginx reverse proxy. The API tier runs FastAPI with 4 Uvicorn workers. Persistent data (scans, reports, XAI metadata) is stored in MongoDB 6.0, while Redis 7.0 acts as the Celery message broker and result cache. CPU-intensive static PE analysis, dynamic telemetry processing, ML inference, and XAI attribution run asynchronously in isolated Celery worker containers.

### Q2: Why use Celery with Redis instead of FastAPI BackgroundTasks?
**Answer**: FastAPI BackgroundTasks run inside the same Uvicorn process as the HTTP server. Heavy static analysis (`pefile`) or ML model evaluations (PyTorch/SHAP) would block the main event loop and degrade HTTP response latency. Celery isolates execution to dedicated worker containers with separate resource limits (2.0 CPU / 2048 MB RAM) and retry capabilities.

---

## 2. Security Engineering Questions

### Q3: How do you ensure untrusted malware samples do not infect the host?
**Answer**: We enforce a strict **Zero Host Execution Invariant**. Uploaded PE files operate purely as byte buffers or static file artifacts. The codebase strictly prohibits `subprocess`, `Popen`, `os.system`, or shell execution on sample files. All structural analysis uses in-memory byte parsing (`pefile`), and dynamic analysis is isolated behind a hypervisor-level VM provider boundary.

### Q4: How do you prevent Path Traversal and NoSQL Injection attacks?
**Answer**:
- **Path Traversal**: Candidate paths are validated against allowed root directories using safe-root path resolution (`validate_safe_path`). If a path attempts to escape via `../` or absolute symlinks, `PathTraversalException` is raised.
- **NoSQL Injection**: All input parameters pass through strict Pydantic v2 type validation schemas, preventing raw dictionary or operator injection into MongoDB queries.

---

## 3. Machine Learning & XAI Questions

### Q5: Why combine static features with a dynamic LSTM model?
**Answer**: Static analysis extracts structural indicators (header anomalies, RWX section flags, section entropy, API import distributions) in milliseconds without execution overhead, but can be evaded by obfuscation or packers. Dynamic analysis tracks runtime behavior (API call sequences, file/registry modifications) which remains invariant across polymorphic variants. Combining both modalities yields robust detection.

### Q6: What is the difference between SHAP attribution and causal evidence?
**Answer**: SHAP values measure the mathematical contribution of a feature toward shifting the model's output probability relative to a baseline explainer state. They do not constitute causal proof of maliciousness. PolyShield explicitly separates **Observed Evidence** (e.g., Section `.text` has RWX flags) from **Model Attribution** (SHAP value +0.28 toward Malware) in report visualizations.

---

## 4. Hard / Difficult Interview Questions

### Q7: Your dataset uses synthetic fixtures. Why should I trust your ML claims?
**Answer**: We do not make false claims about real-world accuracy. Synthetic fixtures are deliberately used for **engineering smoke validation** — proving that feature extraction pipelines, matrix conversions, PyTorch LSTM tensor operations, ensemble probability calculations, and XAI attribution engines operate reliably without runtime crashes. To make scientific claims about real-world detection accuracy, the platform must be benchmarked on verified real-world corpora like BODS or EMBER using group-aware family splits, which is documented as future research work.

### Q8: Is this system production-ready?
**Answer**:
- **Application Engineering & Security**: Production-ready with non-root containers, health probes, JWT RBAC, rate limiting, and 191/191 passed tests.
- **Runtime Deployment**: `RUNTIME_VERIFICATION_NOT_PERFORMED` because Docker CLI was unavailable in the local dev environment.
- **Real-World Detection**: Requires physical VM sandbox hardware and real-world benchmark datasets.
