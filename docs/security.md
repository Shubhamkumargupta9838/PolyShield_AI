# Security Policy & Execution Boundary Controls

## 1. Absolute Host Execution Prohibition
No uploaded PE executable binary is ever executed on the host operating system. System commands (`subprocess`, `os.system`, shell, PowerShell, `CreateProcess`, Wine, or Windows loader) are strictly forbidden for submitted files.

## 2. Trusted vs. Untrusted Zone Isolation
- **Trusted Zone**: FastAPI API Server, MongoDB metadata persistence, Redis queue orchestrator, Celery task distribution, static PE feature extraction, static ML model inference, dynamic sequence LSTM inference, multimodal ensemble fusion, SHAP/Captum explainability engine.
- **Untrusted Zone**: Air-gapped Windows Virtual Machine sandbox (CAPE Sandbox). Executable binaries undergo execution ONLY inside disposable, revertible VM environments in future dynamic analysis phases.

## 3. Pure In-Memory PE Parsing
Static PE analysis is performed strictly in memory using `pefile`. The engine reads binary byte streams, checks magic bytes (`b"MZ"`), parses PE data structures, and never dynamically loads or imports analyzed binaries.

## 4. Static Indicators Limitation
Static indicators derived during PE extraction represent observed security features/evidence and are **NOT by themselves proof of maliciousness**.

## 5. Input Validation & Secure Upload Handling (Phase 6 & 13)
- Size check: Uploads exceeding `MAX_UPLOAD_SIZE_BYTES` (50 MB default) trigger HTTP 400 (`FILE_TOO_LARGE`).
- Empty file check: 0-byte uploads trigger HTTP 400 (`EMPTY_FILE`).
- Non-PE header check: Missing `MZ` magic header triggers HTTP 400 (`INVALID_PE_FILE`).
- Path Traversal Protection: Upload filenames are sanitized and never used to construct host file paths or shell commands. Safe-root path resolution (`relative_to`) is strictly enforced.
- Cryptographic Identity: SHA-256 is calculated directly from raw upload bytes (`SHA-256(raw_bytes)`). Filenames are ignored for identity.
- Internal stack traces are suppressed in API responses and recorded in structured server logs.

## 6. Synthetic Model Disclosure Boundary (Phase 6 & 11)
- The static ML model (`static_baseline_v2.0.joblib`) and dynamic LSTM model (`dynamic_lstm_v1.0.pt`) were trained using synthetic engineering fixtures.
- All API responses, analysis reports, and UI dashboards MUST preserve explicit synthetic model warnings disclosing that scores represent engineering baseline evaluation probabilities rather than calibrated real-world malware certainty.

## 7. Malware Dataset Handling & Isolation (Phase 5.5)
1. **Untrusted Sample Boundary**: All raw executable samples (`.exe`, `.dll`, `.sys`, `.scr`, `.ocx`) stored in `data/raw/` or `data/samples/` are treated strictly as untrusted binary byte data.
2. **Strict No-Execution Rule**: The dataset pipeline reads raw sample bytes directly via Python file handles and passes byte streams to `pefile`. Samples are never double-clicked, invoked, loaded as executable code, or passed to subprocess shell commands.
3. **Storage Isolation & Git Exclusion**: Raw malware binaries are strictly excluded from source control via `.gitignore` rules.
4. **Checksum Verification**: Every sample is assigned a cryptographic identity via SHA-256 (`SHA256(raw_bytes)`).
5. **Failure & Corrupt File Isolation**: Corrupt PE files or parsing errors fail gracefully by setting `analysis_status = "INVALID_PE"`.

## 8. Asynchronous Task & Storage Security (Phase 7 & 13)
1. **Zero Binary Data in Message Broker**: Raw PE binary contents MUST NEVER be passed as task payloads or arguments across Redis or Celery. Only safe, validated `scan_id` UUID strings pass through the broker.
2. **Path Traversal Shielding**: `LocalStorageService` enforces strict safe-root path traversal protection using `candidate.resolve().relative_to(allowed_root.resolve())`.
3. **Task Parameter Integrity**: Celery workers re-validate scan existence, ownership, state transitions, and artifact paths before executing background jobs.

## 9. Phase 13 Security Hardening & Threat Model (Categories A–V)

The following threat matrix documents all audited threat categories, attack surfaces, existing/new security controls, enforcement mechanisms, test locations, and accepted residual risks.

| Threat Category | Attack Surface | Existing Control | New Phase 13 Control | Enforcement | Test Module | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **A. Malicious Upload** | `POST /scans/analyze` | Extension check, MZ magic check | Hard 50MB request streaming limits, DOS header validation, null-byte rejection | `security.py`, `scans.py` | `test_upload_security.py` | Resource consumption during upload stream buffering |
| **B. Path Traversal** | Filesystem APIs, filenames, artifacts | Path string replacement | `candidate.resolve().relative_to(safe_root.resolve())` | `security.py`, `storage_service.py` | `test_path_traversal.py` | Path manipulation bugs in third-party libraries |
| **C. Request Abuse** | API endpoints | None | `slowapi` rate limiting on POST routes (e.g. 10 req/min for uploads, 30 req/min for auth) | `main.py`, `security_config.py` | `test_rate_limiting.py` | Distributed denial of service across multiple IPs |
| **D. Authentication Attacks** | API routes | None | Mandatory Bearer JWT auth, Argon2id/bcrypt password hashing, no plaintext passwords | `security.py`, `auth.py`, `dependencies.py` | `test_authentication.py` | Brute force user credential guessing (mitigated by rate limits) |
| **E. Authorization Bypass** | Protected endpoints | None | RBAC roles (`ANALYST`, `ADMIN`) via FastAPI dependency injection | `dependencies.py` | `test_authorization.py` | Misconfigured role scopes on future endpoints |
| **F. SSRF** | Outbound network clients | No user URL input allowed | Outbound URL fetching is not exposed (`SSRF attack surface: NOT EXPOSED`) | `security.py` | `test_ssrf.py` | Future URL fetching features if added without IP filtering |
| **G. Resource Exhaustion** | Uploads, telemetry, sequence length | Upload limit | Maximum string lengths, bounded event counts, max sequence length (100 tokens) | `Pydantic` models, `config.py` | `test_telemetry_validation.py` | Memory pressure from concurrent heavy analyses |
| **H. Artifact Access Abuse** | `/artifacts/{id}` | None | Opaque artifact references and scan ownership verification (`owner_id`) | `storage_service.py`, `scans.py` | `test_artifact_access.py` | Internal administrative storage access |
| **I. Celery/Task Abuse** | Redis task queue | Broker isolation | Worker task input re-validation (ownership, scan state, artifact paths) | `celery_tasks.py` | `test_celery_security.py` | Compromise of Redis message broker |
| **J. Redis Abuse** | Redis connection | Isolated Docker network | Password authentication, private network bound (not published publicly) | `docker-compose.yml`, `config.py` | `test_container_security.py` | Redis command injection if exposed |
| **K. MongoDB Injection** | Database queries | Motor parameterized driver | Typed Pydantic models, query operator rejection (`$gt`, `$ne`, `$where`, `$regex`) | `backend/app/db/` | `test_nosql_injection.py` | Operator injection via raw dictionary parameters |
| **L. NoSQL Injection** | API query params | Pydantic model parsing | Strict field filtering and strict Pydantic model validation | API schemas | `test_nosql_injection.py` | Complex unparsed dictionary parameters |
| **M. Secret Leakage** | Source code, logs, configs | `.env` gitignore | Strict startup config validation, `.env.example` placeholders only, log sanitization | `security_config.py`, `logging.py` | `test_secret_exposure.py` | Accidental inclusion of secrets in deployment environments |
| **N. Error Info Disclosure** | Exception responses | Global exception handler | Universal exception handlers suppress stack traces, returning stable error codes | `main.py`, `exceptions.py` | `test_secret_exposure.py` | Verbose third-party library error logs |
| **O. CORS Abuse** | Cross-origin requests | CORSMiddleware | Environment-configurable explicit `CORS_ORIGINS` (reject `*` with credentials) | `main.py`, `config.py` | `test_cors.py` | Subdomain takeover of allowed frontend origin |
| **P. Container Escape** | Docker containers | Unprivileged containers | Non-root container users, no host sockets, minimal cap drops | `Dockerfiles`, `docker-compose.yml` | `test_container_security.py` | Kernel vulnerabilities in container host OS |
| **Q. Sandbox Compromise** | Dynamic sandbox | Air-gapped guest VM | Strict provider allowlist (`mock`, `vm`), job state machine, mandatory snapshot revert | `sandbox/` | `test_container_security.py` | Zero-day hypervisor escape from guest VM to host |
| **R. Telemetry Poisoning** | Sandbox telemetry input | Telemetry normalizers | Telemetry schema bounds, relative timestamping, signal quality gating (`LOW_SIGNAL`) | `normalizers.py`, `ensemble_service.py` | `test_telemetry_validation.py` | Adversarial behavioral event sequences crafted to evade LSTM |
| **S. Model-Input Poisoning** | Inference endpoints | Feature bounds | Strict 17-feature static vector check, dynamic token vocabulary check, finite checks | `model_service.py`, `dynamic_inference.py` | `test_ml_input_validation.py` | Adversarial feature manipulation preserving PE functionality |
| **T. Log Injection** | Server logs | Standard logger | Sanitization of `\n`, `\r`, and ANSI escape characters in logged user metadata | `security.py`, `logging.py` | `test_secret_exposure.py` | Unsanitized log parsing tools downstream |
| **U. Dependency Vulns** | Third-party packages | Version pinning | Dependency vulnerability auditing via `pip-audit` and `npm audit` | `requirements.txt`, `package.json` | `test_container_security.py` | Unpatched transitive third-party vulnerabilities |
| **V. Denial of Service** | Web application | None | API rate limiting, body size limits, bounded worker concurrency | `main.py`, `security_config.py` | `test_rate_limiting.py` | Volumetric network layer DoS targeting web server |

---

## 10. Residual Risk Disclosure Statement
Phase 13 implements and verifies the documented application security controls. Residual risks remain deployment-specific, particularly around production infrastructure, TLS termination, virtualization hypervisor hardening, secrets management systems, and real sandbox guest VM deployment.
