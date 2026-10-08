# PolyShield AI Security Controls Matrix

| Control Category | Control Name | Status | Evidence Location | Test Verification Module |
| :--- | :--- | :--- | :--- | :--- |
| **Authentication** | Bearer JWT (HS256) Token Issuance & Verification | `VERIFIED` | `backend/app/core/security.py`, `backend/app/api/auth.py` | `tests/security/test_authentication.py` |
| **Authentication** | Rejection of `alg = none` and Expired Tokens | `VERIFIED` | `backend/app/core/security.py` | `tests/security/test_authentication.py` |
| **Authentication** | Password Hashing (PBKDF2-HMAC-SHA256) | `VERIFIED` | `backend/app/core/security.py` | `tests/security/test_authentication.py` |
| **Authorization** | RBAC (`ANALYST`, `ADMIN`) Role Dependencies | `VERIFIED` | `backend/app/api/dependencies.py` | `tests/security/test_authorization.py` |
| **Authorization** | Multi-Tenant `owner_id` IDOR Shielding | `VERIFIED` | `backend/app/api/dependencies.py`, `backend/app/api/scans.py` | `tests/security/test_authorization.py` |
| **Upload Security** | Hard Upload Size Limits (50MB) | `VERIFIED` | `backend/app/services/scan_service.py` | `tests/security/test_upload_security.py` |
| **Upload Security** | Extension & MZ Magic Byte Header Checks | `VERIFIED` | `backend/app/core/security.py` | `tests/security/test_upload_security.py` |
| **Path Traversal** | Safe-Root Resolution (`relative_to`) | `VERIFIED` | `backend/app/core/security.py`, `backend/app/services/storage_service.py` | `tests/security/test_path_traversal.py` |
| **Artifact Security**| Opaque References & Ownership Verification | `VERIFIED` | `backend/app/services/storage_service.py`, `backend/app/api/dynamic_analysis.py` | `tests/security/test_artifact_access.py` |
| **SSRF** | Outbound Network Fetching Attack Surface Assessment | `VERIFIED` | Architecture & API router inspection (`NOT EXPOSED`) | `tests/security/test_ssrf.py` |
| **NoSQL Injection**| Pydantic Strict Bounds & Operator Rejection | `VERIFIED` | `backend/app/schemas/` models | `tests/security/test_nosql_injection.py` |
| **Celery Security** | Worker Task Parameter Security Re-validation | `VERIFIED` | `backend/app/workers/analysis_tasks.py` | `tests/security/test_celery_security.py` |
| **Rate Limiting** | API Rate Limits (`slowapi`) | `VERIFIED` | `backend/app/main.py`, `backend/app/core/security_config.py` | `tests/security/test_rate_limiting.py` |
| **Security Headers**| `X-Content-Type-Options`, `X-Frame-Options`, `CSP` | `VERIFIED` | `backend/app/main.py` | `tests/security/test_security_headers.py` |
| **CORS** | Configured Allowed Origins (No `*` with credentials) | `VERIFIED` | `backend/app/main.py`, `backend/app/core/config.py` | `tests/security/test_cors.py` |
| **ML Security** | Model Checksum Verification (SHA-256) | `VERIFIED` | `backend/app/services/model_service.py` | `tests/security/test_model_integrity.py` |
| **ML Security** | Safe Model Load (Registry Path Boundary) | `VERIFIED` | `backend/app/services/model_service.py` | `tests/security/test_pickle_security.py` |
| **ML Security** | PyTorch `weights_only=True` Loading | `VERIFIED` | `ml/models/lstm.py` | `tests/security/test_model_integrity.py` |
| **ML Input Bounds**| Non-Finite (`NaN`, `Inf`) Number Rejection | `VERIFIED` | `backend/app/services/model_service.py` | `tests/security/test_ml_input_validation.py` |
| **Log Injection** | Log Metadata Sanitization (`\r`, `\n`, ANSI) | `VERIFIED` | `backend/app/core/security.py` | `tests/security/test_secret_exposure.py` |
| **Correlation** | Request ID (`X-Request-ID`) Propagation | `VERIFIED` | `backend/app/main.py` | `tests/security/test_security_headers.py` |
| **Secret Shielding**| Startup Configuration Security Validator | `VERIFIED` | `backend/app/core/security_config.py` | `tests/security/test_secret_exposure.py` |
| **Container Security**| Non-root, No `docker.sock`, No `privileged` | `VERIFIED` | `docker-compose.yml`, `Dockerfiles` | `tests/security/test_container_security.py` |
| **Static Audit** | Static Security Audit Tool | `VERIFIED` | `scripts/security_audit.py` | Direct Execution (`python scripts/security_audit.py`) |
