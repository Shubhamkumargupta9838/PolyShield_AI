# PolyShield AI — Security Architecture & Controls

## 1. Security Principles

PolyShield AI is designed according to **Defense in Depth**, **Least Privilege**, and **Zero Host Execution** invariants.

---

## 2. Core Security Controls Matrix

| Layer | Threat | Security Control | Verification Status |
| :--- | :--- | :--- | :--- |
| **Authentication** | Unauthorized Access | JWT access tokens with mandatory exp, iat, iss, aud claims. Alg `none` explicitly rejected. | VERIFIED (`test_authentication.py`) |
| **Authorization** | IDOR / Privilege Escalation | RBAC roles (`ANALYST`, `ADMIN`). Scan ownership enforcement on all scan/report routes. | VERIFIED (`test_authorization.py`) |
| **Input Validation** | File Upload Attacks / Null-byte | Extension allowlisting, null-byte stripping, 50MB hard size limit. | VERIFIED (`test_upload_security.py`) |
| **Path Security** | Path Traversal (`../`) | Safe-root directory validation via `validate_safe_path`. | VERIFIED (`test_path_traversal.py`) |
| **Host Boundary** | Host Code Execution | Zero subprocess / shell execution policy on PE binaries. In-memory byte processing. | VERIFIED (`test_security_execution_boundary.py`) |
| **Database** | NoSQL Injection | Type-enforced Pydantic schema validation preventing raw dict query injection. | VERIFIED (`test_nosql_injection.py`) |
| **Model Security** | Model Artifact Tampering | SHA-256 model checksum verification + PyTorch `weights_only=True` loading + Safe path check. | VERIFIED (`test_model_integrity.py`, `test_model_path_integrity.py`) |
| **Network & Edge** | XSS / Clickjacking / HSTS | Refined CSP, `X-Frame-Options: DENY`, `nosniff`, `HSTS` production header. | VERIFIED (`test_security_headers.py`) |
| **Container Hardening**| Privilege Escalation | Non-root `polyshield` user (UID 10001), `cap_drop: ALL`, internal bridge networks. | VERIFIED (`test_container_security.py`) |
| **Secret Management** | Secret Leakage | Production startup validation rejecting default `SECRET_KEY` or `DEBUG=True`. | VERIFIED (`test_production_config.py`, `test_secret_exposure.py`) |

---

## 3. Host Execution Invariant

> **Uploaded PE binaries are NEVER executed directly on the host operating system.**

All PE inspection is conducted using static byte stream parsing (`pefile` in-memory structure analysis) or within disposable virtual machine sandbox boundaries. Subprocess invocation on host PE samples is prohibited across all backend services.
