# Phase 13 — Initial Security Baseline Assessment

**Project**: PolyShield AI — AI-Powered Polymorphic Malware Detection & Analysis Platform  
**Date**: September 15, 2026  
**Status**: Pre-Hardening Assessment Baseline  

---

## Executive Overview

This baseline documents the security posture of the PolyShield AI infrastructure prior to Phase 13 Security Hardening. Every security control is classified into one of five states:
- `MISSING`: Control is completely absent.
- `DESIGNED`: Control is documented in architecture/design specifications but not code.
- `CONFIGURED`: Control parameters exist in settings/configs but lack active runtime enforcement.
- `ENFORCED`: Control is actively executed and enforced in application code.
- `TESTED`: Control is validated by automated test suites in `tests/`.

---

## 1. Security Control Baseline Matrix

| Control Category | Specific Security Control | Initial Baseline Classification | Notes & Deficiencies Prior to Phase 13 |
| :--- | :--- | :--- | :--- |
| **Authentication** | Bearer JWT Authentication | `MISSING` | API endpoints are unauthenticated. |
| **Authentication** | Argon2id / bcrypt Password Hashing | `MISSING` | No auth/user management routes exist. |
| **Authentication** | JWT Claim & Alg Validation (`none` rejection) | `MISSING` | JWT middleware not yet active. |
| **Authorization** | RBAC (`ANALYST`, `ADMIN`) | `MISSING` | Authorization checks do not exist. |
| **Scan Ownership** | `owner_id` Scan Access Control & IDOR Shielding | `MISSING` | Scans accessible by scan_id without ownership check. |
| **Upload Security** | Hard Upload Size Limit (`MAX_UPLOAD_SIZE_BYTES`) | `ENFORCED` / `TESTED` | Tested in `test_scans.py`. Requires request streaming bounds. |
| **Upload Security** | Filename Path Traversal Sanitization | `CONFIGURED` | Raw filename saved in metadata; needs safe normalization. |
| **Upload Security** | PE Magic Byte Validation (`MZ` & `PE\0\0`) | `ENFORCED` / `TESTED` | Enforced by static PE analyzer. |
| **Path Traversal** | Filesystem Safe-Root Resolution (`relative_to`) | `DESIGNED` | Standard pathing used; needs explicit safe root checks. |
| **Artifact Security** | Opaque Storage Refs / Path Hiding | `CONFIGURED` | Absolute paths suppressed in responses; needs full audit. |
| **Artifact Security** | Artifact Access Ownership Authorization | `MISSING` | Artifact retrieval does not check owner. |
| **SSRF** | Server-Side Request Forgery Prevention | `DESIGNED` | No outgoing arbitrary URL fetch functions currently exposed. |
| **NoSQL Injection** | MongoDB Parameter Sanitization & Pydantic Bounds | `CONFIGURED` | PyMongo / Motor parameterized; needs explicit Pydantic strictness. |
| **DB & Cache Security**| MongoDB / Redis Authentication & Isolated Network | `CONFIGURED` | Docker service settings exist; production auth env vars required. |
| **Celery Security** | Task Parameter Re-validation & Integrity | `CONFIGURED` | Workers trust task args; need scan ownership/state checks. |
| **Rate Limiting** | API Request Rate Limiting (`slowapi` / Redis) | `MISSING` | Endpoint rate limiting absent. |
| **Request Limits** | Middleware Payload Bounds & Strict Pydantic Bounds | `CONFIGURED` | Enforced at application level; needs middleware bounds. |
| **CORS & Headers** | Restricted CORS & HTTP Security Headers | `CONFIGURED` | `CORSMiddleware` active; needs origin restriction & security headers. |
| **Frontend Security**| React XSS Protection & Output Escaping | `ENFORCED` / `TESTED` | React JSX escapes text; no `dangerouslySetInnerHTML`. |
| **Security Logging** | Structured Audit Events & Log Injection Sanitization | `CONFIGURED` | Standard logger active; needs security audit event schema. |
| **Request Correlation**| `X-Request-ID` Tracing Across Services | `MISSING` | Request tracing absent. |
| **Secret Management**| Secrets Strict Isolation & Startup Config Validation | `CONFIGURED` | `.env.example` safe; needs strict startup validator. |
| **ML Integrity** | Model Checksum Verification (SHA-256) | `MISSING` | Models loaded from file without hash check. |
| **ML Security** | Safe Model Load (No user joblib/pickle loading) | `ENFORCED` | Hardcoded model paths only; needs regression tests. |
| **ML Security** | PyTorch Weights-Only & Input Bounds Validation | `CONFIGURED` | `torch.load` used; needs explicit `weights_only=True`. |
| **Telemetry Security**| Untrusted Telemetry Boundary Sanitization | `ENFORCED` / `TESTED` | Telemetry normalized via `DynamicTelemetryNormalizer`. |
| **Container Hardening**| Non-root Docker, No Host Sockets, Network Segments | `DESIGNED` | Compose services defined; needs non-root / capability drop audit. |
| **Audit Automation** | Static Security Audit Script (`scripts/security_audit.py`) | `MISSING` | Audit script not yet created. |
| **Test Coverage** | Security Regression Test Suite (`tests/security/`) | `MISSING` | Unit tests exist for components, but no dedicated `tests/security/`. |

---

## 2. Summary of Gaps to Address in Phase 13

1. **Authentication Layer**: Introduce JWT Bearer token authentication with Argon2id password hashing and strict claim/algorithm verification.
2. **Authorization & Multi-Tenancy**: Introduce RBAC (`ANALYST` vs `ADMIN`) and `owner_id` scan ownership to eliminate IDOR across scans, reports, artifacts, and explanations.
3. **Model & Supply Chain Integrity**: Implement SHA-256 model checksum verification and enforce `weights_only=True` for PyTorch. Document joblib/pickle trust boundaries.
4. **Rate Limiting & Security Headers**: Add rate limiting middleware and environment-aware HTTP security headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`).
5. **Path Traversal & Storage Bounds**: Enforce strict safe-root path resolution for all file system operations and enforce bounded string/array lengths in Pydantic models.
6. **Security Audit Script & Test Suite**: Create `scripts/security_audit.py` and `tests/security/` covering 18 critical threat vectors.
