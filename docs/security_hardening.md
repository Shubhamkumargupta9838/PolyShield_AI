# PolyShield AI Security Hardening & Controls Architecture

## Executive Overview
Phase 13 establishes application boundary defense for PolyShield AI, assuming an active adversary model across all external and internal entry points (uploaded binaries, HTTP parameters, JSON payloads, Celery tasks, Redis queues, and database records).

---

## 1. Authentication & JWT Security Specification
- **Authentication Scheme**: HTTP Bearer JWT tokens (`Authorization: Bearer <token>`).
- **Password Hashing**: PBKDF2-HMAC-SHA256 with 100,000 iterations and cryptographically secure random salts (`secrets.token_bytes(16)`). Plaintext passwords are never stored or logged.
- **JWT Claims & Validation**:
  - Algorithm: `HS256` explicitly enforced.
  - Rejection of `alg = none`: Tokens with missing or `"none"` algorithms raise `401 Unauthorized` (`AuthenticationException`).
  - Mandatory Claims: `exp` (expiration), `iat` (issued-at), `iss` (`polyshield`), `aud` (`polyshield-api`), `sub` (`user_id`), `username`, `role`.
  - Secret Isolation: Loaded strictly from `JWT_SECRET_KEY` environment variable. Default development keys trigger startup validation errors in production (`ENVIRONMENT=production`).

---

## 2. Multi-Tenant Authorization & IDOR Shielding
- **RBAC Roles**:
  - `ANALYST`: Can upload PE samples, initiate static/dynamic analyses, run inference, generate explanations, and view own scan reports.
  - `ADMIN`: Full administrative privileges, system status inspection, and security audit log review.
- **Scan Ownership Control**:
  - Every scan document tracks `owner_id`.
  - IDOR Prevention: Direct object references (`/scans/{scan_id}`, `/reports/{id}`, `/artifacts/{id}`, `/dynamic-analysis`, `/ensemble-inference`, `/explanation`) evaluate `check_scan_ownership`.
  - Access Rules:
    - User A accessing User A scan: `ALLOWED` (HTTP 200).
    - User B accessing User A scan: `FORBIDDEN` (HTTP 403 `AUTHORIZATION_DENIED`).
    - Admin accessing User A scan: `ALLOWED` (HTTP 200).

---

## 3. Upload & Path Traversal Security
- **PE Header & Extension Validation**: Validates `.exe`, `.dll`, `.sys`, `.scr`, `.bin`, `.ocx` extensions and mandatory `MZ` (0x4D, 0x5A) magic header.
- **Size Bounds**: Enforces hard `MAX_UPLOAD_SIZE_BYTES` (50MB default) to prevent memory or disk exhaustion.
- **Null-Byte Rejection**: Filenames containing `\x00` are rejected immediately.
- **Path Traversal Safe-Root Resolution**: `LocalStorageService` enforces `validate_safe_path(candidate_path, allowed_root)` using `candidate.resolve().relative_to(allowed_root.resolve())`.

---

## 4. Model Artifact & Supply Chain Security
- **SHA-256 Checksum Verification**: Model service computes SHA-256 checksums of `joblib` and PyTorch `.pt` artifacts prior to deserialization.
- **Path Allowlist Boundary**: Model artifact loading is strictly restricted to internal registry directories (`ml/artifacts/models/`). User-supplied `model_path` inputs attempting traversal escape raise `PathTraversalException`.
- **PyTorch `weights_only=True`**: All PyTorch models use `torch.load(..., weights_only=True)` to prevent arbitrary code execution during deserialization.

---

## 5. Security Logging & Correlation
- **Structured Audit Events**: Logged events include `AUTH_SUCCESS`, `AUTH_FAILURE`, `AUTHZ_DENIED`, `PATH_TRAVERSAL_BLOCKED`, `MODEL_INTEGRITY_FAILURE`, `SECURITY_POLICY_VIOLATION`.
- **Log Injection Sanitization**: `sanitize_log_input` strips `\r`, `\n`, `\t`, and ANSI escape codes from user-controlled metadata before writing to logs.
- **Request Correlation**: Middleware propagates `X-Request-ID` across HTTP responses and worker tasks for end-to-end auditability.
