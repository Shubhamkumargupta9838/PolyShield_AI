# PolyShield AI Testing Strategy & Quality Framework

## Executive Overview
Phase 14 defines the testing strategy, verification pyramid, and engineering quality assurance framework for PolyShield AI. The framework ensures application reliability, input validation bounds, state machine invariants, security control preservation, and failure isolation under normal, malformed, and adversarial workloads.

---

## 1. Testing Pyramid Architecture

```text
                        +-----------------------+
                        |    E2E Workflow       |  (1. Safe Synthetic E2E Flow)
                        +-----------------------+
                        |  Performance / Latency|  (2. Execution Smoke Measurements)
                        +-----------------------+
                        |   Integration & API   |  (3. Multi-service & Router Tests)
                        +-----------------------+
                        | Security & IDOR Shield|  (4. Auth, RBAC, Safe Paths, Hashes)
                        +-----------------------+
                        | Unit & Property Bounds|  (5. Pure Functions & Invariants)
                        +-----------------------+
```

---

## 2. Test Layer Definitions & Responsibilities

### Unit & Property-Based Tests (`tests/backend`, `tests/analysis`, `tests/ml`, `tests/integration`)
- **Focus**: Pure deterministic functions, schema validations, numeric invariant bounds.
- **Invariants Verified**:
  - Shannon Entropy $H(X) \in [0.0, 8.0]$ for all non-empty byte inputs.
  - Model malware probability $P \in [0.0, 1.0]$.
  - Static feature vector length equals exactly 17 canonical features.
  - Dynamic feature vector length equals exactly 14 canonical features.
  - Resolved storage paths remain strictly inside allowed root directories (`validate_safe_path`).
  - Event sequence encoding truncates at maximum sequence length 256.

### API & State Machine Integration Tests (`tests/backend`, `tests/integration`)
- **Focus**: REST endpoints, status lifecycle transitions, database persistence, and multi-tenant authorization.
- **Scenarios Tested**:
  - Complete legal scan status lifecycle: `QUEUED` $\rightarrow$ `STATIC_ANALYSIS` $\rightarrow$ `ML_INFERENCE` $\rightarrow$ `REPORT_GENERATION` $\rightarrow$ `COMPLETED`.
  - Illegal transition rejection: `COMPLETED` $\rightarrow$ `STATIC_ANALYSIS` returns `409 Conflict`.
  - Multi-tenant scan ownership: User B requesting User A scan returns `403 Forbidden`.
  - Idempotent re-analysis calls on completed scans.

### Security Regression Suite (`tests/security`)
- **Focus**: Preserving all Phase 13 security controls.
- **Controls Verified**: Bearer JWT authentication, password hashing, IDOR prevention, upload size limits (50MB), extension & MZ magic checks, path traversal resolution, NoSQL operator injection rejection, PyTorch `weights_only=True` loading, model SHA-256 checksum validation, rate limiting, and HTTP security headers.

### Dynamic Sandbox & Telemetry Isolation Tests (`tests/sandbox`)
- **Focus**: `ISandboxProvider` abstraction, `MockSandboxProvider` execution, `VmSandboxProvider` fallback handling (`PROVIDER_UNAVAILABLE`), sample staging integrity, and telemetry normalization.
- **Host Execution Boundary Invariant**: Zero untrusted PE binaries are ever executed on the host system.

### Performance & Latency Smoke Tests (`tests/performance`)
- **Focus**: Lightweight engineering latency measurements across upload validation, static feature extraction, model inference, ensemble fusion, and explainability generation on safe synthetic PE fixtures.

### End-to-End Safe Synthetic Workflow (`tests/e2e`)
- **Focus**: Complete user journey from account creation and token login to PE binary upload, scan state polling, report retrieval, and XAI attribution generation using safe synthetic PE byte streams.

---

## 3. Zero Host PE Execution Guarantee
- **Rule**: Uploaded PE files MUST NEVER be executed on the trusted host OS (`subprocess`, `os.system`, shell, PowerShell, `CreateProcess`, Wine, or Windows loader are strictly prohibited for submitted samples).
- **Enforcement**: Static analysis operates strictly in-memory using `pefile`. Dynamic analysis utilizes `MockSandboxProvider` or isolated virtualized environments.
