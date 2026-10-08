# PolyShield AI — Final Threat Model & Risk Analysis

## 1. Threat Taxonomy & Mitigation Matrix

| Threat Category | Target Surface | Applied Control | Verification Status | Residual Risk |
| :--- | :--- | :--- | :--- | :--- |
| **Host Code Execution** | Upload Endpoint / Worker Node | Zero subprocess execution policy; byte-stream static parsing; VM boundary. | VERIFIED | Hypervisor zero-day escape (mitigated by isolated VM guest network). |
| **Path Traversal** | Artifact / Report Fetch Routes | Safe-root directory validation via `validate_safe_path`. | VERIFIED | OS-level symbolic link manipulation outside app root. |
| **IDOR / Data Leakage** | Scan Result Query API | Mandatory JWT claim validation & scan ownership assertion. | VERIFIED | Stolen user authorization bearer tokens. |
| **NoSQL Injection** | MongoDB Query Engine | Pydantic v2 strict type coercion & explicit field mapping. | VERIFIED | MongoDB engine vulnerability. |
| **Model Tampering** | Model Weight Storage | SHA-256 integrity verification + PyTorch `weights_only=True`. | VERIFIED | Unauthorized write access to `ml/artifacts/models`. |
| **Denial of Service (DoS)**| API Gateway | SlowAPI rate limiting (100/min general, 10/min upload, 30/min auth). | VERIFIED | Distributed volumetric DDoS at edge proxy. |
| **Secret Exposure** | Environment / Container | Startup validation failing fast on default keys; `.env` excluded from git. | VERIFIED | Environment variable leak via compromised host OS. |
| **XSS / Frame Attacks** | React Frontend | Nginx strict CSP (`script-src 'self'`), `X-Frame-Options: DENY`, `nosniff`. | VERIFIED | Browser zero-day bypass of CSP engine. |

---

## 2. Threat Verification Summary

All 16 threat vectors identified in PolyShield AI security risk registers are backed by automated test suites in `tests/security/`. Static security scanning script `scripts/security_audit.py` runs as part of continuous integration to verify unmitigated findings remain at 0.
