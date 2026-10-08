# PolyShield AI Security Residual Risk Register

## Risk Assessment Framework
Risk scores are calculated as $\text{Risk} = \text{Likelihood} \times \text{Impact}$ on a scale of 1 (Low) to 5 (Critical).

---

## Active Residual Risk Register

| Risk ID | Vulnerability / Exposure Category | Likelihood | Impact | Overall Risk Score | Existing / Planned Mitigation | Component Owner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **RR-01** | **Synthetic Dataset Provenance**: Detection model is trained on safe synthetic PE fixtures (`dataset_provenance_status = SYNTHETIC_FIXTURE`). | High (4) | Low (2) | **Medium (8)** | Explicit provenance disclaimers displayed in UI, API, and report payloads. Models must be retrained on real-world malware datasets before production deployment. | ML Pipeline / Data Science |
| **RR-02** | **Production TLS Termination**: Application layer runs plain HTTP internally; TLS termination relies on an external reverse proxy (e.g. NGINX, Cloudflare). | Medium (3) | High (4) | **High (12)** | Production deployment configuration enforces HTTPS forwarding and HSTS headers via reverse proxy configuration. | DevOps / Infrastructure |
| **RR-03** | **Real VM Hypervisor Hardening**: Production dynamic sandbox hypervisor isolation requires deployment-specific virtualization validation (e.g., CAPE / KVM). | Low (2) | Critical (5) | **High (10)** | Sandbox security provider abstraction defaults to `MockSandboxProvider` with zero host PE execution until hypervisor is verified. | Sandbox Engineering |
| **RR-04** | **Third-Party Transitive Dependencies**: Transitive Python and npm dependencies may contain unpatched upstream CVEs. | Medium (3) | Medium (3) | **Medium (9)** | Continuous dependency auditing via `pip-audit` and `npm audit` integrated into security audit workflows. | Security / QA |
| **RR-05** | **Distributed DoS Target**: API rate limiting handles single-IP request bursts, but distributed botnets require network-level DDoS protection. | Medium (3) | High (4) | **High (12)** | Deployment behind WAF / Cloudflare network layer edge protection. | Infrastructure |
| **RR-06** | **Container Runtime Verification**: Local development/test environment lacks Docker CLI daemon; container runtime execution status is `RUNTIME_VERIFICATION_NOT_PERFORMED`. | Medium (3) | Medium (3) | **Medium (9)** | Execute runtime `docker compose up` integration tests on staging server with active Docker daemon. | DevOps / QA |
| **RR-07** | **Production Secret Management**: Deployment configuration relies on environment variables; raw `.env` files can leak if misconfigured. | Medium (3) | High (4) | **High (12)** | Integrate Docker secrets, Kubernetes secrets, or cloud secret manager (AWS Secrets Manager / Vault) in production. | DevOps / Security |

---

## Security Disclosure Statement
Phase 15 implements and verifies production container manifests, startup configuration validation, health probes, and deployment documentation. Residual risks remain deployment-specific, particularly around container daemon runtime execution, production secrets management, WAF edge protection, and hypervisor virtualization validation.
