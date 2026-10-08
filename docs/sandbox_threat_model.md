# PolyShield AI — Sandbox Threat Model & Security Boundaries (Phase 8)

## 1. Executive Summary

This document defines the formal threat model for dynamic analysis within PolyShield AI. As PolyShield AI prepares for isolated sandbox detonation in future phases, this threat model establishes the security assumptions, threat actors, attack vectors, trust boundaries, assets, and mandatory mitigation controls required before executing hostile Windows Portable Executable (PE) binaries.

---

## 2. Protected Assets

| Asset Category | Description | Sensitivity / Impact |
| :--- | :--- | :--- |
| **Host Operating System** | Host OS running Docker hypervisor, developer kernel, and filesystem. | **CRITICAL** (Host compromise risks entire infrastructure) |
| **Docker Infrastructure** | Docker daemon (`/var/run/docker.sock`), containers, volumes, networks. | **CRITICAL** (Privilege escalation via Docker socket) |
| **Trusted Services** | FastAPI REST server, Celery task workers, static analysis engine. | **HIGH** (Service disruption, code injection, unauthorized access) |
| **Data Persistence** | MongoDB database (metadata, reports) and Redis broker/cache. | **HIGH** (Data tampering, exfiltration, queue poisoning) |
| **Machine Learning Models** | Trained model artifacts (`static_baseline_v2.0.joblib`), pipeline schemas. | **MEDIUM** (Model theft, adversarial tampering) |
| **Host Credentials & Secrets** | `.env` files, database passwords, API tokens, SSH keys, cloud keys. | **CRITICAL** (Unauthorized exfiltration or lateral movement) |
| **Analysis Reports** | User-submitted PE metadata and generated static/dynamic reports. | **MEDIUM** (Confidentiality & integrity) |

---

## 3. Threat Actor Profile

The threat model assumes the submitted sample is **actively malicious, adversarial, and hostile**.

The sample may attempt to:
1. **Escape Sandbox Boundary**: Exploit hypervisor or container vulnerabilities to break out onto the host OS.
2. **Access Host File System & Secrets**: Read `/etc/passwd`, `.env`, SSH keys, database credentials, or developer home directories.
3. **Escalate Privileges via Docker**: Access `/var/run/docker.sock` to gain root control over the host.
4. **Attack Internal Infrastructure**: Target local network IP ranges, Redis, MongoDB, or FastAPI endpoints via lateral movement.
5. **Establish Command & Control (C2)**: Connect to external malicious IPs/domains, exfiltrate data, or participate in botnet operations.
6. **Denial of Service (Resource Exhaustion)**: Consume 100% CPU, allocate massive RAM, fill host disk space, or spawn infinite child processes.
7. **Persist Across Executions**: Attempt to modify golden VM images, leave hidden payloads in shared folders, or survive snapshot resets.
8. **Evade & Counter Analysis**: Detect sandbox indicators (QEMU/VMware artifacts, timing analysis) or corrupt telemetry collectors.

---

## 4. Trust Boundaries

```text
                                TRUSTED ZONE
──────────────────────────────────────────────────────────────────────────
[ React Dashboard ] <---> [ FastAPI Server ] <---> [ MongoDB / Redis ]
                                  │
                                  ▼
                         [ Celery Workers ]
                                  │
                                  ▼
                       [ Sandbox Controller ]
                                  │
====================== MANDATORY SECURITY BOUNDARY =======================
                                  │
                                  ▼
                              UNTRUSTED
──────────────────────────────────────────────────────────────────────────
                      [ Disposable Isolated VM ]
                                  │
                          (Submitted PE File)
                                  │
                      [ Guest Process & Filesystem ]
                                  │
                      [ Guest Runtime Telemetry ]
```

### Non-Negotiable Security Axioms:
- **Rule 1**: Submitted PE files are strictly untrusted regardless of file extension, digital signatures, hash reputation, or user input.
- **Rule 2**: Docker containers must NOT be used as the primary security isolation boundary for hostile Windows binary detonation. Hypervisor-level VM isolation is required.
- **Rule 3**: Guest execution environments must NEVER possess access to `.env`, credentials, secrets, shared folders, shared clipboards, or Docker sockets.

---

## 5. Security Objectives & Mitigation Matrix

| Threat / Attack Surface | Security Objective | Mandatory Mitigation Control |
| :--- | :--- | :--- |
| **Guest VM Escape** | Contain sample in guest | Air-gapped hypervisor, minimal hypervisor device surface, no host mounts. |
| **Host Secrets Exfiltration** | Shield credentials | Strict secret isolation; zero secrets passed to guest. |
| **Docker Daemon Hijack** | Protect Docker socket | `deny_docker_socket = True`; socket never passed to guest container or VM. |
| **Lateral Network Attack** | Isolate network | `internet_access = False`; default `network_mode = "isolated"`, sinkhole DNS. |
| **Resource Exhaustion (DoS)** | Enforce bounds | Declarative `ResourcePolicy`: CPU, RAM (4GB), disk (20GB), and timeout (300s). |
| **Persistence Across Scans** | Guarantee clean state | Disposable execution: VM snapshot revert / destruction on completion or failure. |
| **Telemetry Tampering** | Protect integrity | Artifact integrity verification via SHA-256 identity and read-only storage. |

---

## 6. Phase 8 Status & Zero Execution Statement

> **SECURITY VERIFICATION STATEMENT**:  
> In Phase 8, dynamic malware detonation is NOT enabled. All sandbox jobs are processed by `MockSandboxProvider`, which simulates lifecycle transitions (`CREATED` $\rightarrow$ `READY` $\rightarrow$ `RUNNING` $\rightarrow$ `COLLECTING` $\rightarrow$ `COMPLETED` $\rightarrow$ `DESTROYED`) with **zero host PE execution**.
