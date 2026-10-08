# PolyShield AI — Sandbox Security Checklist (Phase 8 Audit)

## 1. Host Isolation Controls
- [x] **No Host Filesystem Mounts**: Guest VM has zero read/write access to host directories or developer files.
- [x] **No Host Process Visibility**: Guest processes are completely isolated from host IPC and process space.
- [x] **No Docker Socket Exposure**: `/var/run/docker.sock` is strictly denied to guest instances.
- [x] **No Shared Folders**: Host-guest shared folders disabled.
- [x] **No Shared Clipboard**: Copy-paste buffer passthrough disabled.
- [x] **No USB Passthrough**: Direct host USB device passthrough disabled.
- [x] **No Host Credential Access**: Secrets (`.env`, database credentials, API tokens, SSH keys) strictly denied to guest instances.

---

## 2. Network Containment Controls
- [x] **Internet Access Disabled by Default**: Default configuration sets `internet_access = False`.
- [x] **Isolated Network Mode**: Default `network_mode = "isolated"`.
- [x] **Explicit Outbound Policy**: Outbound traffic blocked by default (`deny_all`).
- [x] **Explicit Inbound Policy**: Inbound traffic blocked by default (`deny_all`).
- [x] **DNS Sinkholing**: DNS resolution set to sinkhole mode.

---

## 3. Resource Containment Controls
- [x] **CPU Core Allocation Limit**: Enforced cap on guest CPU cores (default 2 cores).
- [x] **RAM Allocation Limit**: Enforced cap on guest memory (default 4096MB).
- [x] **Disk Space Limit**: Enforced cap on guest virtual disk allocation (default 20GB).
- [x] **Execution Timeout**: Enforced hard limit on execution runtime (default 300 seconds).
- [x] **Artifact Size Limit**: Enforced cap on total telemetry storage per job (default 500MB).

---

## 4. Environment Lifecycle & Cleanup Controls
- [x] **Disposable Environment Model**: Every analysis environment is created $\rightarrow$ used $\rightarrow$ destroyed.
- [x] **Automatic Cleanup on Completion**: Environment destroyed unconditionally after successful run.
- [x] **Automatic Cleanup on Failure**: Environment destroyed unconditionally on job failure.
- [x] **Automatic Cleanup on Timeout**: Environment destroyed unconditionally when execution times out.
- [x] **Watchdog Stale Job Reconciliation**: Watchdog cleans up orphaned or stale jobs exceeding 600 seconds.

---

## 5. Artifact Integrity & Untrusted Handling
- [x] **Cryptographic Hash Verification**: SHA-256 hash calculated for all collected telemetry artifacts.
- [x] **Untrusted Artifact Classification**: Artifacts tagged with `is_executable` and treated strictly as non-executable evidence.
- [x] **No Automatic Dropped File Execution**: Dropped files inside artifacts are never executed on host or server.

---

---

## 7. Dynamic Telemetry Ingestion & Sample Transfer Controls (Phase 9 Audit)
- [x] **Sample Transfer Integrity**: `SampleTransferService` verifies SHA-256 hash before and after staging to prevent tampered sample transfer.
- [x] **Path Traversal Shielding**: Filenames and paths in sample transfer and artifact collection strictly sanitized against path traversal (`..`, `/`, `\`).
- [x] **Hypervisor Absence Safety**: `VmSandboxProvider` checks host environment and returns `PROVIDER_UNAVAILABLE` without throwing unhandled host exceptions.
- [x] **Telemetry SHA-256 Fingerprinting**: Normalized `DynamicAnalysisResult` computes deterministic SHA-256 hash over normalized telemetry JSON.
- [x] **Absolute Zero Host Execution**: Verification suite (`tests/sandbox/test_security_execution_boundary.py`) confirms zero `subprocess.Popen(sample)` execution across all providers.

