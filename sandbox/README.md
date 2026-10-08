# PolyShield AI Sandbox Module (Phase 8 Architecture Foundation)

## Overview
The `sandbox` package defines the threat model, security policies, provider interface abstractions, mock provider implementation, and sandbox controller for PolyShield AI's future dynamic analysis capabilities.

> **STRICT SECURITY RULE**:  
> No submitted PE files are executed during Phase 8. The `MockSandboxProvider` simulates environment state transitions (`CREATED` -> `READY` -> `RUNNING` -> `COLLECTING` -> `COMPLETED` -> `DESTROYED`) with **zero sample execution**.

---

## Directory Structure

```text
sandbox/
├── interfaces/
│   └── sandbox_provider.py     # Abstract Base Class (ISandboxProvider)
├── models/
│   ├── sandbox_job.py          # SandboxJob & SandboxJobStatus enum
│   ├── sandbox_result.py       # SandboxResult execution response
│   └── artifact.py             # SandboxArtifact untrusted telemetry model
├── controller/
│   └── sandbox_controller.py   # Lifecycle controller & watchdog reconciler
├── providers/
│   └── mock_provider.py        # Safe mock sandbox implementation (No PE Execution)
├── security/
│   ├── isolation_policy.py     # Non-negotiable host isolation deny rules
│   ├── network_policy.py       # Internet containment & DNS sinkhole policy
│   ├── resource_policy.py      # CPU, RAM, disk, and timeout caps
│   └── cleanup_policy.py       # Guaranteed environment destruction policy
└── README.md
```

---

## Security Policies

1. **Isolation Policy (`sandbox.security.IsolationPolicy`)**:
   - `deny_host_filesystem = True`
   - `deny_host_processes = True`
   - `deny_docker_socket = True`
   - `deny_shared_folders = True`
   - `deny_shared_clipboard = True`
   - `deny_usb_passthrough = True`
   - `deny_secret_access = True`

2. **Network Policy (`sandbox.security.NetworkPolicy`)**:
   - `internet_access = False` (Default)
   - `network_mode = "isolated"`
   - `dns_policy = "sinkhole"`

3. **Cleanup Guarantee (`sandbox.security.CleanupPolicy`)**:
   - VM snapshot revert or instance destruction is executed unconditionally on success, failure, timeout, or worker crash.
