# PolyShield AI — Dynamic Behavioral Telemetry Schema (Phase 9)

## 1. Overview

This document specifies the normalized data models for dynamic behavioral telemetry events captured during sandbox analysis in PolyShield AI. All events maintain relative timestamps (`relative_time_ms`) measured from `analysis_start` to format reproducible input sequences for Phase 10 (LSTM models).

---

## 2. Event Models

### A. Process Event (`ProcessEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed since analysis start.
- `pid`: Process ID.
- `parent_pid`: Parent Process ID.
- `image_name`: Executable image name (e.g. `sample.exe`).
- `command_line`: Command line invocation arguments.
- `event_type`: `PROCESS_CREATE`, `PROCESS_EXIT`, `PROCESS_INJECT`, `PROCESS_TERMINATE`.
- `exit_code`: Process termination exit code.
- `integrity_level`: Windows process integrity level.

### B. Network Event (`NetworkEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed since analysis start.
- `protocol`: Transport protocol (`TCP`, `UDP`, `ICMP`, `HTTP`, `HTTPS`).
- `direction`: `inbound` or `outbound`.
- `src_ip` / `src_port`: Source IP and port.
- `dst_ip` / `dst_port`: Destination IP and port.
- `domain`: Target domain name.
- `bytes_sent` / `bytes_received`: Byte counters.
- `action`: `CONNECT`, `DNS_QUERY`, `DNS_RESPONSE`, `BLOCKED`.

### C. DNS Event (`DNSEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed.
- `query`: Domain query string.
- `record_type`: DNS record type (`A`, `AAAA`, `TXT`).
- `response`: Resolved IP string or null.
- `action`: `sinkholed`, `resolved`, `blocked`.

### D. Filesystem Event (`FilesystemEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed.
- `operation`: `CREATE`, `WRITE`, `READ`, `DELETE`, `RENAME`.
- `path`: Target Windows guest filesystem path.
- `process_id`: Initiating process ID.
- `result`: `SUCCESS` or error message.
- `sha256`: Optional hash of created/modified file.
- `size`: File size in bytes.

### E. Registry Event (`RegistryEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed.
- `operation`: `CREATE_KEY`, `SET_VALUE`, `DELETE_KEY`, `OPEN_KEY`.
- `key`: Full registry key path (e.g. `HKLM\Software\...`).
- `value_name`: Value name modified.
- `value_type`: Registry value type (`REG_SZ`, `REG_DWORD`).

### F. API Trace Event (`ApiEvent`)
- `timestamp`: ISO-8601 UTC timestamp.
- `relative_time_ms`: Milliseconds elapsed.
- `process_id`: Initiating process ID.
- `module`: DLL module name (e.g. `kernel32.dll`, `ntdll.dll`).
- `api_name`: Intercepted API symbol name.
- `category`: `PROCESS`, `MEMORY`, `FILE`, `REGISTRY`, `NETWORK`, `CRYPTO`, `SERVICE`, `PERSISTENCE`, `PRIVILEGE`, `INJECTION`.
- `arguments_hash`: Cryptographic hash of API parameters.
