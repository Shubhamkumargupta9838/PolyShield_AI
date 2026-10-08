"""
Synthetic Telemetry Fixtures for PolyShield AI Testing (Phase 14).

Provides reusable, structured raw telemetry dictionaries and event sequences
for testing dynamic analysis normalizers, sequence encoders, LSTM inference,
and fallback paths without executing real malware or requiring host sandbox execution.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List


def generate_clean_telemetry() -> Dict[str, Any]:
    """Generates benign/clean process telemetry log dictionary."""
    base_time = datetime.now(timezone.utc)
    return {
        "processes": [
            {
                "timestamp": base_time.isoformat(),
                "pid": 1004,
                "ppid": 4,
                "image_name": "explorer.exe",
                "event_type": "PROCESS_CREATE"
            },
            {
                "timestamp": (base_time + timedelta(milliseconds=100)).isoformat(),
                "pid": 2048,
                "ppid": 1004,
                "image_name": "notepad.exe",
                "event_type": "PROCESS_CREATE"
            }
        ],
        "network": [
            {
                "timestamp": (base_time + timedelta(milliseconds=200)).isoformat(),
                "protocol": "HTTPS",
                "dst_ip": "142.250.190.46",
                "dst_port": 443,
                "action": "ALLOWED"
            }
        ],
        "filesystem": [
            {
                "timestamp": (base_time + timedelta(milliseconds=150)).isoformat(),
                "operation": "READ",
                "path": "C:\\Windows\\System32\\notepad.exe",
                "size": 184320
            }
        ],
        "registry": [
            {
                "timestamp": (base_time + timedelta(milliseconds=160)).isoformat(),
                "operation": "READ_VALUE",
                "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion"
            }
        ],
        "api_traces": [
            {
                "timestamp": (base_time + timedelta(milliseconds=50)).isoformat(),
                "process_id": 2048,
                "module": "kernel32.dll",
                "api_name": "CreateFileW",
                "category": "FILESYSTEM"
            }
        ]
    }


def generate_suspicious_telemetry() -> Dict[str, Any]:
    """Generates synthetic telemetry representing high-risk/suspicious behavioral patterns."""
    base_time = datetime.now(timezone.utc)
    return {
        "processes": [
            {
                "timestamp": base_time.isoformat(),
                "pid": 4096,
                "ppid": 1004,
                "image_name": "sample.exe",
                "event_type": "PROCESS_CREATE"
            },
            {
                "timestamp": (base_time + timedelta(milliseconds=50)).isoformat(),
                "pid": 5120,
                "ppid": 4096,
                "image_name": "cmd.exe",
                "event_type": "PROCESS_CREATE"
            },
            {
                "timestamp": (base_time + timedelta(milliseconds=100)).isoformat(),
                "pid": 5200,
                "ppid": 5120,
                "image_name": "powershell.exe",
                "event_type": "PROCESS_CREATE"
            }
        ],
        "network": [
            {
                "timestamp": (base_time + timedelta(milliseconds=150)).isoformat(),
                "protocol": "TCP",
                "dst_ip": "198.51.100.55",
                "dst_port": 4444,
                "action": "BLOCKED"
            }
        ],
        "filesystem": [
            {
                "timestamp": (base_time + timedelta(milliseconds=120)).isoformat(),
                "operation": "WRITE",
                "path": "C:\\Users\\Public\\malicious.dll",
                "size": 65536
            },
            {
                "timestamp": (base_time + timedelta(milliseconds=200)).isoformat(),
                "operation": "WRITE",
                "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "size": 1024
            }
        ],
        "registry": [
            {
                "timestamp": (base_time + timedelta(milliseconds=130)).isoformat(),
                "operation": "SET_VALUE",
                "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            }
        ],
        "api_traces": [
            {
                "timestamp": (base_time + timedelta(milliseconds=30)).isoformat(),
                "process_id": 4096,
                "module": "ntdll.dll",
                "api_name": "NtWriteVirtualMemory",
                "category": "MEMORY"
            },
            {
                "timestamp": (base_time + timedelta(milliseconds=40)).isoformat(),
                "process_id": 4096,
                "module": "kernel32.dll",
                "api_name": "CreateRemoteThread",
                "category": "PROCESS"
            }
        ]
    }


def generate_empty_telemetry() -> Dict[str, Any]:
    """Generates minimal empty telemetry structure."""
    return {
        "processes": [],
        "network": [],
        "filesystem": [],
        "registry": [],
        "api_traces": []
    }


def generate_malformed_telemetry() -> Dict[str, Any]:
    """Generates raw telemetry with missing fields, invalid timestamps, and non-standard types."""
    return {
        "processes": [
            {"invalid_field": True},
            {"pid": "NOT_AN_INT", "timestamp": "INVALID_TIMESTAMP"}
        ],
        "network": [
            {"dst_port": -1, "protocol": None}
        ],
        "filesystem": [
            {"size": "UNBOUNDED"}
        ],
        "registry": [],
        "api_traces": [
            "corrupted_trace_string_instead_of_dict"
        ]
    }
