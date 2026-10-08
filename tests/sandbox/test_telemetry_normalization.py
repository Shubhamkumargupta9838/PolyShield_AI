from datetime import datetime, timezone
from sandbox.telemetry.normalizer import TelemetryNormalizer
from sandbox.models.sandbox_result import DynamicAnalysisResult


def test_telemetry_normalizer_pipeline():
    normalizer = TelemetryNormalizer()
    start_time = datetime.now(timezone.utc)
    completed_time = datetime.now(timezone.utc)

    raw_data = {
        "processes": [
            {"timestamp": start_time.isoformat(), "pid": 100, "image_name": "malware.exe", "event_type": "PROCESS_CREATE"},
            {"timestamp": start_time.isoformat(), "pid": 200, "parent_pid": 100, "image_name": "cmd.exe", "event_type": "PROCESS_CREATE"}
        ],
        "network": [
            {"timestamp": start_time.isoformat(), "protocol": "TCP", "dst_ip": "1.2.3.4", "dst_port": 443, "action": "BLOCKED"}
        ],
        "filesystem": [
            {"timestamp": start_time.isoformat(), "operation": "WRITE", "path": "C:\\temp\\dropped.exe", "size": 2048}
        ],
        "registry": [
            {"timestamp": start_time.isoformat(), "operation": "SET_VALUE", "key": "HKLM\\Software\\Run"}
        ],
        "api_traces": [
            {"timestamp": start_time.isoformat(), "process_id": 100, "module": "ntdll.dll", "api_name": "NtCreateProcess", "category": "PROCESS"}
        ]
    }

    result = normalizer.normalize(
        job_id="job_norm_1",
        scan_id="scan_norm_1",
        sample_sha256="f" * 64,
        provider_name="mock",
        environment_id="mock_env_1",
        started_at=start_time,
        completed_at=completed_time,
        raw_telemetry=raw_data
    )

    assert isinstance(result, DynamicAnalysisResult)
    assert len(result.process_events) == 2
    assert len(result.network_events) == 1
    assert len(result.filesystem_events) == 1
    assert len(result.registry_events) == 1
    assert len(result.api_events) == 1
    assert result.telemetry_sha256 is not None
    assert len(result.telemetry_sha256) == 64
