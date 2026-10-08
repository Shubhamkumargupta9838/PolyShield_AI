from datetime import datetime, timezone
from analysis.features.dynamic_features import DynamicFeatureExtractor, DYNAMIC_FEATURE_NAMES, DYNAMIC_FEATURE_SCHEMA_VERSION
from sandbox.telemetry.normalizer import TelemetryNormalizer


def test_dynamic_feature_extractor_schema_and_counts():
    normalizer = TelemetryNormalizer()
    start_time = datetime.now(timezone.utc)

    raw_data = {
        "processes": [
            {"timestamp": start_time.isoformat(), "pid": 100, "image_name": "malware.exe", "event_type": "PROCESS_CREATE"},
            {"timestamp": start_time.isoformat(), "pid": 200, "parent_pid": 100, "image_name": "cmd.exe", "event_type": "PROCESS_CREATE"}
        ],
        "network": [
            {"timestamp": start_time.isoformat(), "protocol": "TCP", "dst_ip": "10.0.0.1", "dst_port": 80, "action": "BLOCKED"}
        ],
        "filesystem": [
            {"timestamp": start_time.isoformat(), "operation": "WRITE", "path": "C:\\temp\\dropped.exe", "size": 2048},
            {"timestamp": start_time.isoformat(), "operation": "DELETE", "path": "C:\\temp\\log.txt", "size": 100}
        ],
        "registry": [
            {"timestamp": start_time.isoformat(), "operation": "SET_VALUE", "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}
        ],
        "api_traces": [
            {"timestamp": start_time.isoformat(), "process_id": 100, "module": "kernel32.dll", "api_name": "CreateServiceW", "category": "SERVICE"},
            {"timestamp": start_time.isoformat(), "process_id": 100, "module": "ntdll.dll", "api_name": "NtWriteVirtualMemory", "category": "INJECTION"}
        ]
    }

    dyn_result = normalizer.normalize(
        job_id="job_feat_1",
        scan_id="scan_feat_1",
        sample_sha256="e" * 64,
        provider_name="mock",
        environment_id="mock_env_feat",
        started_at=start_time,
        completed_at=start_time,
        raw_telemetry=raw_data
    )

    extractor = DynamicFeatureExtractor()
    features = extractor.extract_features(dyn_result)

    assert DYNAMIC_FEATURE_SCHEMA_VERSION == "dynamic-v1"
    assert len(features) == 14
    assert list(features.keys()) == DYNAMIC_FEATURE_NAMES

    assert features["process_count"] == 2.0
    assert features["child_process_count"] == 1.0
    assert features["network_connection_count"] == 1.0
    assert features["blocked_network_attempt_count"] == 1.0
    assert features["filesystem_write_count"] == 1.0
    assert features["filesystem_delete_count"] == 1.0
    assert features["registry_write_count"] == 1.0
    assert features["api_event_count"] == 2.0
    assert features["injection_event_count"] == 1.0
    assert features["persistence_event_count"] >= 1.0
    assert features["service_creation_count"] == 1.0
    assert features["suspicious_process_count"] == 1.0
