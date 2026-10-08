from typing import Dict, Any, List
from sandbox.models.sandbox_result import DynamicAnalysisResult
from sandbox.models.telemetry import (
    ProcessEventType,
    NetworkAction,
    FilesystemOperation,
    RegistryOperation,
    ApiCategory,
)

DYNAMIC_FEATURE_SCHEMA_VERSION = "dynamic-v1"

DYNAMIC_FEATURE_NAMES = [
    "process_count",
    "child_process_count",
    "network_connection_count",
    "dns_query_count",
    "blocked_network_attempt_count",
    "filesystem_write_count",
    "filesystem_delete_count",
    "registry_write_count",
    "api_event_count",
    "injection_event_count",
    "persistence_event_count",
    "service_creation_count",
    "suspicious_process_count",
    "dropped_file_count",
]


class DynamicFeatureExtractor:
    """
    Extracts canonical 14-dimensional dynamic-v1 feature dictionary
    from a normalized DynamicAnalysisResult.
    Maintains strict schema versioning ('dynamic-v1') and separation from static-v1 features.
    """

    def extract_features(self, result: DynamicAnalysisResult) -> Dict[str, float]:
        proc_events = result.process_events or []
        net_events = result.network_events or []
        dns_events = result.dns_events or []
        fs_events = result.filesystem_events or []
        reg_events = result.registry_events or []
        api_events = result.api_events or []
        artifacts = result.artifacts or []

        process_count = len(proc_events)
        child_process_count = sum(1 for p in proc_events if p.parent_pid is not None)

        network_connection_count = len(net_events)
        dns_query_count = len(dns_events)
        blocked_network_attempt_count = sum(1 for n in net_events if n.action == NetworkAction.BLOCKED)

        filesystem_write_count = sum(1 for f in fs_events if f.operation == FilesystemOperation.WRITE)
        filesystem_delete_count = sum(1 for f in fs_events if f.operation == FilesystemOperation.DELETE)

        registry_write_count = sum(
            1 for r in reg_events if r.operation in (RegistryOperation.SET_VALUE, RegistryOperation.CREATE_KEY)
        )

        api_event_count = len(api_events)
        injection_event_count = sum(
            1 for a in api_events if a.category == ApiCategory.INJECTION or "INJECT" in a.api_name.upper()
        )
        persistence_event_count = sum(
            1 for a in api_events if a.category == ApiCategory.PERSISTENCE
        ) + sum(
            1 for r in reg_events if "RUN" in r.key.upper() or "STARTUP" in r.key.upper()
        )

        service_creation_count = sum(
            1 for a in api_events if a.category == ApiCategory.SERVICE or "SERVICE" in a.api_name.upper()
        )

        suspicious_process_count = sum(
            1 for p in proc_events if any(kw in p.image_name.lower() for kw in ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "certutil.exe"])
        )

        dropped_file_count = sum(
            1 for art in artifacts if art.artifact_type.value in ("DROPPED_FILE", "DROPPED_FILE_METADATA") or art.is_executable
        )

        features: Dict[str, float] = {
            "process_count": float(process_count),
            "child_process_count": float(child_process_count),
            "network_connection_count": float(network_connection_count),
            "dns_query_count": float(dns_query_count),
            "blocked_network_attempt_count": float(blocked_network_attempt_count),
            "filesystem_write_count": float(filesystem_write_count),
            "filesystem_delete_count": float(filesystem_delete_count),
            "registry_write_count": float(registry_write_count),
            "api_event_count": float(api_event_count),
            "injection_event_count": float(injection_event_count),
            "persistence_event_count": float(persistence_event_count),
            "service_creation_count": float(service_creation_count),
            "suspicious_process_count": float(suspicious_process_count),
            "dropped_file_count": float(dropped_file_count),
        }

        # Verify exact schema key ordering and count
        assert len(features) == len(DYNAMIC_FEATURE_NAMES) == 14
        return features
