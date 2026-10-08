import json
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from sandbox.models.telemetry import (
    ProcessEvent,
    NetworkEvent,
    DNSEvent,
    FilesystemEvent,
    RegistryEvent,
    ApiEvent,
)
from sandbox.models.sandbox_result import DynamicAnalysisResult
from sandbox.models.artifact import SandboxArtifact
from sandbox.telemetry.process_parser import ProcessTelemetryParser
from sandbox.telemetry.network_parser import NetworkTelemetryParser
from sandbox.telemetry.filesystem_parser import FilesystemTelemetryParser
from sandbox.telemetry.registry_parser import RegistryTelemetryParser
from sandbox.telemetry.api_parser import ApiTelemetryParser


class TelemetryNormalizer:
    """
    Normalizes heterogeneous raw telemetry output into structured event arrays,
    relative time sequences (`relative_time_ms`), cryptographic telemetry hash,
    and populates canonical DynamicAnalysisResult models for Phase 9 & Phase 10 consumption.
    """

    def __init__(self):
        self.process_parser = ProcessTelemetryParser()
        self.network_parser = NetworkTelemetryParser()
        self.filesystem_parser = FilesystemTelemetryParser()
        self.registry_parser = RegistryTelemetryParser()
        self.api_parser = ApiTelemetryParser()

    def normalize(
        self,
        job_id: str,
        scan_id: str,
        sample_sha256: str,
        provider_name: str,
        environment_id: str,
        started_at: datetime,
        completed_at: datetime,
        raw_telemetry: Dict[str, Any],
        artifacts: Optional[List[SandboxArtifact]] = None
    ) -> DynamicAnalysisResult:
        analysis_start = started_at or datetime.now(timezone.utc)
        duration_sec = (completed_at - analysis_start).total_seconds() if completed_at else 0.0

        proc_events = self.process_parser.parse_events(raw_telemetry.get("processes", []), analysis_start)
        net_events, dns_events = self.network_parser.parse_events(raw_telemetry.get("network", []), analysis_start)
        fs_events = self.filesystem_parser.parse_events(raw_telemetry.get("filesystem", []), analysis_start)
        reg_events = self.registry_parser.parse_events(raw_telemetry.get("registry", []), analysis_start)
        api_events = self.api_parser.parse_events(raw_telemetry.get("api_traces", []), analysis_start)

        # Generate canonical chronological event sequence representation for Phase 10 LSTM
        chronological_sequence = self._build_event_sequence(proc_events, net_events, dns_events, fs_events, reg_events, api_events)

        # Compute cryptographic hash of normalized telemetry JSON payload
        telemetry_bytes = json.dumps(chronological_sequence, default=str, sort_keys=True).encode("utf-8")
        telemetry_sha256 = hashlib.sha256(telemetry_bytes).hexdigest()

        art_list = artifacts or []
        art_refs = [art.storage_reference for art in art_list]

        result = DynamicAnalysisResult(
            job_id=job_id,
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            provider=provider_name,
            environment_id=environment_id,
            started_at=analysis_start,
            completed_at=completed_at,
            duration_seconds=max(0.0, duration_sec),
            process_events=proc_events,
            network_events=net_events,
            dns_events=dns_events,
            filesystem_events=fs_events,
            registry_events=reg_events,
            api_events=api_events,
            artifacts=art_list,
            artifact_references=art_refs,
            telemetry_sha256=telemetry_sha256
        )

        return result

    def _build_event_sequence(
        self,
        proc_events: List[ProcessEvent],
        net_events: List[NetworkEvent],
        dns_events: List[DNSEvent],
        fs_events: List[FilesystemEvent],
        reg_events: List[RegistryEvent],
        api_events: List[ApiEvent]
    ) -> List[Dict[str, Any]]:
        seq: List[Dict[str, Any]] = []

        for p in proc_events:
            seq.append({"relative_time_ms": p.relative_time_ms, "type": "PROCESS", "action": p.event_type.value, "detail": p.image_name})
        for n in net_events:
            seq.append({"relative_time_ms": n.relative_time_ms, "type": "NETWORK", "action": n.action.value, "detail": f"{n.dst_ip}:{n.dst_port}"})
        for d in dns_events:
            seq.append({"relative_time_ms": d.relative_time_ms, "type": "DNS", "action": d.action, "detail": d.query})
        for f in fs_events:
            seq.append({"relative_time_ms": f.relative_time_ms, "type": "FILESYSTEM", "action": f.operation.value, "detail": f.path})
        for r in reg_events:
            seq.append({"relative_time_ms": r.relative_time_ms, "type": "REGISTRY", "action": r.operation.value, "detail": r.key})
        for a in api_events:
            seq.append({"relative_time_ms": a.relative_time_ms, "type": "API", "action": a.category.value, "detail": f"{a.module}!{a.api_name}"})

        # Sort chronologically by relative_time_ms
        seq.sort(key=lambda x: x["relative_time_ms"])
        return seq
