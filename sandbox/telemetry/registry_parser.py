from typing import List, Dict, Any
from datetime import datetime, timezone
from sandbox.models.telemetry import RegistryEvent, RegistryOperation


class RegistryTelemetryParser:
    """Parses raw registry telemetry records into normalized RegistryEvent objects."""

    def parse_events(self, raw_records: List[Dict[str, Any]], analysis_start: datetime) -> List[RegistryEvent]:
        events: List[RegistryEvent] = []
        for record in raw_records:
            try:
                op_str = record.get("operation", "SET_VALUE").upper()
                op = RegistryOperation(op_str) if op_str in RegistryOperation.__members__ else RegistryOperation.SET_VALUE

                ts = record.get("timestamp")
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, datetime):
                    dt = ts
                else:
                    dt = analysis_start

                relative_ms = max(0, int((dt - analysis_start).total_seconds() * 1000))

                event = RegistryEvent(
                    timestamp=dt,
                    relative_time_ms=relative_ms,
                    operation=op,
                    key=str(record.get("key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")),
                    value_name=record.get("value_name"),
                    value_type=record.get("value_type"),
                    process_id=int(record["process_id"]) if record.get("process_id") is not None else None,
                    result=str(record.get("result", "SUCCESS")),
                    metadata=record.get("metadata", {})
                )
                events.append(event)
            except Exception:
                continue
        return events
