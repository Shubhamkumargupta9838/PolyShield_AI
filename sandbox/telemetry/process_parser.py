from typing import List, Dict, Any
from datetime import datetime, timezone
from sandbox.models.telemetry import ProcessEvent, ProcessEventType


class ProcessTelemetryParser:
    """Parses raw process telemetry records into normalized ProcessEvent objects."""

    def parse_events(self, raw_records: List[Dict[str, Any]], analysis_start: datetime) -> List[ProcessEvent]:
        events: List[ProcessEvent] = []
        for record in raw_records:
            try:
                event_type_str = record.get("event_type", "PROCESS_CREATE").upper()
                event_type = ProcessEventType(event_type_str) if event_type_str in ProcessEventType.__members__ else ProcessEventType.PROCESS_CREATE

                ts = record.get("timestamp")
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, datetime):
                    dt = ts
                else:
                    dt = analysis_start

                relative_ms = max(0, int((dt - analysis_start).total_seconds() * 1000))

                event = ProcessEvent(
                    timestamp=dt,
                    relative_time_ms=relative_ms,
                    pid=int(record.get("pid", 1000)),
                    parent_pid=int(record["parent_pid"]) if record.get("parent_pid") is not None else None,
                    image_name=str(record.get("image_name", record.get("process_name", "unknown.exe"))),
                    command_line=record.get("command_line"),
                    event_type=event_type,
                    exit_code=int(record["exit_code"]) if record.get("exit_code") is not None else None,
                    integrity_level=record.get("integrity_level"),
                    metadata=record.get("metadata", {})
                )
                events.append(event)
            except Exception:
                continue
        return events
