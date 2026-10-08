from typing import List, Dict, Any
from datetime import datetime, timezone
from sandbox.models.telemetry import FilesystemEvent, FilesystemOperation


class FilesystemTelemetryParser:
    """Parses raw filesystem telemetry records into normalized FilesystemEvent objects."""

    def parse_events(self, raw_records: List[Dict[str, Any]], analysis_start: datetime) -> List[FilesystemEvent]:
        events: List[FilesystemEvent] = []
        for record in raw_records:
            try:
                op_str = record.get("operation", "WRITE").upper()
                op = FilesystemOperation(op_str) if op_str in FilesystemOperation.__members__ else FilesystemOperation.WRITE

                ts = record.get("timestamp")
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, datetime):
                    dt = ts
                else:
                    dt = analysis_start

                relative_ms = max(0, int((dt - analysis_start).total_seconds() * 1000))

                event = FilesystemEvent(
                    timestamp=dt,
                    relative_time_ms=relative_ms,
                    operation=op,
                    path=str(record.get("path", "C:\\Windows\\Temp\\unknown.tmp")),
                    process_id=int(record["process_id"]) if record.get("process_id") is not None else None,
                    result=str(record.get("result", "SUCCESS")),
                    sha256=record.get("sha256"),
                    size=int(record["size"]) if record.get("size") is not None else None,
                    metadata=record.get("metadata", {})
                )
                events.append(event)
            except Exception:
                continue
        return events
