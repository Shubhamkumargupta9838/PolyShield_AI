from typing import List, Dict, Any
from datetime import datetime, timezone
from sandbox.models.telemetry import ApiEvent, ApiCategory


class ApiTelemetryParser:
    """Parses raw API trace records into normalized ApiEvent objects."""

    def parse_events(self, raw_records: List[Dict[str, Any]], analysis_start: datetime) -> List[ApiEvent]:
        events: List[ApiEvent] = []
        for record in raw_records:
            try:
                cat_str = record.get("category", "PROCESS").upper()
                category = ApiCategory(cat_str) if cat_str in ApiCategory.__members__ else ApiCategory.PROCESS

                ts = record.get("timestamp")
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, datetime):
                    dt = ts
                else:
                    dt = analysis_start

                relative_ms = max(0, int((dt - analysis_start).total_seconds() * 1000))

                event = ApiEvent(
                    timestamp=dt,
                    relative_time_ms=relative_ms,
                    process_id=int(record.get("process_id", 1000)),
                    module=str(record.get("module", "kernel32.dll")),
                    api_name=str(record.get("api_name", "CreateProcessW")),
                    category=category,
                    arguments_hash=record.get("arguments_hash"),
                    result=str(record.get("result", "SUCCESS")),
                    metadata=record.get("metadata", {})
                )
                events.append(event)
            except Exception:
                continue
        return events
