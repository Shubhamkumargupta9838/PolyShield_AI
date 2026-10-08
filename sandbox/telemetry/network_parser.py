from typing import List, Dict, Any, Tuple
from datetime import datetime, timezone
from sandbox.models.telemetry import NetworkEvent, NetworkAction, DNSEvent


class NetworkTelemetryParser:
    """Parses raw network telemetry logs/PCAP entries into normalized NetworkEvent & DNSEvent objects."""

    def parse_events(self, raw_records: List[Dict[str, Any]], analysis_start: datetime) -> Tuple[List[NetworkEvent], List[DNSEvent]]:
        network_events: List[NetworkEvent] = []
        dns_events: List[DNSEvent] = []

        for record in raw_records:
            try:
                action_str = record.get("action", "BLOCKED").upper()
                action = NetworkAction(action_str) if action_str in NetworkAction.__members__ else NetworkAction.BLOCKED

                ts = record.get("timestamp")
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                elif isinstance(ts, datetime):
                    dt = ts
                else:
                    dt = analysis_start

                relative_ms = max(0, int((dt - analysis_start).total_seconds() * 1000))

                if record.get("domain") or action == NetworkAction.DNS_QUERY:
                    dns_event = DNSEvent(
                        timestamp=dt,
                        relative_time_ms=relative_ms,
                        query=str(record.get("domain", record.get("query", "unknown.domain"))),
                        record_type=str(record.get("record_type", "A")),
                        response=record.get("response"),
                        action=str(record.get("dns_action", "sinkholed")),
                        metadata=record.get("metadata", {})
                    )
                    dns_events.append(dns_event)

                net_event = NetworkEvent(
                    timestamp=dt,
                    relative_time_ms=relative_ms,
                    protocol=str(record.get("protocol", "TCP")),
                    direction=str(record.get("direction", "outbound")),
                    src_ip=record.get("src_ip", "192.168.56.10"),
                    src_port=int(record["src_port"]) if record.get("src_port") is not None else 49152,
                    dst_ip=record.get("dst_ip"),
                    dst_port=int(record["dst_port"]) if record.get("dst_port") is not None else None,
                    domain=record.get("domain"),
                    bytes_sent=int(record.get("bytes_sent", 0)),
                    bytes_received=int(record.get("bytes_received", 0)),
                    action=action,
                    metadata=record.get("metadata", {})
                )
                network_events.append(net_event)
            except Exception:
                continue

        return network_events, dns_events
