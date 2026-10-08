from typing import Dict, List, Any


def parse_sandbox_behavior(raw_report: Dict[str, Any]) -> Dict[str, Any]:
    """Normalizes raw sandbox behavior into API traces, process trees, and registry events."""
    return {
        "api_calls": [],
        "file_events": [],
        "registry_events": [],
        "network_events": []
    }
