from typing import Dict, Any, Optional


class SandboxClient:
    """Client integration interface for isolated CAPE Sandbox."""
    def __init__(self, api_url: str, api_token: Optional[str] = None):
        self.api_url = api_url
        self.api_token = api_token

    def submit_sample(self, file_path: str) -> str:
        """Submits sample to isolated sandbox environment."""
        return "task_stub_123"

    def get_report(self, task_id: str) -> Dict[str, Any]:
        """Retrieves raw execution telemetry report."""
        return {"task_id": task_id, "status": "completed"}
