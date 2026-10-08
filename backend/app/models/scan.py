from typing import Optional, Dict, Any
from datetime import datetime


class ScanModel:
    """Database model stub for Scan records."""
    def __init__(self, scan_id: str, filename: str):
        self.scan_id = scan_id
        self.filename = filename
        self.status = "QUEUED"
        self.created_at = datetime.utcnow()
