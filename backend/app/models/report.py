from typing import Dict, Any


class ReportModel:
    """Database model stub for Analysis Report records."""
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.classification = "BENIGN"
        self.risk_score = 0.0
