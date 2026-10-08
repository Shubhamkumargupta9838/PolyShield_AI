from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class MalwareClassification(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class RiskCategory(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"



class AnalysisReportResponse(BaseModel):
    scan_id: str
    filename: str
    file_hash: str
    file_size: int = 0
    classification: MalwareClassification = MalwareClassification.BENIGN
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    risk_category: RiskCategory = RiskCategory.LOW
    malware_score: float = Field(default=0.0, ge=0.0, le=1.0)
    benign_score: float = Field(default=1.0, ge=0.0, le=1.0)
    threshold: float = 0.5
    model_name: str = "static_baseline_v2.0"
    model_version: str = "static-baseline-v1"
    feature_schema_version: str = "static-v1"
    dataset_version: str = "v2.0"
    dataset_provenance_status: str = "SYNTHETIC_FIXTURE"
    evaluation_status: str = "ENGINEERING_SMOKE_EVALUATION"
    scientific_benchmark: bool = False
    synthetic_dataset_warning: str = (
        "Engineering Evaluation Model: This model was trained using synthetic/safe PE fixtures "
        "and has not been validated as a real-world malware detector."
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    static_analysis: Optional[Dict[str, Any]] = None
    feature_vector: Optional[Dict[str, float]] = None
    indicators: List[Dict[str, Any]] = []
    explanations: List[Dict[str, Any]] = []
    summary: Dict[str, Any] = {}

