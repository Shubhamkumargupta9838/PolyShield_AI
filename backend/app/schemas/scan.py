from enum import Enum
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    FEATURE_EXTRACTION = "FEATURE_EXTRACTION"
    ML_INFERENCE = "ML_INFERENCE"
    REPORT_GENERATION = "REPORT_GENERATION"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CreateScanRequest(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255, description="Uploaded PE filename")
    file_hash: Optional[str] = Field(None, max_length=64, description="Optional SHA-256 hash of executable")
    file_size: Optional[int] = Field(None, ge=0, description="Size in bytes")


class CreateScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    created_at: datetime
    owner_id: Optional[str] = None


class UpdateScanStatusRequest(BaseModel):
    status: ScanStatus = Field(..., description="Target status in scan lifecycle")
    error_information: Optional[str] = Field(None, max_length=1000, description="Detailed error payload if status is FAILED")


class ScanResponse(BaseModel):
    scan_id: str
    filename: str
    file_hash: Optional[str] = None
    file_size: Optional[int] = None
    status: ScanStatus = ScanStatus.QUEUED
    owner_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    static_analysis_reference: Optional[str] = None
    dynamic_analysis_reference: Optional[str] = None
    feature_reference: Optional[str] = None
    prediction_reference: Optional[str] = None
    report_reference: Optional[str] = None
    model_version: Optional[str] = None
    error: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int
    total_pages: int
