from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, Query, UploadFile, File, status, HTTPException
from backend.app.schemas.scan import (
    CreateScanRequest,
    CreateScanResponse,
    ScanResponse,
    ScanListResponse,
    UpdateScanStatusRequest
)
from backend.app.schemas.report import AnalysisReportResponse
from backend.app.services.scan_service import ScanService
from backend.app.repositories.scan_repository import MongoScanRepository, InMemoryScanRepository
from backend.app.db.mongodb import db
from backend.app.api.dependencies import get_current_user, check_scan_ownership
from backend.app.core.security import validate_file_upload
from analysis.static.schemas import StaticAnalysisResult

router = APIRouter(prefix="/scans", tags=["Scans"])


def get_scan_service() -> ScanService:
    """Dependency provider returning ScanService with live Mongo or fallback repository."""
    if db.client and db.db is not None:
        repo = MongoScanRepository(db)
    else:
        if not hasattr(get_scan_service, "_in_memory_repo"):
            get_scan_service._in_memory_repo = InMemoryScanRepository()
        repo = get_scan_service._in_memory_repo
    return ScanService(repository=repo)


@router.post("", response_model=CreateScanResponse, status_code=status.HTTP_201_CREATED, summary="Create a new scan record")
async def create_scan(
    payload: CreateScanRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Creates a new scan record for a Windows PE executable attached to the authenticated owner.
    """
    return await service.create_scan(payload, current_user=current_user)


@router.get("", response_model=ScanListResponse, summary="List paginated scan records")
async def list_scans(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=10, ge=1, le=100, description="Items per page"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Retrieves paginated scan metadata records.
    """
    return await service.list_scans(page=page, page_size=page_size)


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get scan details by ID")
async def get_scan_status(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Retrieves scan metadata and current status by scan_id after verifying scan ownership.
    """
    scan = await service.get_scan(scan_id)
    await check_scan_ownership(scan.model_dump(), current_user)
    return scan


@router.patch("/{scan_id}/status", response_model=ScanResponse, summary="Update scan lifecycle status")
async def update_scan_status(
    scan_id: str,
    payload: UpdateScanStatusRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Updates the lifecycle status of an existing scan record after verifying scan ownership.
    """
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    return await service.update_scan_status(
        scan_id=scan_id,
        target_status=payload.status,
        error_information=payload.error_information
    )


@router.post("/{scan_id}/static-analysis", response_model=StaticAnalysisResult, summary="Perform Static PE Analysis on uploaded file")
async def perform_static_analysis(
    scan_id: str,
    file: UploadFile = File(..., description="Windows PE executable (.exe, .dll)"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Performs pure static PE analysis on uploaded file bytes after verifying file upload rules and scan ownership.
    """
    validate_file_upload(file)
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)

    file_bytes = await file.read()
    filename = file.filename or "uploaded_pe_sample.exe"

    return await service.perform_static_analysis(
        scan_id=scan_id,
        file_bytes=file_bytes,
        filename=filename
    )


@router.post("/{scan_id}/analyze", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED, summary="Enqueue Asynchronous Phase 7 Static ML Analysis Task")
async def analyze_pe_scan(
    scan_id: str,
    file: UploadFile = File(..., description="Windows PE executable (.exe, .dll, .sys)"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Phase 7 & Phase 13 Asynchronous Upload Endpoint:
    Validates binary upload bounds, verifies scan ownership, attaches owner_id, stores payload safely,
    and enqueues Celery task.
    """
    validate_file_upload(file)
    file_bytes = await file.read()
    filename = file.filename or "uploaded_pe_sample.exe"

    return await service.enqueue_scan_analysis(
        scan_id=scan_id,
        file_bytes=file_bytes,
        filename=filename,
        current_user=current_user
    )
