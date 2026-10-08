from typing import Dict, Any
from fastapi import APIRouter, Depends, status
from backend.app.schemas.report import AnalysisReportResponse
from backend.app.services.scan_service import ScanService
from backend.app.api.scans import get_scan_service
from backend.app.api.dependencies import get_current_user, check_scan_ownership

router = APIRouter(prefix="/scans", tags=["Reports"])


@router.get("/{scan_id}/report", response_model=AnalysisReportResponse, summary="Get completed analysis report by scan_id")
async def get_scan_report(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
):
    """
    Retrieves the completed end-to-end static ML analysis report for a given scan_id after verifying scan ownership.
    """
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    return await service.get_scan_report(scan_id)
