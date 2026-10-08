"""REST API Router for Explainable AI & SHAP Attributions (Phase 12 & Phase 13)."""

import logging
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.services.scan_service import ScanService
from backend.app.api.scans import get_scan_service
from backend.app.services.explanation_service import ExplanationService
from backend.app.api.dependencies import get_current_user, check_scan_ownership
from backend.app.core.exceptions import ScanNotFoundException, PolyShieldException

logger = logging.getLogger("polyshield.explanation_router")

router = APIRouter(prefix="/scans", tags=["Explainability"])


def get_explanation_service(
    scan_service: ScanService = Depends(get_scan_service),
) -> ExplanationService:
    """Dependency injector for ExplanationService."""
    return ExplanationService(repository=scan_service.repository)


@router.post(
    "/{scan_id}/explanation",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Generate Explainable AI Report",
    description="Computes local static SHAP attributions, dynamic sequence attributions, observed evidence, and ensemble component decomposition.",
)
async def generate_explanation(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    scan_svc: ScanService = Depends(get_scan_service),
    service: ExplanationService = Depends(get_explanation_service),
):
    """Triggers or retrieves XAI explanation report for a scan after verifying scan ownership."""
    existing = await scan_svc.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    try:
        return await service.generate_explanation_for_scan(scan_id=scan_id)
    except ScanNotFoundException as snf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(snf.message if hasattr(snf, 'message') else snf))
    except PolyShieldException as pse:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(pse.message if hasattr(pse, 'message') else pse))
    except Exception as e:
        logger.exception(f"Unhandled error in explanation generation for scan '{scan_id}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during explanation generation.")


@router.get(
    "/{scan_id}/explanation",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Explanation Report",
    description="Retrieves persisted XAI attribution report for a scan.",
)
async def get_explanation(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    scan_svc: ScanService = Depends(get_scan_service),
    service: ExplanationService = Depends(get_explanation_service),
):
    """Retrieves persisted XAI explanation report for a scan after verifying scan ownership."""
    existing = await scan_svc.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    try:
        return await service.get_explanation_report(scan_id=scan_id)
    except ScanNotFoundException as snf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(snf.message if hasattr(snf, 'message') else snf))
    except PolyShieldException as pse:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(pse.message if hasattr(pse, 'message') else pse))
    except Exception as e:
        logger.exception(f"Unhandled error retrieving explanation for scan '{scan_id}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred retrieving explanation report.")
