"""REST API Router for Multimodal Ensemble Inference (Phase 11 & Phase 13)."""

from typing import Dict, Any
from fastapi import APIRouter, Depends, status

from backend.app.services.scan_service import ScanService
from backend.app.api.scans import get_scan_service
from backend.app.services.ensemble_service import EnsembleService
from backend.app.api.dependencies import get_current_user, check_scan_ownership
from backend.app.core.logging import logger

router = APIRouter(prefix="/scans", tags=["Multimodal Ensemble Inference"])


def get_ensemble_service(scan_svc: ScanService = Depends(get_scan_service)) -> EnsembleService:
    """Dependency provider returning EnsembleService configured with the active scan repository."""
    return EnsembleService(repository=scan_svc.repository)


@router.post(
    "/{scan_id}/ensemble-inference",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Execute Static + Dynamic Multimodal Ensemble Inference"
)
async def run_ensemble_inference(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    scan_svc: ScanService = Depends(get_scan_service),
    service: EnsembleService = Depends(get_ensemble_service)
) -> Dict[str, Any]:
    """
    Executes Phase 11 Multimodal Ensemble Inference for scan_id after verifying scan ownership.
    """
    existing = await scan_svc.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    logger.info(f"Received request for multimodal ensemble inference for scan_id='{scan_id}' by '{current_user.get('user_id')}'")
    return await service.predict_ensemble_for_scan(scan_id=scan_id)


@router.get(
    "/{scan_id}/ensemble-inference",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Multimodal Ensemble Inference Result"
)
async def get_ensemble_inference(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    scan_svc: ScanService = Depends(get_scan_service),
    service: EnsembleService = Depends(get_ensemble_service)
) -> Dict[str, Any]:
    """Retrieves completed multimodal ensemble prediction result for scan_id after verifying scan ownership."""
    existing = await scan_svc.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    return await service.get_ensemble_inference_report(scan_id=scan_id)
