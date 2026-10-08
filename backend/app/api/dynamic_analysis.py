from typing import Dict, Any
from fastapi import APIRouter, Depends, status
from backend.app.schemas.scan import ScanResponse
from backend.app.services.scan_service import ScanService
from backend.app.api.scans import get_scan_service
from backend.app.api.dependencies import get_current_user, check_scan_ownership
from backend.app.core.logging import logger

router = APIRouter(prefix="/scans", tags=["Dynamic Sandbox Analysis"])


@router.post(
    "/{scan_id}/dynamic-analysis",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue Dynamic Sandbox Analysis (Non-Blocking)"
)
async def start_dynamic_analysis(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
) -> ScanResponse:
    """
    Enqueues Phase 9 dynamic sandbox analysis job for scan_id after verifying scan ownership.
    """
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    logger.info(f"Received request to start dynamic analysis for scan_id='{scan_id}' by '{current_user.get('user_id')}'")
    return await service.enqueue_dynamic_analysis(scan_id=scan_id)


@router.get(
    "/{scan_id}/dynamic-analysis",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Dynamic Analysis Results & Telemetry Summary"
)
async def get_dynamic_analysis_result(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
) -> Dict[str, Any]:
    """Retrieves persisted dynamic analysis result for scan_id after verifying scan ownership."""
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    doc = await service.get_dynamic_analysis_report(scan_id=scan_id)
    return {
        "scan_id": scan_id,
        "dynamic_result": doc.get("dynamic_result"),
        "dynamic_features": doc.get("dynamic_features")
    }


@router.get(
    "/{scan_id}/dynamic-analysis/artifacts",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Dynamic Analysis Telemetry Artifacts"
)
async def get_dynamic_analysis_artifacts(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
) -> Dict[str, Any]:
    """Retrieves dynamic analysis artifact metadata for scan_id after verifying scan ownership."""
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    doc = await service.get_dynamic_analysis_report(scan_id=scan_id)
    dyn_result = doc.get("dynamic_result", {})
    return {
        "scan_id": scan_id,
        "artifact_count": len(dyn_result.get("artifacts", [])),
        "artifact_references": dyn_result.get("artifact_references", []),
        "artifacts": dyn_result.get("artifacts", [])
    }


@router.post(
    "/{scan_id}/dynamic-inference",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Run LSTM Dynamic Behavioral Sequence Model Inference"
)
async def run_dynamic_inference(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
) -> Dict[str, Any]:
    """
    Executes Phase 10 Dynamic LSTM Sequence Classifier on telemetry after verifying scan ownership.
    """
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    logger.info(f"Received request for dynamic sequence model inference for scan_id='{scan_id}'")
    return await service.predict_dynamic_inference(scan_id=scan_id)


@router.get(
    "/{scan_id}/dynamic-inference",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve Dynamic LSTM Model Inference Prediction"
)
async def get_dynamic_inference(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user),
    service: ScanService = Depends(get_scan_service)
) -> Dict[str, Any]:
    """Retrieves completed dynamic LSTM sequence inference prediction for scan_id after verifying scan ownership."""
    existing = await service.get_scan(scan_id)
    await check_scan_ownership(existing.model_dump(), current_user)
    return await service.get_dynamic_inference_report(scan_id=scan_id)
