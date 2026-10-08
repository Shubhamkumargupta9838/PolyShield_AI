import asyncio
import re
import concurrent.futures
from celery.signals import worker_process_init
from backend.app.workers.celery_app import celery_app
from backend.app.core.logging import logger
from backend.app.repositories.scan_repository import MongoScanRepository, InMemoryScanRepository
from backend.app.db.mongodb import db, connect_to_mongo
from backend.app.services.scan_service import ScanService
from backend.app.core.exceptions import PolyShieldException, ScanNotFoundException


@worker_process_init.connect
def init_worker_process(**kwargs):
    """Initialize worker process configuration."""
    logger.info("[Celery Worker Process] Worker process initialized.")


async def async_get_worker_scan_service() -> ScanService:
    """
    Async provider returning ScanService with live Mongo connection established for the current event loop.
    Ensures workers connect to MongoDB in the active task loop before querying scan documents.
    """
    await connect_to_mongo()

    if db.client and db.db is not None:
        repo = MongoScanRepository(db)
    else:
        from backend.app.api.scans import get_scan_service
        if hasattr(get_scan_service, "_in_memory_repo"):
            repo = get_scan_service._in_memory_repo
        else:
            if not hasattr(_get_worker_scan_service, "_in_memory_repo"):
                _get_worker_scan_service._in_memory_repo = InMemoryScanRepository()
            repo = _get_worker_scan_service._in_memory_repo
    return ScanService(repository=repo)



def _get_worker_scan_service() -> ScanService:
    """Helper provider returning ScanService with live Mongo or fallback repository for workers."""
    if db.client and db.db is not None:
        repo = MongoScanRepository(db)
    else:
        from backend.app.api.scans import get_scan_service
        if hasattr(get_scan_service, "_in_memory_repo"):
            repo = get_scan_service._in_memory_repo
        else:
            if not hasattr(_get_worker_scan_service, "_in_memory_repo"):
                _get_worker_scan_service._in_memory_repo = InMemoryScanRepository()
            repo = _get_worker_scan_service._in_memory_repo
    return ScanService(repository=repo)


def _validate_worker_scan_id(scan_id: str) -> str:
    """
    Worker task security boundary validation.
    Rejects malformed scan_id task arguments containing path traversal or illegal characters.
    """
    if not isinstance(scan_id, str):
        raise ValueError(f"Task scan_id must be a string, got {type(scan_id)}")
    if not scan_id or ".." in scan_id or "/" in scan_id or "\\" in scan_id or "\x00" in scan_id:
        raise ValueError(f"Invalid or unsafe scan_id task argument: '{scan_id}'")
    return scan_id.strip()


async def _execute_analyze_scan_pipeline(scan_id: str):
    service = await async_get_worker_scan_service()
    return await service.analyze_pe_scan_async(scan_id)


@celery_app.task(name="analyze_scan_task", bind=True, max_retries=3)
def analyze_scan_task(self, scan_id: str):
    """
    Celery worker task for executing Phase 7 static PE analysis and ML inference.
    Validates scan_id task input before processing.
    """
    try:
        clean_scan_id = _validate_worker_scan_id(scan_id)
    except ValueError as ve:
        logger.error(f"[Celery Worker] Invalid task payload: {str(ve)}")
        return {"scan_id": scan_id, "status": "FAILED", "error": str(ve)}

    logger.info(f"[Celery Worker] Processing scan_id='{clean_scan_id}', task_id='{self.request.id}'")

    try:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_execute_analyze_scan_pipeline(clean_scan_id)))
                report = future.result()
        else:
            report = asyncio.run(_execute_analyze_scan_pipeline(clean_scan_id))

        logger.info(f"[Celery Worker] Successfully completed scan_id='{clean_scan_id}', risk={report.risk_category}")
        return {"scan_id": clean_scan_id, "status": "COMPLETED"}
    except (ValueError, PolyShieldException) as e:
        logger.error(f"[Celery Worker] Non-retryable error for scan_id='{clean_scan_id}': {str(e)}")
        return {"scan_id": clean_scan_id, "status": "FAILED", "error": str(e)}
    except Exception as e:
        logger.warning(f"[Celery Worker] Transient error for scan_id='{clean_scan_id}' (attempt {self.request.retries + 1}/3): {str(e)}")
        try:
            raise self.retry(exc=e, countdown=2 ** self.request.retries)
        except self.MaxRetriesExceededError:
            logger.error(f"[Celery Worker] Max retries exceeded for scan_id='{clean_scan_id}'")
            return {"scan_id": clean_scan_id, "status": "FAILED", "error": "Max retries exceeded"}


async def _execute_dynamic_analysis_pipeline(scan_id: str):
    service = await async_get_worker_scan_service()
    return await service.analyze_pe_scan_dynamic_async(scan_id)


@celery_app.task(name="run_dynamic_analysis_task", bind=True, max_retries=3)
def run_dynamic_analysis_task(self, scan_id: str):
    """
    Celery worker task for executing Phase 9 Dynamic Sandbox analysis & feature extraction.
    """
    try:
        clean_scan_id = _validate_worker_scan_id(scan_id)
    except ValueError as ve:
        logger.error(f"[Celery Worker Dynamic] Invalid task payload: {str(ve)}")
        return {"scan_id": scan_id, "status": "FAILED", "error": str(ve)}

    logger.info(f"[Celery Worker Dynamic] Processing dynamic analysis scan_id='{clean_scan_id}'")

    try:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_execute_dynamic_analysis_pipeline(clean_scan_id)))
                res = future.result()
        else:
            res = asyncio.run(_execute_dynamic_analysis_pipeline(clean_scan_id))

        logger.info(f"[Celery Worker Dynamic] Completed dynamic analysis scan_id='{clean_scan_id}'")
        return res
    except Exception as e:
        logger.error(f"[Celery Worker Dynamic] Error processing dynamic scan_id='{clean_scan_id}': {str(e)}")
        return {"scan_id": clean_scan_id, "status": "FAILED", "error": str(e)}


async def _execute_dynamic_inference_pipeline(scan_id: str):
    service = await async_get_worker_scan_service()
    return await service.predict_dynamic_inference(scan_id)


@celery_app.task(name="run_dynamic_inference_task", bind=True, max_retries=3)
def run_dynamic_inference_task(self, scan_id: str):
    """
    Celery worker task for executing Phase 10 Dynamic LSTM Sequence Inference.
    """
    try:
        clean_scan_id = _validate_worker_scan_id(scan_id)
    except ValueError as ve:
        return {"scan_id": scan_id, "status": "FAILED", "error": str(ve)}

    logger.info(f"[Celery Worker Dynamic Inference] Processing scan_id='{clean_scan_id}'")

    try:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_execute_dynamic_inference_pipeline(clean_scan_id)))
                res = future.result()
        else:
            res = asyncio.run(_execute_dynamic_inference_pipeline(clean_scan_id))

        logger.info(f"[Celery Worker Dynamic Inference] Completed scan_id='{clean_scan_id}'")
        return res
    except Exception as e:
        logger.error(f"[Celery Worker Dynamic Inference] Error processing scan_id='{clean_scan_id}': {str(e)}")
        return {"scan_id": clean_scan_id, "status": "FAILED", "error": str(e)}


async def _execute_ensemble_inference_pipeline(scan_id: str):
    service = await async_get_worker_scan_service()
    from backend.app.services.ensemble_service import EnsembleService
    ens_svc = EnsembleService(repository=service.repository)
    return await ens_svc.predict_ensemble_for_scan(scan_id)


@celery_app.task(name="run_ensemble_inference_task", bind=True, max_retries=3)
def run_ensemble_inference_task(self, scan_id: str):
    """
    Celery worker task for executing Phase 11 Multimodal Ensemble Inference.
    """
    try:
        clean_scan_id = _validate_worker_scan_id(scan_id)
    except ValueError as ve:
        return {"scan_id": scan_id, "status": "FAILED", "error": str(ve)}

    logger.info(f"[Celery Worker Ensemble] Processing scan_id='{clean_scan_id}'")

    try:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_execute_ensemble_inference_pipeline(clean_scan_id)))
                res = future.result()
        else:
            res = asyncio.run(_execute_ensemble_inference_pipeline(clean_scan_id))

        logger.info(f"[Celery Worker Ensemble] Completed scan_id='{clean_scan_id}'")
        return res
    except Exception as e:
        logger.error(f"[Celery Worker Ensemble] Error processing scan_id='{clean_scan_id}': {str(e)}")
        return {"scan_id": clean_scan_id, "status": "FAILED", "error": str(e)}


async def _execute_explanation_pipeline(scan_id: str):
    service = await async_get_worker_scan_service()
    from backend.app.services.explanation_service import ExplanationService
    exp_svc = ExplanationService(repository=service.repository)
    return await exp_svc.generate_explanation_for_scan(scan_id)


@celery_app.task(name="run_explanation_task", bind=True, max_retries=3)
def run_explanation_task(self, scan_id: str):
    """
    Celery worker task for executing Phase 12 Explainable AI generation.
    """
    try:
        clean_scan_id = _validate_worker_scan_id(scan_id)
    except ValueError as ve:
        return {"scan_id": scan_id, "status": "FAILED", "error": str(ve)}

    logger.info(f"[Celery Worker Explanation] Processing scan_id='{clean_scan_id}'")

    try:
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop and running_loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(lambda: asyncio.run(_execute_explanation_pipeline(clean_scan_id)))
                res = future.result()
        else:
            res = asyncio.run(_execute_explanation_pipeline(clean_scan_id))

        logger.info(f"[Celery Worker Explanation] Completed scan_id='{clean_scan_id}'")
        return res
    except Exception as e:
        logger.error(f"[Celery Worker Explanation] Error processing scan_id='{clean_scan_id}': {str(e)}")
        return {"scan_id": clean_scan_id, "status": "FAILED", "error": str(e)}

