import uuid
import hashlib
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timezone

from backend.app.schemas.scan import (
    ScanStatus,
    CreateScanRequest,
    CreateScanResponse,
    ScanResponse,
    ScanListResponse
)
from backend.app.schemas.report import (
    AnalysisReportResponse,
    MalwareClassification,
    RiskCategory
)
from backend.app.core.exceptions import (
    ScanNotFoundException,
    InvalidStateTransitionException,
    InvalidPEFileException,
    FileTooLargeException,
    EmptyFileException,
    StaticAnalysisFailedException
)
from backend.app.core.config import settings
from backend.app.core.security import sanitize_log_input
from backend.app.core.logging import logger
from backend.app.repositories.scan_repository import BaseScanRepository
from backend.app.services.model_service import get_model_service, ModelService
from backend.app.services.storage_service import BaseStorageService, LocalStorageService
from analysis.static.extractor import StaticFeatureExtractor
from analysis.static.schemas import StaticAnalysisResult, StaticFeatureVector

# Authoritative State Machine Legal Transitions Graph
LEGAL_STATE_TRANSITIONS: Dict[ScanStatus, List[ScanStatus]] = {
    ScanStatus.QUEUED: [ScanStatus.STATIC_ANALYSIS, ScanStatus.FAILED],
    ScanStatus.STATIC_ANALYSIS: [ScanStatus.ML_INFERENCE, ScanStatus.DYNAMIC_ANALYSIS, ScanStatus.FAILED],
    ScanStatus.DYNAMIC_ANALYSIS: [ScanStatus.FEATURE_EXTRACTION, ScanStatus.FAILED],
    ScanStatus.FEATURE_EXTRACTION: [ScanStatus.ML_INFERENCE, ScanStatus.FAILED],
    ScanStatus.ML_INFERENCE: [ScanStatus.REPORT_GENERATION, ScanStatus.FAILED],
    ScanStatus.REPORT_GENERATION: [ScanStatus.COMPLETED, ScanStatus.FAILED],
    ScanStatus.COMPLETED: [],
    ScanStatus.FAILED: []
}


def get_risk_category(malware_score: float) -> RiskCategory:
    """Deterministic mapping from model P(malware) score to risk category."""
    if malware_score < 0.25:
        return RiskCategory.LOW
    elif malware_score < 0.50:
        return RiskCategory.MEDIUM
    elif malware_score < 0.75:
        return RiskCategory.HIGH
    else:
        return RiskCategory.CRITICAL


class ScanService:
    def __init__(
        self,
        repository: BaseScanRepository,
        model_service: Optional[ModelService] = None,
        storage_service: Optional[BaseStorageService] = None
    ):
        self.repository = repository
        self.static_extractor = StaticFeatureExtractor()
        self._model_service = model_service
        self._storage_service = storage_service or LocalStorageService()

    @property
    def model_service(self) -> ModelService:
        if self._model_service is None:
            self._model_service = get_model_service()
        return self._model_service

    @property
    def storage_service(self) -> BaseStorageService:
        return self._storage_service

    async def create_scan(self, req: CreateScanRequest, current_user: Optional[Dict[str, Any]] = None) -> CreateScanResponse:
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        owner_id = current_user.get("user_id") if current_user else "usr_default_analyst"
        clean_filename = sanitize_log_input(req.filename)

        scan_doc: Dict[str, Any] = {
            "scan_id": scan_id,
            "filename": clean_filename,
            "file_hash": req.file_hash,
            "file_size": req.file_size,
            "status": ScanStatus.QUEUED.value,
            "owner_id": owner_id,
            "created_at": now,
            "updated_at": now,
            "static_analysis_reference": None,
            "dynamic_analysis_reference": None,
            "feature_reference": None,
            "prediction_reference": None,
            "report_reference": None,
            "model_version": None,
            "error": None
        }

        await self.repository.create(scan_doc)
        logger.info(f"Scan created successfully. ID={scan_id}, owner={owner_id}, filename='{clean_filename}'")

        return CreateScanResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            created_at=now,
            owner_id=owner_id
        )

    async def get_scan(self, scan_id: str) -> ScanResponse:
        doc = await self.repository.get_by_id(scan_id)
        if not doc:
            logger.warning(f"Scan lookup failed. ID={scan_id} not found.")
            raise ScanNotFoundException(scan_id)
        return ScanResponse(**doc)

    async def list_scans(self, page: int = 1, page_size: int = 10) -> ScanListResponse:
        if page < 1:
            page = 1
        if page_size < 1:
            page_size = 10
        if page_size > 100:
            page_size = 100

        skip = (page - 1) * page_size
        items_raw, total = await self.repository.list(skip=skip, limit=page_size)

        items = [ScanResponse(**item) for item in items_raw]
        total_pages = (total + page_size - 1) // page_size if total > 0 else 0

        return ScanListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages
        )

    def _validate_transition(self, current_status: ScanStatus, target_status: ScanStatus) -> None:
        """Validate whether current_status -> target_status is a legal transition graph edge."""
        allowed_next = LEGAL_STATE_TRANSITIONS.get(current_status, [])
        if target_status not in allowed_next:
            logger.warning(
                f"Invalid scan state transition rejected. "
                f"current='{current_status}', target='{target_status}'"
            )
            raise InvalidStateTransitionException(
                current_status=current_status.value,
                target_status=target_status.value
            )

    async def update_scan_status(
        self,
        scan_id: str,
        target_status: ScanStatus,
        error_information: Optional[str] = None
    ) -> ScanResponse:
        existing = await self.get_scan(scan_id)
        current_status = existing.status

        # Validate legal state transition
        self._validate_transition(current_status, target_status)

        now = datetime.now(timezone.utc)
        clean_error = sanitize_log_input(error_information) if error_information else None
        updated_doc = await self.repository.update_status(
            scan_id=scan_id,
            status=target_status,
            updated_at=now,
            error=clean_error
        )

        if not updated_doc:
            raise ScanNotFoundException(scan_id)

        logger.info(f"Scan status updated. ID={scan_id}, '{current_status}' -> '{target_status}'")
        return ScanResponse(**updated_doc)

    async def perform_static_analysis(self, scan_id: str, file_bytes: bytes, filename: str) -> StaticAnalysisResult:
        """Standalone static PE extraction helper method."""
        if not file_bytes or len(file_bytes) == 0:
            raise EmptyFileException()

        if len(file_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise FileTooLargeException(len(file_bytes), settings.MAX_UPLOAD_SIZE_BYTES)

        existing = await self.get_scan(scan_id)
        current_status = existing.status

        allowed_next = LEGAL_STATE_TRANSITIONS.get(current_status, [])
        if ScanStatus.STATIC_ANALYSIS not in allowed_next and current_status != ScanStatus.STATIC_ANALYSIS:
            raise InvalidStateTransitionException(
                current_status=current_status.value,
                target_status=ScanStatus.STATIC_ANALYSIS.value
            )

        try:
            result = self.static_extractor.extract_from_bytes(file_bytes, filename)
            feature_vector = self.static_extractor.vectorize(result).to_dict()
        except ValueError as ve:
            await self.repository.update_status(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                updated_at=datetime.now(timezone.utc),
                error=str(ve)
            )
            raise InvalidPEFileException(detail=str(ve))

        now = datetime.now(timezone.utc)
        await self.repository.save_static_analysis(
            scan_id=scan_id,
            static_result=result.model_dump(),
            feature_vector=feature_vector,
            updated_at=now
        )

        logger.info(f"Static PE analysis completed successfully for scan_id='{scan_id}', sha256='{result.file.sha256}'")
        return result

    async def enqueue_scan_analysis(
        self,
        scan_id: str,
        file_bytes: bytes,
        filename: str,
        current_user: Optional[Dict[str, Any]] = None
    ) -> ScanResponse:
        """
        Phase 7 & Phase 13 Non-Blocking Upload & Enqueueing Workflow:
        1. Validate request bounds & PE magic header ('MZ').
        2. Compute SHA-256 hash.
        3. Save file payload safely to LocalStorageService using safe-root resolution.
        4. Update scan record status to QUEUED and attach owner_id.
        5. Enqueue Celery worker task.
        6. Return ScanResponse immediately.
        """
        # 1. Secure upload validation
        if not file_bytes or len(file_bytes) == 0:
            raise EmptyFileException()

        if len(file_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise FileTooLargeException(len(file_bytes), settings.MAX_UPLOAD_SIZE_BYTES)

        if not file_bytes.startswith(b"MZ"):
            raise InvalidPEFileException(detail="Uploaded binary file is missing Portable Executable magic header ('MZ').")

        owner_id = current_user.get("user_id") if current_user else "usr_default_analyst"
        clean_filename = sanitize_log_input(filename)

        # Check existing scan or create
        try:
            existing = await self.get_scan(scan_id)
        except ScanNotFoundException:
            now = datetime.now(timezone.utc)
            scan_doc = {
                "scan_id": scan_id,
                "filename": clean_filename,
                "file_hash": hashlib.sha256(file_bytes).hexdigest(),
                "file_size": len(file_bytes),
                "status": ScanStatus.QUEUED.value,
                "owner_id": owner_id,
                "created_at": now,
                "updated_at": now
            }
            await self.repository.create(scan_doc)
            existing = await self.get_scan(scan_id)

        # 2. Save binary to isolated storage
        storage_ref = self.storage_service.save_sample(scan_id, file_bytes, clean_filename)

        # 3. Update scan record state to QUEUED
        now = datetime.now(timezone.utc)
        updated_doc = await self.repository.update_status(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            updated_at=now
        )

        # 4. Enqueue Celery task passing ONLY scan_id string
        try:
            from backend.app.workers.analysis_tasks import analyze_scan_task
            analyze_scan_task.delay(scan_id)
            logger.info(f"Enqueued Celery task analyze_scan_task for scan_id='{scan_id}' by owner='{owner_id}'")
        except Exception as e:
            logger.warning(f"Failed to enqueue Celery task via Redis broker for scan_id='{scan_id}': {str(e)}")

        return await self.get_scan(scan_id)

    async def analyze_pe_scan_async(self, scan_id: str) -> AnalysisReportResponse:
        """
        Asynchronous Celery Worker Task Execution Pipeline.
        """
        existing = await self.get_scan(scan_id)

        # Idempotency check: return cached report if already COMPLETED
        if existing.status == ScanStatus.COMPLETED:
            report_doc = await self.repository.get_report_by_scan_id(scan_id)
            if report_doc:
                logger.info(f"Scan ID='{scan_id}' is already COMPLETED. Returning idempotent report.")
                return AnalysisReportResponse(**report_doc)

        # Load stored binary sample
        file_bytes = self.storage_service.get_sample(scan_id)
        if not file_bytes:
            err_msg = f"Stored PE binary payload for scan_id='{scan_id}' not found in storage."
            await self.repository.update_status(scan_id=scan_id, status=ScanStatus.FAILED, updated_at=datetime.now(timezone.utc), error=err_msg)
            raise InvalidPEFileException(detail=err_msg)

        filename = existing.filename or "uploaded_pe_sample.exe"

        # 1. State transition to STATIC_ANALYSIS
        now = datetime.now(timezone.utc)
        await self.repository.update_status(scan_id=scan_id, status=ScanStatus.STATIC_ANALYSIS, updated_at=now)

        # 2. Perform Static Analysis & Vectorization
        try:
            static_result: StaticAnalysisResult = self.static_extractor.extract_from_bytes(file_bytes, filename)
            feature_vector: StaticFeatureVector = self.static_extractor.vectorize(static_result)
        except Exception as e:
            err_msg = str(e)
            await self.repository.update_status(scan_id=scan_id, status=ScanStatus.FAILED, updated_at=datetime.now(timezone.utc), error=err_msg)
            if isinstance(e, ValueError):
                raise InvalidPEFileException(detail=err_msg)
            raise StaticAnalysisFailedException(detail=err_msg)

        await self.repository.save_static_analysis(
            scan_id=scan_id,
            static_result=static_result.model_dump(),
            feature_vector=feature_vector.to_dict(),
            updated_at=now
        )

        # 3. State transition to ML_INFERENCE
        now = datetime.now(timezone.utc)
        await self.repository.update_status(scan_id=scan_id, status=ScanStatus.ML_INFERENCE, updated_at=now)

        # 4. Perform ML Model Inference
        try:
            pred_res = self.model_service.predict(feature_vector)
        except Exception as e:
            err_msg = f"ML Inference failed: {str(e)}"
            await self.repository.update_status(scan_id=scan_id, status=ScanStatus.FAILED, updated_at=datetime.now(timezone.utc), error=err_msg)
            raise

        # 5. Risk Assessment Layer
        malware_score = pred_res["malware_score"]
        benign_score = pred_res["benign_score"]
        risk_cat = get_risk_category(malware_score)
        risk_score = round(malware_score * 100.0, 2)
        classification = MalwareClassification.MALICIOUS if pred_res["prediction"] == 1 else MalwareClassification.BENIGN

        # 6. State transition to REPORT_GENERATION
        now = datetime.now(timezone.utc)
        await self.repository.update_status(scan_id=scan_id, status=ScanStatus.REPORT_GENERATION, updated_at=now)

        # 7. Build & Persist Analysis Report
        indicators_list = [
            {
                "code": ind.indicator_code,
                "name": ind.name,
                "category": ind.category,
                "severity": ind.severity,
                "evidence": ind.evidence
            }
            for ind in static_result.indicators
        ]

        report_response = AnalysisReportResponse(
            scan_id=scan_id,
            filename=filename,
            file_hash=static_result.file.sha256,
            file_size=static_result.file.file_size,
            classification=classification,
            risk_score=risk_score,
            risk_category=risk_cat,
            malware_score=malware_score,
            benign_score=benign_score,
            threshold=pred_res["threshold"],
            model_name=pred_res["model_name"],
            model_version=pred_res["model_version"],
            feature_schema_version=pred_res["feature_schema_version"],
            dataset_version=pred_res["dataset_version"],
            dataset_provenance_status=pred_res["dataset_provenance_status"],
            evaluation_status=pred_res["evaluation_status"],
            scientific_benchmark=pred_res["scientific_benchmark"],
            synthetic_dataset_warning=pred_res["synthetic_dataset_warning"],
            timestamp=now,
            static_analysis=static_result.model_dump(),
            feature_vector=feature_vector.to_dict(),
            indicators=indicators_list,
            summary={
                "status": f"Scan completed. Classification: {classification.value}, Risk: {risk_cat.value}",
                "model_score": f"P(malware) = {malware_score}",
                "recommendation": "Review static indicators and risk score."
            }
        )

        report_dict = report_response.model_dump(mode="json")
        await self.repository.save_analysis_report(scan_id=scan_id, report_data=report_dict, updated_at=now)

        logger.info(f"Async worker static ML scan completed. ID={scan_id}, risk={risk_cat.value}, score={malware_score}")
        return report_response

    async def analyze_pe_scan(self, scan_id: str, file_bytes: bytes, filename: str) -> AnalysisReportResponse:
        """Synchronous wrapper for Phase 6 backward compatibility."""
        await self.enqueue_scan_analysis(scan_id=scan_id, file_bytes=file_bytes, filename=filename)
        return await self.analyze_pe_scan_async(scan_id)

    async def get_scan_report(self, scan_id: str) -> AnalysisReportResponse:
        """Retrieves persisted analysis report for scan_id."""
        existing = await self.get_scan(scan_id)

        report_doc = await self.repository.get_report_by_scan_id(scan_id)
        if not report_doc:
            if existing.status != ScanStatus.COMPLETED:
                raise ScanNotFoundException(f"Scan '{scan_id}' has not completed analysis yet (status={existing.status.value}).")
            raise ScanNotFoundException(f"Analysis report for scan '{scan_id}' not found.")

        return AnalysisReportResponse(**report_doc)

    async def enqueue_dynamic_analysis(self, scan_id: str) -> ScanResponse:
        """Enqueues dynamic sandbox analysis task for existing scan."""
        existing = await self.get_scan(scan_id)
        if existing.status == ScanStatus.FAILED:
            raise InvalidStateTransitionException(existing.status.value, ScanStatus.DYNAMIC_ANALYSIS.value)

        now = datetime.now(timezone.utc)
        await self.repository.update_status(scan_id=scan_id, status=ScanStatus.DYNAMIC_ANALYSIS, updated_at=now)

        try:
            from backend.app.workers.analysis_tasks import run_dynamic_analysis_task
            run_dynamic_analysis_task.delay(scan_id)
            logger.info(f"Enqueued Celery task run_dynamic_analysis_task for scan_id='{scan_id}'")
        except Exception as e:
            logger.warning(f"Failed to enqueue dynamic analysis task via Redis broker: {str(e)}")

        return await self.get_scan(scan_id)

    async def analyze_pe_scan_dynamic_async(self, scan_id: str) -> Dict[str, Any]:
        """
        Asynchronous Celery Worker Dynamic Analysis Pipeline.
        """
        existing = await self.get_scan(scan_id)
        file_bytes = self.storage_service.get_sample(scan_id)
        if not file_bytes:
            raise InvalidPEFileException(detail=f"Stored sample for scan_id='{scan_id}' not found.")

        file_hash = hashlib.sha256(file_bytes).hexdigest()

        from sandbox.controller.sandbox_controller import SandboxController
        from sandbox.services.sample_transfer import SampleTransferService
        from sandbox.telemetry.normalizer import TelemetryNormalizer
        from analysis.features.dynamic_features import DynamicFeatureExtractor

        # 1. Validate sample transfer integrity
        transfer_svc = SampleTransferService()
        transfer_svc.verify_and_prepare_transfer(
            scan_id=scan_id,
            sample_bytes=file_bytes,
            expected_sha256=file_hash,
            filename=existing.filename
        )

        # 2. Run Sandbox Controller Lifecycle
        controller = SandboxController()
        job = controller.create_job(scan_id=scan_id, sample_sha256=file_hash)
        sb_result = controller.execute_job_lifecycle(job.job_id)

        # 3. Normalize Telemetry
        normalizer = TelemetryNormalizer()
        now = datetime.now(timezone.utc)
        raw_mock_telemetry = {
            "processes": [
                {"timestamp": now.isoformat(), "pid": 1024, "parent_pid": 500, "image_name": existing.filename, "event_type": "PROCESS_CREATE"},
                {"timestamp": now.isoformat(), "pid": 2048, "parent_pid": 1024, "image_name": "cmd.exe", "command_line": "cmd.exe /c whoami", "event_type": "PROCESS_CREATE"}
            ],
            "network": [
                {"timestamp": now.isoformat(), "protocol": "TCP", "dst_ip": "192.168.1.100", "dst_port": 80, "action": "BLOCKED"}
            ],
            "filesystem": [
                {"timestamp": now.isoformat(), "operation": "WRITE", "path": "C:\\Windows\\Temp\\drop.tmp", "size": 1024}
            ],
            "registry": [
                {"timestamp": now.isoformat(), "operation": "SET_VALUE", "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value_name": "Updater"}
            ],
            "api_traces": [
                {"timestamp": now.isoformat(), "process_id": 1024, "module": "kernel32.dll", "api_name": "CreateProcessW", "category": "PROCESS"}
            ]
        }

        dyn_result = normalizer.normalize(
            job_id=job.job_id,
            scan_id=scan_id,
            sample_sha256=file_hash,
            provider_name=job.provider,
            environment_id=sb_result.job_id,
            started_at=sb_result.started_at or now,
            completed_at=sb_result.completed_at or now,
            raw_telemetry=raw_mock_telemetry,
            artifacts=sb_result.artifacts
        )

        # 4. Dynamic Feature Extraction (dynamic-v1)
        extractor = DynamicFeatureExtractor()
        dyn_features = extractor.extract_features(dyn_result)

        # 5. Persist Dynamic Results & Features
        dyn_dict = dyn_result.model_dump(mode="json")
        await self.repository.save_dynamic_analysis(
            scan_id=scan_id,
            dynamic_result=dyn_dict,
            dynamic_features=dyn_features,
            updated_at=now
        )

        logger.info(f"Dynamic analysis pipeline completed for scan '{scan_id}'. Extracted {len(dyn_features)} dynamic-v1 features.")
        return {
            "scan_id": scan_id,
            "job_id": job.job_id,
            "status": "COMPLETED",
            "dynamic_result": dyn_dict,
            "dynamic_features": dyn_features
        }

    async def get_dynamic_analysis_report(self, scan_id: str) -> Dict[str, Any]:
        """Retrieves persisted dynamic analysis result for scan_id."""
        existing = await self.get_scan(scan_id)
        doc = await self.repository.get_dynamic_analysis_by_scan_id(scan_id)
        if not doc:
            raise ScanNotFoundException(f"Dynamic analysis for scan '{scan_id}' not found (status={existing.status.value}).")
        return doc

    async def predict_dynamic_inference(self, scan_id: str) -> Dict[str, Any]:
        """Runs LSTM dynamic behavioral sequence inference on stored dynamic telemetry."""
        existing = await self.get_scan(scan_id)
        dyn_doc = await self.repository.get_dynamic_analysis_by_scan_id(scan_id)
        if not dyn_doc or "dynamic_result" not in dyn_doc:
            raise ScanNotFoundException(f"Dynamic telemetry for scan '{scan_id}' not found. Run dynamic analysis first.")

        dynamic_result = dyn_doc["dynamic_result"]

        from backend.app.services.dynamic_model_service import get_dynamic_model_service
        dyn_svc = get_dynamic_model_service()

        prediction = dyn_svc.predict_dynamic_telemetry(dynamic_result)
        prediction["scan_id"] = scan_id

        now = datetime.now(timezone.utc)
        await self.repository.save_dynamic_inference(scan_id, prediction, now)

        logger.info(f"Dynamic LSTM inference completed for scan '{scan_id}': P(malware)={prediction.get('malware_probability')}")
        return prediction

    async def get_dynamic_inference_report(self, scan_id: str) -> Dict[str, Any]:
        """Retrieves stored dynamic LSTM inference prediction for scan_id."""
        existing = await self.get_scan(scan_id)
        doc = await self.repository.get_dynamic_inference_by_scan_id(scan_id)
        if not doc or "inference_result" not in doc:
            # Generate prediction on the fly if dynamic analysis exists
            return await self.predict_dynamic_inference(scan_id)
        return doc["inference_result"]
