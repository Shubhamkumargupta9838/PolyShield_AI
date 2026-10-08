"""Backend Ensemble Service (Phase 11).

Orchestrates multimodal ensemble prediction execution, prediction document loading,
version compatibility validation, and repository persistence.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from ml.models.ensemble import MultimodalEnsembleModel
from ml.models.prediction_schema import PredictionResult, EnsembleMode, ENSEMBLE_VERSION
from backend.app.repositories.scan_repository import BaseScanRepository
from backend.app.core.exceptions import ScanNotFoundException, PolyShieldException

logger = logging.getLogger("polyshield.ensemble_service")


class EnsembleService:
    """Service managing multimodal static + dynamic ensemble predictions."""

    _instance: Optional["EnsembleService"] = None

    def __init__(
        self,
        repository: BaseScanRepository,
        static_weight: float = 0.5,
        dynamic_weight: float = 0.5,
    ):
        self.repository = repository
        self.ensemble_model = MultimodalEnsembleModel(
            static_weight=static_weight,
            dynamic_weight=dynamic_weight,
        )

    async def predict_ensemble_for_scan(self, scan_id: str) -> Dict[str, Any]:
        """Execute multimodal ensemble prediction for a scan_id by fetching static & dynamic predictions.

        Enforces strict missing-modality handling and compatibility validation.
        """
        # 1. Fetch scan metadata
        scan_doc = await self.repository.get_by_id(scan_id)
        if not scan_doc:
            raise ScanNotFoundException(scan_id)

        sample_sha256 = scan_doc.get("file_hash") or "0" * 64

        # 2. Fetch static report if available
        static_report = await self.repository.get_report_by_scan_id(scan_id)
        static_prob: Optional[float] = None
        static_version: str = "static_baseline_v2.0"

        if static_report:
            static_prob = static_report.get("malware_score")
            static_version = static_report.get("model_version", "static_baseline_v2.0")

        # 3. Fetch dynamic inference if available
        dynamic_inference_doc = await self.repository.get_dynamic_inference_by_scan_id(scan_id)
        dynamic_doc = await self.repository.get_dynamic_analysis_by_scan_id(scan_id)

        dynamic_prob: Optional[float] = None
        dynamic_version: str = "dynamic_lstm_v1.0"
        seq_len: int = 0
        unk_rate: float = 0.0

        if dynamic_inference_doc and "inference_result" in dynamic_inference_doc:
            inf_res = dynamic_inference_doc["inference_result"]
            dynamic_prob = inf_res.get("malware_probability")
            dynamic_version = inf_res.get("model_version", "dynamic_lstm_v1.0")
            seq_len = inf_res.get("sequence_length", 0)
            unk_rate = inf_res.get("unknown_event_rate", 0.0)
        elif dynamic_doc and "dynamic_result" in dynamic_doc:
            # Dynamic analysis exists but dynamic model hasn't been run yet: run dynamic inference service
            from backend.app.services.dynamic_model_service import get_dynamic_model_service
            dyn_svc = get_dynamic_model_service()
            inf_res = dyn_svc.predict_dynamic_telemetry(dynamic_doc["dynamic_result"])
            dynamic_prob = inf_res.get("malware_probability")
            dynamic_version = inf_res.get("model_version", "dynamic_lstm_v1.0")
            seq_len = inf_res.get("sequence_length", 0)
            unk_rate = inf_res.get("unknown_event_rate", 0.0)

        # Check that at least one modality exists
        if static_prob is None and dynamic_prob is None:
            raise PolyShieldException(
                detail=f"Neither static ML analysis nor dynamic sandbox telemetry is available for scan '{scan_id}'. Run static or dynamic analysis first."
            )

        # 4. Compute ensemble prediction
        prediction_result: PredictionResult = self.ensemble_model.predict_ensemble(
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            static_probability=static_prob,
            dynamic_probability=dynamic_prob,
            dynamic_sequence_length=seq_len,
            dynamic_unknown_event_rate=unk_rate,
            static_version=static_version,
            dynamic_version=dynamic_version,
        )

        res_dict = prediction_result.model_dump(mode="json")

        # 5. Persist ensemble prediction
        now = datetime.now(timezone.utc)
        await self.repository.save_ensemble_inference(scan_id, res_dict, now)

        logger.info(
            f"Multimodal ensemble completed for scan '{scan_id}': "
            f"mode={prediction_result.ensemble_mode.value}, P(malware)={prediction_result.ensemble_probability}, "
            f"risk={prediction_result.risk_level}"
        )
        return res_dict

    async def get_ensemble_inference_report(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve stored ensemble prediction report for scan_id."""
        scan_doc = await self.repository.get_by_id(scan_id)
        if not scan_doc:
            raise ScanNotFoundException(scan_id)

        doc = await self.repository.get_ensemble_inference_by_scan_id(scan_id)
        if not doc or "inference_result" not in doc:
            # Generate prediction on the fly
            return await self.predict_ensemble_for_scan(scan_id)
        return doc["inference_result"]
