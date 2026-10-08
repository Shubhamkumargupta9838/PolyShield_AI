"""Backend Explanation Service (Phase 12).

Orchestrates XAI generation using StaticSHAPExplainer, DynamicSequenceExplainer,
and EnsembleExplainer. Validates numerical sanity and persists ExplanationResult documents.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from ml.explainability.schemas import (
    ExplanationResult,
    StaticExplanation,
    DynamicExplanation,
    EnsembleDecomposition,
    EvidenceItem,
    ExplanationLimitations,
    EXPLANATION_VERSION,
)
from ml.explainability.static_explainer import StaticSHAPExplainer
from ml.explainability.dynamic_explainer import DynamicSequenceExplainer
from ml.explainability.ensemble_explainer import EnsembleExplainer
from ml.explainability.validation import ExplanationValidator
from ml.explainability.serialization import ExplanationSerializer

from backend.app.repositories.scan_repository import BaseScanRepository
from backend.app.services.ensemble_service import EnsembleService
from backend.app.core.exceptions import ScanNotFoundException, PolyShieldException

logger = logging.getLogger("polyshield.explanation_service")


class ExplanationService:
    """Service managing explainable AI generation and attribution persistence."""

    _instance: Optional["ExplanationService"] = None

    def __init__(self, repository: BaseScanRepository):
        self.repository = repository
        self.static_explainer = StaticSHAPExplainer()
        self.dynamic_explainer = DynamicSequenceExplainer()
        self.ensemble_explainer = EnsembleExplainer()
        self.validator = ExplanationValidator()
        self.ensemble_service = EnsembleService(repository=repository)

    async def generate_explanation_for_scan(self, scan_id: str) -> Dict[str, Any]:
        """Generates or retrieves stored explanation report for scan_id."""
        # 1. Idempotency check: return cached explanation if exists
        cached = await self.repository.get_explanation_by_scan_id(scan_id)
        if cached and "explanation_result" in cached:
            logger.info(f"Returning cached explanation report for scan '{scan_id}'.")
            return cached["explanation_result"]

        # 2. Fetch scan metadata
        scan_doc = await self.repository.get_by_id(scan_id)
        if not scan_doc:
            raise ScanNotFoundException(scan_id)

        sample_sha256 = scan_doc.get("file_hash") or "0" * 64

        # 3. Fetch static feature vector
        static_analysis_doc = await self.repository.get_static_analysis_by_scan_id(scan_id)
        if not static_analysis_doc:
            static_analysis_doc = await self.repository.get_report_by_scan_id(scan_id)

        static_exp: Optional[StaticExplanation] = None
        evidence_items: List[EvidenceItem] = []

        if static_analysis_doc:
            feats = static_analysis_doc.get("feature_vector") or static_analysis_doc.get("features")
            if feats:
                static_exp = self.static_explainer.explain(feats, top_k=5)

                # Build Observed Evidence from static measurements (FACTS, not attributions)
                evidence_items.extend([
                    EvidenceItem(
                        metric_name="max_section_entropy",
                        metric_value=feats.get("max_section_entropy", 0.0),
                        category="static_structural",
                        description="Maximum Shannon entropy observed across PE sections (0.0 - 8.0)",
                    ),
                    EvidenceItem(
                        metric_name="rwx_section_count",
                        metric_value=feats.get("rwx_section_count", 0.0),
                        category="static_structural",
                        description="Count of PE sections configured as simultaneously readable, writable, and executable",
                    ),
                    EvidenceItem(
                        metric_name="suspicious_api_count",
                        metric_value=feats.get("suspicious_api_count", 0.0),
                        category="static_structural",
                        description="Count of security-sensitive Win32 APIs imported",
                    ),
                    EvidenceItem(
                        metric_name="file_size",
                        metric_value=feats.get("file_size", 0.0),
                        category="static_structural",
                        description="PE binary file size in bytes",
                    ),
                ])

        # 4. Fetch dynamic result if available
        dynamic_doc = await self.repository.get_dynamic_analysis_by_scan_id(scan_id)
        dynamic_exp: Optional[DynamicExplanation] = None

        if dynamic_doc and "dynamic_result" in dynamic_doc:
            dyn_res = dynamic_doc["dynamic_result"]
            dynamic_exp = self.dynamic_explainer.explain_telemetry(dyn_res, top_k=5)

            # Build Observed Evidence from dynamic trace (FACTS, not attributions)
            metrics = dyn_res.get("metrics", {})
            evidence_items.extend([
                EvidenceItem(
                    metric_name="process_count",
                    metric_value=metrics.get("process_count", 0),
                    category="dynamic_telemetry",
                    description="Count of processes created during sandbox execution trace",
                ),
                EvidenceItem(
                    metric_name="registry_write_count",
                    metric_value=metrics.get("registry_write_count", 0),
                    category="dynamic_telemetry",
                    description="Count of registry key write/delete operations observed",
                ),
                EvidenceItem(
                    metric_name="blocked_network_attempt_count",
                    metric_value=metrics.get("blocked_network_attempt_count", 0),
                    category="dynamic_telemetry",
                    description="Count of outbound network connection attempts blocked by isolation policy",
                ),
            ])

        # 5. Fetch ensemble prediction & compute decomposition
        ens_pred_dict = await self.ensemble_service.predict_ensemble_for_scan(scan_id)
        from ml.models.prediction_schema import PredictionResult
        prediction_obj = PredictionResult(**ens_pred_dict)

        ensemble_decomp = self.ensemble_explainer.explain_ensemble(prediction_obj)

        # 6. Construct top-level ExplanationResult
        result = ExplanationResult(
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            explanation_version=EXPLANATION_VERSION,
            static_explanation=static_exp,
            dynamic_explanation=dynamic_exp,
            ensemble_decomposition=ensemble_decomp,
            observed_evidence=evidence_items,
            risk_level=prediction_obj.risk_level,
            decision_threshold=prediction_obj.threshold,
            decision_summary=(
                f"Prediction classification '{prediction_obj.ensemble_classification}' with P={prediction_obj.ensemble_probability:.4f} "
                f"assigned risk level '{prediction_obj.risk_level}'. {ensemble_decomp.explanation_summary}"
            ),
            limitations=ExplanationLimitations(),
        )

        # 7. Validate numerical sanity & schema rules
        self.validator.validate_explanation_result(result)

        res_dict = result.model_dump(mode="json")

        # 8. Persist explanation document to repository & export JSON artifact
        now = datetime.now(timezone.utc)
        await self.repository.save_explanation(scan_id, res_dict, now)
        try:
            ExplanationSerializer.save_artifact(result)
        except Exception as e:
            logger.warning(f"Failed to export artifact file explanation_v1.0.json: {e}")

        logger.info(f"Explanation generated and persisted successfully for scan '{scan_id}'.")
        return res_dict

    async def get_explanation_report(self, scan_id: str) -> Dict[str, Any]:
        """Retrieves explanation report for scan_id."""
        scan_doc = await self.repository.get_by_id(scan_id)
        if not scan_doc:
            raise ScanNotFoundException(scan_id)

        doc = await self.repository.get_explanation_by_scan_id(scan_id)
        if not doc or "explanation_result" not in doc:
            return await self.generate_explanation_for_scan(scan_id)
        return doc["explanation_result"]
