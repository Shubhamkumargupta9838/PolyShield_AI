from abc import ABC, abstractmethod
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timezone
from backend.app.schemas.scan import ScanStatus


class BaseScanRepository(ABC):
    @abstractmethod
    async def create(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def get_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def list(self, skip: int, limit: int) -> Tuple[List[Dict[str, Any]], int]:
        pass

    @abstractmethod
    async def update_status(self, scan_id: str, status: ScanStatus, updated_at: datetime, error: Optional[str] = None) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_static_analysis(self, scan_id: str, static_result: Dict[str, Any], feature_vector: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_static_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_analysis_report(self, scan_id: str, report_data: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_report_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_dynamic_analysis(self, scan_id: str, dynamic_result: Dict[str, Any], dynamic_features: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_dynamic_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_dynamic_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_dynamic_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_ensemble_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_ensemble_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_explanation(self, scan_id: str, explanation_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def get_explanation_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        pass


class MongoScanRepository(BaseScanRepository):
    def __init__(self, database):
        self.db = database
        self.collection_name = "scans"
        self.static_results_collection_name = "static_analysis_results"
        self.reports_collection_name = "analysis_reports"
        self.dynamic_results_collection_name = "dynamic_analysis_results"
        self.dynamic_inference_collection_name = "dynamic_inference_results"
        self.ensemble_inference_collection_name = "ensemble_inference_results"
        self.explanations_collection_name = "explanation_results"

    @property
    def collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.collection_name]
        return None

    @property
    def static_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.static_results_collection_name]
        return None

    @property
    def reports_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.reports_collection_name]
        return None

    @property
    def dynamic_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.dynamic_results_collection_name]
        return None

    @property
    def dynamic_inference_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.dynamic_inference_collection_name]
        return None

    @property
    def ensemble_inference_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.ensemble_inference_collection_name]
        return None

    @property
    def explanations_collection(self):
        if self.db and self.db.db is not None:
            return self.db.db[self.explanations_collection_name]
        return None

    async def create(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        if self.collection is not None:
            await self.collection.insert_one(scan_data)
        return scan_data

    async def get_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.collection is not None:
            doc = await self.collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None

    async def list(self, skip: int, limit: int) -> Tuple[List[Dict[str, Any]], int]:
        if self.collection is not None:
            total = await self.collection.count_documents({})
            cursor = self.collection.find({}, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit)
            items = await cursor.to_list(length=limit)
            return items, total
        return [], 0

    async def update_status(self, scan_id: str, status: ScanStatus, updated_at: datetime, error: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if self.collection is not None:
            update_fields: Dict[str, Any] = {
                "status": status.value if hasattr(status, "value") else status,
                "updated_at": updated_at
            }
            if error:
                update_fields["error"] = error

            result = await self.collection.find_one_and_update(
                {"scan_id": scan_id},
                {"$set": update_fields},
                projection={"_id": 0},
                return_document=True
            )
            return result
        return None

    async def save_static_analysis(self, scan_id: str, static_result: Dict[str, Any], feature_vector: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        static_ref = f"static_res://{scan_id}"
        feature_ref = f"feature_vec://{scan_id}"

        if self.static_collection is not None:
            await self.static_collection.update_one(
                {"scan_id": scan_id},
                {"$set": {"scan_id": scan_id, "result": static_result, "feature_vector": feature_vector}},
                upsert=True
            )

        if self.collection is not None:
            result = await self.collection.find_one_and_update(
                {"scan_id": scan_id},
                {"$set": {
                    "status": ScanStatus.STATIC_ANALYSIS.value,
                    "file_hash": static_result.get("file", {}).get("sha256"),
                    "file_size": static_result.get("file", {}).get("file_size"),
                    "static_analysis_reference": static_ref,
                    "feature_reference": feature_ref,
                    "updated_at": updated_at
                }},
                projection={"_id": 0},
                return_document=True
            )
            return result
        return None

    async def get_static_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.static_collection is not None:
            doc = await self.static_collection.find_one({"scan_id": scan_id}, projection={"_id": 0})
            return doc
        return None

    async def save_analysis_report(self, scan_id: str, report_data: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        pred_ref = f"prediction_res://{scan_id}"
        report_ref = f"report_res://{scan_id}"

        if self.reports_collection is not None:
            await self.reports_collection.update_one(
                {"scan_id": scan_id},
                {"$set": report_data},
                upsert=True
            )

        if self.collection is not None:
            result = await self.collection.find_one_and_update(
                {"scan_id": scan_id},
                {"$set": {
                    "status": ScanStatus.COMPLETED.value,
                    "file_hash": report_data.get("file_hash"),
                    "file_size": report_data.get("file_size"),
                    "prediction_reference": pred_ref,
                    "report_reference": report_ref,
                    "model_version": report_data.get("model_version"),
                    "updated_at": updated_at
                }},
                projection={"_id": 0},
                return_document=True
            )
            return result
        return None

    async def get_report_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.reports_collection is not None:
            doc = await self.reports_collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None

    async def save_dynamic_analysis(self, scan_id: str, dynamic_result: Dict[str, Any], dynamic_features: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        dyn_ref = f"dynamic_res://{scan_id}"
        if self.dynamic_collection is not None:
            await self.dynamic_collection.replace_one(
                {"scan_id": scan_id},
                {
                    "scan_id": scan_id,
                    "dynamic_result": dynamic_result,
                    "dynamic_features": dynamic_features,
                    "updated_at": updated_at
                },
                upsert=True
            )
        if self.collection is not None:
            result = await self.collection.find_one_and_update(
                {"scan_id": scan_id},
                {"$set": {
                    "status": ScanStatus.FEATURE_EXTRACTION.value,
                    "dynamic_analysis_reference": dyn_ref,
                    "updated_at": updated_at
                }},
                projection={"_id": 0},
                return_document=True
            )
            return result
        return None

    async def get_dynamic_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.dynamic_collection is not None:
            doc = await self.dynamic_collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None

    async def save_dynamic_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if self.dynamic_inference_collection is not None:
            await self.dynamic_inference_collection.replace_one(
                {"scan_id": scan_id},
                {
                    "scan_id": scan_id,
                    "inference_result": inference_result,
                    "updated_at": updated_at
                },
                upsert=True
            )
        return inference_result

    async def get_dynamic_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.dynamic_inference_collection is not None:
            doc = await self.dynamic_inference_collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None

    async def save_ensemble_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if self.ensemble_inference_collection is not None:
            await self.ensemble_inference_collection.replace_one(
                {"scan_id": scan_id},
                {
                    "scan_id": scan_id,
                    "inference_result": inference_result,
                    "updated_at": updated_at
                },
                upsert=True
            )
        return inference_result

    async def get_ensemble_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.ensemble_inference_collection is not None:
            doc = await self.ensemble_inference_collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None

    async def save_explanation(self, scan_id: str, explanation_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if self.explanations_collection is not None:
            await self.explanations_collection.replace_one(
                {"scan_id": scan_id},
                {
                    "scan_id": scan_id,
                    "explanation_result": explanation_result,
                    "updated_at": updated_at
                },
                upsert=True
            )
        return explanation_result

    async def get_explanation_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        if self.explanations_collection is not None:
            doc = await self.explanations_collection.find_one({"scan_id": scan_id}, {"_id": 0})
            return doc
        return None


class InMemoryScanRepository(BaseScanRepository):
    """In-memory scan repository for fast offline unit tests."""
    def __init__(self):
        self._store: Dict[str, Dict[str, Any]] = {}
        self._static_store: Dict[str, Dict[str, Any]] = {}
        self._report_store: Dict[str, Dict[str, Any]] = {}
        self._dynamic_store: Dict[str, Dict[str, Any]] = {}
        self._dynamic_inference_store: Dict[str, Dict[str, Any]] = {}
        self._ensemble_inference_store: Dict[str, Dict[str, Any]] = {}
        self._explanation_store: Dict[str, Dict[str, Any]] = {}

    async def create(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        self._store[scan_data["scan_id"]] = dict(scan_data)
        return scan_data

    async def get_by_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._store.get(scan_id)
        return dict(doc) if doc else None

    async def list(self, skip: int, limit: int) -> Tuple[List[Dict[str, Any]], int]:
        all_items = sorted(
            list(self._store.values()),
            key=lambda x: x.get("created_at", datetime.min),
            reverse=True
        )
        total = len(all_items)
        items = all_items[skip:skip + limit]
        return [dict(i) for i in items], total

    async def update_status(self, scan_id: str, status: ScanStatus, updated_at: datetime, error: Optional[str] = None) -> Optional[Dict[str, Any]]:
        if scan_id not in self._store:
            return None
        doc = self._store[scan_id]
        doc["status"] = status.value if hasattr(status, "value") else status
        doc["updated_at"] = updated_at
        if error:
            doc["error"] = error
        return dict(doc)

    async def save_static_analysis(self, scan_id: str, static_result: Dict[str, Any], feature_vector: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if scan_id not in self._store:
            return None
        self._static_store[scan_id] = {
            "result": static_result,
            "feature_vector": feature_vector
        }
        doc = self._store[scan_id]
        doc["status"] = ScanStatus.STATIC_ANALYSIS.value
        doc["file_hash"] = static_result.get("file", {}).get("sha256")
        doc["file_size"] = static_result.get("file", {}).get("file_size")
        doc["static_analysis_reference"] = f"static_res://{scan_id}"
        doc["feature_reference"] = f"feature_vec://{scan_id}"
        doc["updated_at"] = updated_at
        return dict(doc)

    async def get_static_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._static_store.get(scan_id)
        return dict(doc) if doc else None

    async def save_analysis_report(self, scan_id: str, report_data: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if scan_id not in self._store:
            return None
        self._report_store[scan_id] = dict(report_data)
        doc = self._store[scan_id]
        doc["status"] = ScanStatus.COMPLETED.value
        doc["file_hash"] = report_data.get("file_hash")
        doc["file_size"] = report_data.get("file_size")
        doc["prediction_reference"] = f"prediction_res://{scan_id}"
        doc["report_reference"] = f"report_res://{scan_id}"
        doc["model_version"] = report_data.get("model_version")
        doc["updated_at"] = updated_at
        return dict(doc)

    async def get_report_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._report_store.get(scan_id)
        return dict(doc) if doc else None

    async def save_dynamic_analysis(self, scan_id: str, dynamic_result: Dict[str, Any], dynamic_features: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        if scan_id not in self._store:
            return None
        self._dynamic_store[scan_id] = {
            "dynamic_result": dynamic_result,
            "dynamic_features": dynamic_features
        }
        doc = self._store[scan_id]
        doc["status"] = ScanStatus.FEATURE_EXTRACTION.value
        doc["dynamic_analysis_reference"] = f"dynamic_res://{scan_id}"
        doc["updated_at"] = updated_at
        return dict(doc)

    async def get_dynamic_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._dynamic_store.get(scan_id)
        return dict(doc) if doc else None

    async def save_dynamic_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        self._dynamic_inference_store[scan_id] = {
            "inference_result": inference_result,
            "updated_at": updated_at
        }
        return inference_result

    async def get_dynamic_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._dynamic_inference_store.get(scan_id)
        return dict(doc) if doc else None

    async def save_ensemble_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        self._ensemble_inference_store[scan_id] = {
            "inference_result": inference_result,
            "updated_at": updated_at
        }
        return inference_result

    async def get_ensemble_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._ensemble_inference_store.get(scan_id)
        return dict(doc) if doc else None

    async def save_explanation(self, scan_id: str, explanation_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        self._explanation_store[scan_id] = {
            "explanation_result": explanation_result,
            "updated_at": updated_at
        }
        return explanation_result

    async def get_explanation_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        doc = self._explanation_store.get(scan_id)
        return dict(doc) if doc else None


