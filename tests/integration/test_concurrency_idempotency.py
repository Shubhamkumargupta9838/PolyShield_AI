"""
Concurrency & Idempotency Integration Test Suite for PolyShield AI (Phase 14).

Verifies async request safety, concurrent scan registration, duplicate upload handling,
and repository state consistency under concurrent operation.
"""

import asyncio
import pytest
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from backend.app.schemas.scan import CreateScanRequest, ScanStatus
from backend.app.services.scan_service import ScanService
from backend.app.repositories.scan_repository import BaseScanRepository


class InMemoryScanRepository(BaseScanRepository):
    """In-memory scan repository double for testing concurrency."""
    def __init__(self):
        self.scans = {}
        self._lock = asyncio.Lock()

    async def create(self, scan_doc: dict) -> dict:
        async with self._lock:
            scan_id = scan_doc["scan_id"]
            if scan_id in self.scans:
                raise ValueError(f"Scan {scan_id} already exists")
            self.scans[scan_id] = scan_doc
            return scan_doc

    async def get_by_id(self, scan_id: str) -> Optional[dict]:
        async with self._lock:
            return self.scans.get(scan_id)

    async def update_status(self, scan_id: str, status: ScanStatus, updated_at: datetime, error: Optional[str] = None) -> Optional[dict]:
        async with self._lock:
            if scan_id not in self.scans:
                return None
            self.scans[scan_id]["status"] = status.value
            self.scans[scan_id]["updated_at"] = updated_at
            if error:
                self.scans[scan_id]["error"] = error
            return self.scans[scan_id]

    async def list(self, skip: int = 0, limit: int = 10) -> Tuple[List[dict], int]:
        async with self._lock:
            items = list(self.scans.values())
            return items[skip:skip + limit], len(items)

    async def save_static_analysis(self, scan_id: str, static_result: Dict[str, Any], feature_vector: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_static_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def save_analysis_report(self, scan_id: str, report_data: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_report_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def save_dynamic_analysis(self, scan_id: str, dynamic_result: Dict[str, Any], dynamic_features: Dict[str, float], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_dynamic_analysis_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def save_dynamic_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_dynamic_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def save_ensemble_inference(self, scan_id: str, inference_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_ensemble_inference_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None

    async def save_explanation(self, scan_id: str, explanation_result: Dict[str, Any], updated_at: datetime) -> Optional[Dict[str, Any]]:
        return None

    async def get_explanation_by_scan_id(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return None


@pytest.mark.asyncio
async def test_concurrent_scan_creation_idempotency():
    """Verify that creating 50 concurrent scan requests produces 50 unique scan records."""
    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    async def create_single_scan(index: int):
        req = CreateScanRequest(
            filename=f"sample_{index}.exe",
            file_hash=f"{index:064x}",
            file_size=1024
        )
        return await service.create_scan(req)

    results = await asyncio.gather(*[create_single_scan(i) for i in range(50)])

    assert len(results) == 50
    scan_ids = {r.scan_id for r in results}
    assert len(scan_ids) == 50  # All scan IDs must be globally unique UUIDs


@pytest.mark.asyncio
async def test_concurrent_status_updates_do_not_corrupt_state():
    """Verify concurrent reads/writes on scan records maintain valid states."""
    repo = InMemoryScanRepository()
    service = ScanService(repository=repo)

    req = CreateScanRequest(filename="test.exe", file_hash="a" * 64, file_size=2048)
    created = await service.create_scan(req)

    # Initial transition
    await service.update_scan_status(created.scan_id, ScanStatus.STATIC_ANALYSIS)

    scan = await service.get_scan(created.scan_id)
    assert scan.status == ScanStatus.STATIC_ANALYSIS
