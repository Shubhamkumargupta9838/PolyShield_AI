import pytest
from unittest.mock import AsyncMock, MagicMock
from bson import ObjectId
from backend.app.repositories.scan_repository import MongoScanRepository
from backend.app.workers.analysis_tasks import (
    _validate_worker_scan_id,
    analyze_scan_task,
    async_get_worker_scan_service
)


def test_celery_worker_task_scan_id_validation():
    assert _validate_worker_scan_id("scan_uuid_12345") == "scan_uuid_12345"

    with pytest.raises(ValueError):
        _validate_worker_scan_id("../../../etc/passwd")

    with pytest.raises(ValueError):
        _validate_worker_scan_id("scan_id\x00_null")

    with pytest.raises(ValueError):
        _validate_worker_scan_id(12345)


def test_celery_worker_task_malformed_input_handling():
    res = analyze_scan_task("../../traversal_scan")
    assert res["status"] == "FAILED"
    assert "invalid" in res["error"].lower() or "unsafe" in res["error"].lower()


@pytest.mark.asyncio
async def test_worker_scan_lookup_canonical_scan_id():
    """
    Regression test:
    Verifies worker lookup uses canonical scan_id string filter, successfully retrieves
    a scan document created with a Mongo ObjectId '_id', and does not query '_id' using scan_id.
    """
    target_scan_id = "06fe3b00-c503-493d-821b-bebdeedb105d"
    mock_mongo_doc = {
        "_id": ObjectId("6abbf5a1d431ea71c5d3e530"),
        "scan_id": target_scan_id,
        "filename": "sample_pe_binary.exe",
        "file_hash": None,
        "file_size": 102400,
        "status": "QUEUED",
        "owner_id": "usr_default_analyst"
    }

    mock_collection = MagicMock()

    async def mock_find_one(filter_query, projection=None):
        assert "scan_id" in filter_query, "Lookup query must filter by 'scan_id'"
        assert filter_query["scan_id"] == target_scan_id, "Lookup query must match canonical scan_id string"
        assert "_id" not in filter_query or filter_query["_id"] != target_scan_id, "Worker must NOT query '_id' with scan_id"

        if filter_query.get("scan_id") == target_scan_id:
            if projection and projection.get("_id") == 0:
                doc_copy = dict(mock_mongo_doc)
                doc_copy.pop("_id", None)
                return doc_copy
            return dict(mock_mongo_doc)
        return None

    mock_collection.find_one = AsyncMock(side_effect=mock_find_one)
    mock_db = MagicMock()
    mock_db.db = {"scans": mock_collection}

    repo = MongoScanRepository(mock_db)
    result = await repo.get_by_id(target_scan_id)

    assert result is not None
    assert result["scan_id"] == target_scan_id
    assert result["filename"] == "sample_pe_binary.exe"
    assert "_id" not in result


@pytest.mark.asyncio
async def test_async_get_worker_scan_service_uses_mongo_repository(monkeypatch):
    """
    Verifies that async_get_worker_scan_service initializes Mongo connection
    and uses MongoScanRepository when MongoDB client is connected.
    """
    from backend.app.db.mongodb import db

    mock_client = MagicMock()
    mock_db_instance = MagicMock()

    monkeypatch.setattr(db, "client", mock_client)
    monkeypatch.setattr(db, "db", mock_db_instance)

    service = await async_get_worker_scan_service()
    assert isinstance(service.repository, MongoScanRepository)

