"""Unit tests for Dynamic Sequence Explainer (Phase 12)."""

import pytest
from ml.explainability.dynamic_explainer import DynamicSequenceExplainer
from ml.explainability.schemas import DynamicExplanation


@pytest.fixture
def sample_dynamic_result():
    return {
        "scan_id": "test_dyn_exp_123",
        "sample_sha256": "a" * 64,
        "metrics": {
            "process_count": 3,
            "child_process_count": 1,
            "network_connection_count": 2,
            "dns_query_count": 1,
            "blocked_network_attempt_count": 1,
            "filesystem_write_count": 4,
            "filesystem_delete_count": 0,
            "registry_write_count": 2,
            "api_event_count": 8,
            "injection_event_count": 1,
            "persistence_event_count": 1,
            "service_creation_count": 0,
            "suspicious_process_count": 1,
            "dropped_file_count": 1,
        },
        "raw_event_stream": [
            {"relative_time_ms": 10, "event_type": "PROCESS_CREATE", "event_category": "process"},
            {"relative_time_ms": 150, "event_type": "FILE_WRITE", "event_category": "filesystem"},
            {"relative_time_ms": 300, "event_type": "REGISTRY_SET", "event_category": "registry"},
            {"relative_time_ms": 450, "event_type": "NETWORK_CONNECT", "event_category": "network"},
            {"relative_time_ms": 600, "event_type": "PROCESS_INJECT", "event_category": "process"},
        ],
    }


def test_dynamic_explainer_initialization():
    """Verify DynamicSequenceExplainer loads LSTM model artifact and Captum LIG."""
    explainer = DynamicSequenceExplainer()
    assert explainer.model is not None
    assert explainer.lig is not None


def test_dynamic_explanation_structure(sample_dynamic_result):
    """Verify sequence event attributions, timeline, top-k ranking, and PAD token exclusion."""
    explainer = DynamicSequenceExplainer()
    res: DynamicExplanation = explainer.explain_telemetry(sample_dynamic_result, top_k=3, n_steps=20)

    assert res.model_version == "dynamic_lstm_v1.0"
    assert res.sequence_length == 5
    assert 0.0 <= res.model_output <= 1.0
    assert len(res.top_k_attributions) == 3
    assert len(res.temporal_timeline) == 5

    # PAD exclusion test: no event_type should contain <PAD>
    for attr in res.attributions:
        assert "<PAD>" not in attr.event_type, f"Found <PAD> token in attributions: {attr}"

    # Timeline ordering sanity: relative_time_ms should be non-decreasing
    for i in range(len(res.temporal_timeline) - 1):
        assert res.temporal_timeline[i].relative_time_ms <= res.temporal_timeline[i + 1].relative_time_ms


def test_unknown_event_handling():
    """Verify unknown events are preserved with <UNK> tag."""
    explainer = DynamicSequenceExplainer()
    unk_dynamic_result = {
        "scan_id": "test_unk_456",
        "sample_sha256": "b" * 64,
        "metrics": {"process_count": 1},
        "raw_event_stream": [
            {"relative_time_ms": 20, "event_type": "SOME_UNKNOWN_CUSTOM_API_CALL", "event_category": "api"},
        ],
    }
    res = explainer.explain_telemetry(unk_dynamic_result, top_k=5, n_steps=10)
    assert res.sequence_length == 1
    assert len(res.attributions) == 1
    assert "<UNK>" in res.attributions[0].event_type
