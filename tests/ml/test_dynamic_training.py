"""Unit Tests for Dynamic Training Pipeline & Metrics (Phase 10)."""

import pytest
import numpy as np

from ml.data.dynamic_sequence_schema import DynamicBehavioralSequence, DynamicEventToken
from ml.training.dynamic_training_pipeline import DynamicLSTMTrainer
from ml.evaluation.dynamic_metrics import compute_dynamic_metrics


def test_dynamic_metrics_safe_handling():
    """Verify evaluation metrics handle single-class or undefined cases safely without throwing exceptions."""
    # Single-class input (all benign)
    y_true_single = np.array([0, 0, 0, 0])
    y_prob_single = np.array([0.1, 0.2, 0.3, 0.4])

    metrics = compute_dynamic_metrics(y_true_single, y_prob_single, threshold=0.5)
    assert metrics["evaluation_status"] == "NOT_SCIENTIFICALLY_EVALUABLE"
    assert metrics["precision"] is None
    assert metrics["recall"] is None

    # Multi-class input
    y_true_multi = np.array([0, 0, 1, 1])
    y_prob_multi = np.array([0.1, 0.3, 0.7, 0.9])

    metrics_multi = compute_dynamic_metrics(y_true_multi, y_prob_multi, threshold=0.5)
    assert metrics_multi["evaluation_status"] == "ENGINEERING_SMOKE_EVALUATION"
    assert metrics_multi["accuracy"] == 1.0
    assert metrics_multi["f1"] == 1.0


def test_dynamic_training_pipeline_smoke(tmp_path):
    """Verify full end-to-end training pipeline on synthetic sequences."""
    seqs = []
    for i in range(10):
        label = 1 if i >= 5 else 0
        seqs.append(
            DynamicBehavioralSequence(
                sample_sha256=f"{i}" * 64,
                label=label,
                family="benign" if label == 0 else "trojan",
                events=[
                    DynamicEventToken(relative_time_ms=0, event_type="PROCESS_CREATE", event_category="process"),
                    DynamicEventToken(relative_time_ms=10, event_type="NETWORK_CONNECT" if label == 1 else "FILESYSTEM_READ", event_category="net"),
                ]
            )
        )

    trainer = DynamicLSTMTrainer(max_sequence_length=16, batch_size=4, epochs=3, patience=2, seed=42)
    res = trainer.train_pipeline(seqs, artifacts_dir=tmp_path)

    assert res["model_version"] == "dynamic_lstm_v1.0"
    assert res["training_status"] == "COMPLETED"
    assert (tmp_path / "dynamic_vocab_v1.json").exists()
    assert (tmp_path / "dynamic_dataset_report_v1.0.json").exists()
    assert (tmp_path / "dynamic_training_report_v1.0.json").exists()
