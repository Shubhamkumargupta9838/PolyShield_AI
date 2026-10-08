import pytest
import numpy as np
import pandas as pd
from ml.evaluation.metrics import calculate_metrics, calculate_confusion_matrix_dict, measure_inference_latency
from ml.evaluation.threshold import find_optimal_threshold
from ml.evaluation.comparison import format_comparison_table
from ml.models.random_forest import RandomForestBaseline
from ml.data.constants import FEATURE_NAMES
from ml.data.dataset_quality import EvaluationStatus


def test_confusion_matrix_and_metrics_calculation_both_classes():
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_proba = np.array([0.1, 0.2, 0.3, 0.8, 0.4, 0.6, 0.7, 0.9])
    
    cm = calculate_confusion_matrix_dict(y_true, (y_proba >= 0.5).astype(int))
    assert cm["true_negatives"] == 3
    assert cm["false_positives"] == 1
    assert cm["false_negatives"] == 1
    assert cm["true_positives"] == 3

    metrics = calculate_metrics(y_true, y_proba, threshold=0.5)
    assert metrics["evaluation_status"] == EvaluationStatus.VALID.value
    assert metrics["has_both_classes"] is True
    assert metrics["accuracy"] == 0.75
    assert metrics["precision"] == 0.75
    assert metrics["recall"] == 0.75
    assert metrics["f1_score"] == 0.75
    assert metrics["false_positive_rate"] == 0.25
    assert metrics["false_negative_rate"] == 0.25
    assert metrics["roc_auc"] is not None
    assert metrics["pr_auc"] is not None


def test_metrics_calculation_single_class_guardrails():
    # Only benign samples present (0s)
    y_true = np.array([0, 0, 0, 0])
    y_proba = np.array([0.1, 0.2, 0.3, 0.4])

    metrics = calculate_metrics(y_true, y_proba, threshold=0.5)
    assert metrics["evaluation_status"] == EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE.value
    assert metrics["has_both_classes"] is False
    assert metrics["accuracy"] == 1.0
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["f1_score"] is None
    assert metrics["roc_auc"] is None
    assert metrics["pr_auc"] is None
    assert len(metrics["warnings"]) >= 2
    assert "Accuracy is calculated, but evaluation split does not contain both benign and malware classes" in metrics["warnings"][0]


def test_threshold_optimization_single_class_fallback():
    y_val_true = np.array([0, 0, 0, 0])
    y_val_proba = np.array([0.1, 0.2, 0.3, 0.4])

    best_thresh, best_metrics, candidates = find_optimal_threshold(y_val_true, y_val_proba)
    assert best_thresh == 0.5
    assert best_metrics["threshold_selection_status"] == "NOT_SCIENTIFICALLY_EVALUABLE"


def test_latency_measurement_and_comparison_formatting():
    X = pd.DataFrame(np.random.rand(10, 17), columns=FEATURE_NAMES)
    y = pd.Series([0] * 5 + [1] * 5)
    rf = RandomForestBaseline(n_estimators=5, random_state=42)
    rf.fit(X, y)

    latency = measure_inference_latency(rf, X, num_runs=2)
    assert "total_inference_time_ms" in latency
    assert "average_time_per_sample_ms" in latency
    assert latency["average_time_per_sample_ms"] >= 0.0

    m1 = calculate_metrics(y, rf.predict_proba(X))
    m2 = calculate_metrics(y, rf.predict_proba(X))
    comp_df = format_comparison_table({"RF1": m1, "RF2": m2})
    assert comp_df.shape == (2, 11)
    assert "Status" in comp_df.columns
