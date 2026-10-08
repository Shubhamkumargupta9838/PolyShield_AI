import time
import numpy as np
import pandas as pd
from typing import Dict, Any, Union, Optional
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    auc,
    confusion_matrix,
)
from ml.data.dataset_quality import EvaluationStatus


def calculate_confusion_matrix_dict(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, int]:
    """
    Computes confusion matrix metrics: TN, FP, FN, TP.
    """
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    return {
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    }


def calculate_metrics(
    y_true: Union[pd.Series, np.ndarray],
    y_proba: Union[pd.Series, np.ndarray],
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """
    Computes metric suite for binary malware classification with single-class safety guardrails.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_proba = np.asarray(y_proba, dtype=float)
    y_pred = (y_proba >= threshold).astype(int)

    unique_classes = set(np.unique(y_true))
    has_both_classes = unique_classes == {0, 1}

    cm_dict = calculate_confusion_matrix_dict(y_true, y_pred)
    tn = cm_dict["true_negatives"]
    fp = cm_dict["false_positives"]
    fn = cm_dict["false_negatives"]
    tp = cm_dict["true_positives"]

    accuracy = float(accuracy_score(y_true, y_pred)) if len(y_true) > 0 else 0.0
    warnings = []

    if not has_both_classes:
        evaluation_status = EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE.value
        warnings.append("Accuracy is calculated, but evaluation split does not contain both benign and malware classes. Accuracy must NOT be interpreted as malware detection performance.")

        if 1 not in unique_classes:
            warnings.append("Evaluation split contains no malware (positive) samples. Recall, Precision, F1, FNR, ROC-AUC, and PR-AUC are undefined.")
        if 0 not in unique_classes:
            warnings.append("Evaluation split contains no benign (negative) samples. Precision, FPR, ROC-AUC, and PR-AUC are undefined.")

        precision = None
        recall = None
        f1 = None
        roc_auc = None
        pr_auc_val = None
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else None
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else None
        roc_curve_data = {"false_positive_rate": [], "true_positive_rate": [], "thresholds": []}
        pr_curve_data = {"precision": [], "recall": [], "thresholds": []}

    else:
        evaluation_status = EvaluationStatus.VALID.value
        precision = float(precision_score(y_true, y_pred, zero_division=0))
        recall = float(recall_score(y_true, y_pred, zero_division=0))
        f1 = float(f1_score(y_true, y_pred, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        try:
            roc_auc = float(roc_auc_score(y_true, y_proba))
            fpr_c, tpr_c, roc_thresh = roc_curve(y_true, y_proba)
            roc_curve_data = {
                "false_positive_rate": [float(x) for x in fpr_c],
                "true_positive_rate": [float(x) for x in tpr_c],
                "thresholds": [float(x) for x in roc_thresh],
            }
        except Exception:
            roc_auc = None
            roc_curve_data = {"false_positive_rate": [], "true_positive_rate": [], "thresholds": []}

        try:
            p_c, r_c, pr_thresh = precision_recall_curve(y_true, y_proba)
            pr_auc_val = float(auc(r_c, p_c))
            pr_curve_data = {
                "precision": [float(x) for x in p_c],
                "recall": [float(x) for x in r_c],
                "thresholds": [float(x) for x in pr_thresh],
            }
        except Exception:
            pr_auc_val = None
            pr_curve_data = {"precision": [], "recall": [], "thresholds": []}

    return {
        "evaluation_status": evaluation_status,
        "has_both_classes": has_both_classes,
        "threshold": float(threshold),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "f1_score": round(f1, 4) if f1 is not None else None,
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else None,
        "pr_auc": round(pr_auc_val, 4) if pr_auc_val is not None else None,
        "false_positive_rate": round(fpr, 4) if fpr is not None else None,
        "false_negative_rate": round(fnr, 4) if fnr is not None else None,
        "confusion_matrix": cm_dict,
        "roc_curve": roc_curve_data,
        "pr_curve": pr_curve_data,
        "warnings": warnings,
    }


def measure_inference_latency(
    model_wrapper: Any,
    X: Union[pd.DataFrame, np.ndarray],
    num_runs: int = 5,
) -> Dict[str, float]:
    """
    Measures total and per-sample inference latency.
    """
    num_samples = len(X)
    if num_samples == 0:
        return {"total_inference_time_ms": 0.0, "average_time_per_sample_ms": 0.0}

    # Warmup
    _ = model_wrapper.predict_proba(X)

    start_time = time.perf_counter()
    for _ in range(num_runs):
        _ = model_wrapper.predict_proba(X)
    end_time = time.perf_counter()

    total_time_sec = (end_time - start_time) / num_runs
    total_time_ms = total_time_sec * 1000.0
    avg_per_sample_ms = total_time_ms / num_samples

    return {
        "total_inference_time_ms": round(total_time_ms, 4),
        "average_time_per_sample_ms": round(avg_per_sample_ms, 4),
    }
