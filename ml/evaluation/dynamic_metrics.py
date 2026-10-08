"""Dynamic Evaluation Metrics & Latency Profiling (Phase 10).

Calculates binary metrics, confusion matrices, and latency stats with safe fallback handling
for small or single-class dataset splits.
"""

from typing import Dict, Any, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
)


def compute_dynamic_metrics(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    threshold: float = 0.5,
    latency_ms_list: Optional[list] = None,
) -> Dict[str, Any]:
    """Compute comprehensive evaluation metrics for dynamic classification.

    Handles single-class or undefined cases safely by returning None for uncomputable metrics.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_prob = np.asarray(y_prob, dtype=float)
    y_pred = (y_prob >= threshold).astype(int)

    n_samples = len(y_true)
    if n_samples == 0:
        return {
            "evaluation_status": "NOT_SCIENTIFICALLY_EVALUABLE",
            "sample_count": 0,
            "threshold": threshold,
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "roc_auc": None,
            "pr_auc": None,
            "fpr": None,
            "fnr": None,
            "confusion_matrix": [[0, 0], [0, 0]],
            "latency": None,
        }

    # Accuracy
    acc = float(accuracy_score(y_true, y_pred))

    # Single-class check
    unique_true = np.unique(y_true)
    is_single_class = len(unique_true) < 2

    if is_single_class:
        prec = None
        rec = None
        f1_val = None
        roc_auc_val = None
        pr_auc_val = None
        fpr_val = None
        fnr_val = None
        cm = [[0, 0], [0, 0]]
        status = "NOT_SCIENTIFICALLY_EVALUABLE"
    else:
        prec = float(precision_score(y_true, y_pred, zero_division=0))
        rec = float(recall_score(y_true, y_pred, zero_division=0))
        f1_val = float(f1_score(y_true, y_pred, zero_division=0))

        try:
            roc_auc_val = float(roc_auc_score(y_true, y_prob))
        except Exception:
            roc_auc_val = None

        try:
            p_curve, r_curve, _ = precision_recall_curve(y_true, y_prob)
            pr_auc_val = float(auc(r_curve, p_curve))
        except Exception:
            pr_auc_val = None

        try:
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
            cm = [[int(tn), int(fp)], [int(fn), int(tp)]]
            fpr_val = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            fnr_val = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        except Exception:
            cm = [[0, 0], [0, 0]]
            fpr_val = None
            fnr_val = None

        status = "ENGINEERING_SMOKE_EVALUATION"

    # Latency statistics
    latency_stats = None
    if latency_ms_list and len(latency_ms_list) > 0:
        lat_arr = np.asarray(latency_ms_list, dtype=float)
        latency_stats = {
            "mean_ms": float(np.mean(lat_arr)),
            "median_ms": float(np.median(lat_arr)),
            "p95_ms": float(np.percentile(lat_arr, 95)),
            "min_ms": float(np.min(lat_arr)),
            "max_ms": float(np.max(lat_arr)),
        }

    return {
        "evaluation_status": status,
        "sample_count": n_samples,
        "threshold": threshold,
        "accuracy": round(acc, 4) if acc is not None else None,
        "precision": round(prec, 4) if prec is not None else None,
        "recall": round(rec, 4) if rec is not None else None,
        "f1": round(f1_val, 4) if f1_val is not None else None,
        "roc_auc": round(roc_auc_val, 4) if roc_auc_val is not None else None,
        "pr_auc": round(pr_auc_val, 4) if pr_auc_val is not None else None,
        "fpr": round(fpr_val, 4) if fpr_val is not None else None,
        "fnr": round(fnr_val, 4) if fnr_val is not None else None,
        "confusion_matrix": cm,
        "latency": latency_stats,
    }
