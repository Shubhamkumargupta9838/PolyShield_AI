import numpy as np
import pandas as pd
from typing import Dict, Any, Union, Tuple, List, Optional
from ml.evaluation.metrics import calculate_metrics


def find_optimal_threshold(
    y_val_true: Union[pd.Series, np.ndarray],
    y_val_proba: Union[pd.Series, np.ndarray],
    candidate_thresholds: Optional[List[float]] = None,
    target_metric: str = "f1_score",
) -> Tuple[float, Dict[str, Any], List[Dict[str, Any]]]:
    """
    Evaluates candidate classification thresholds strictly on validation probabilities.
    Safely defaults to 0.5 if validation set lacks class coverage.
    """
    if candidate_thresholds is None:
        candidate_thresholds = [round(x, 2) for x in np.arange(0.1, 0.95, 0.05)]

    y_val_true = np.asarray(y_val_true, dtype=int)
    y_val_proba = np.asarray(y_val_proba, dtype=float)

    unique_classes = set(np.unique(y_val_true))
    has_both_classes = unique_classes == {0, 1}

    evaluations = []
    if not has_both_classes:
        # Default to 0.5 for engineering pipeline execution
        default_metrics = calculate_metrics(y_val_true, y_val_proba, threshold=0.5)
        default_metrics["threshold_selection_status"] = "NOT_SCIENTIFICALLY_EVALUABLE"
        return 0.5, default_metrics, [default_metrics]

    best_threshold = 0.5
    best_metric_val = -1.0
    best_metrics_dict = None

    for thresh in candidate_thresholds:
        m = calculate_metrics(y_val_true, y_val_proba, threshold=thresh)
        evaluations.append(m)

        current_val = m.get(target_metric)
        if current_val is not None:
            if current_val > best_metric_val:
                best_metric_val = current_val
                best_threshold = thresh
                best_metrics_dict = m
            elif current_val == best_metric_val and best_metrics_dict is not None:
                if abs(thresh - 0.5) < abs(best_threshold - 0.5):
                    best_threshold = thresh
                    best_metrics_dict = m

    if best_metrics_dict is None:
        best_metrics_dict = calculate_metrics(y_val_true, y_val_proba, threshold=0.5)
        best_threshold = 0.5

    best_metrics_dict["threshold_selection_status"] = "VALID"
    return best_threshold, best_metrics_dict, evaluations
