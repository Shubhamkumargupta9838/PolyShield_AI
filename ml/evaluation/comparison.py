import pandas as pd
from typing import Dict, Any, List


def format_comparison_table(model_results: Dict[str, Dict[str, Any]]) -> pd.DataFrame:
    """
    Formats model evaluation metric dictionaries into a comparative pandas DataFrame.
    Format None values as 'N/A'.
    """
    def _fmt(val):
        return val if val is not None else "N/A"

    rows = []
    for model_name, metrics in model_results.items():
        rows.append({
            "Model": model_name,
            "Accuracy": _fmt(metrics.get("accuracy")),
            "Precision": _fmt(metrics.get("precision")),
            "Recall": _fmt(metrics.get("recall")),
            "F1": _fmt(metrics.get("f1_score")),
            "ROC-AUC": _fmt(metrics.get("roc_auc")),
            "PR-AUC": _fmt(metrics.get("pr_auc")),
            "FPR": _fmt(metrics.get("false_positive_rate")),
            "FNR": _fmt(metrics.get("false_negative_rate")),
            "Threshold": _fmt(metrics.get("threshold")),
            "Status": _fmt(metrics.get("evaluation_status")),
        })

    df = pd.DataFrame(rows)
    return df
