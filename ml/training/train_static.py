import os
import sys
import json
import argparse
import platform
import numpy as np
import pandas as pd
import sklearn
import xgboost
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION, DEFAULT_DATASET_VERSION
from ml.data.preprocessing import DatasetPreprocessor
from ml.data.dataset_quality import inspect_dataset_quality, EvaluationStatus
from ml.models.random_forest import RandomForestBaseline
from ml.models.xgboost_model import XGBoostBaseline, compute_scale_pos_weight
from ml.models.model_registry import ModelRegistry
from ml.evaluation.metrics import calculate_metrics, measure_inference_latency
from ml.evaluation.threshold import find_optimal_threshold
from ml.evaluation.comparison import format_comparison_table


def verify_data_integrity_and_leakage(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    preprocessor: DatasetPreprocessor,
):
    """
    Strict integrity and zero-leakage assertions.
    """
    X_train, y_train = preprocessor.extract_features_and_target(train_df)
    X_val, y_val = preprocessor.extract_features_and_target(val_df)
    X_test, y_test = preprocessor.extract_features_and_target(test_df)

    # Column count and order assertions
    for name, X in [("train", X_train), ("validation", X_val), ("test", X_test)]:
        assert X.shape[1] == 17, f"{name} matrix must contain 17 columns, got {X.shape[1]}"
        assert list(X.columns) == FEATURE_NAMES, f"{name} columns do not match canonical FEATURE_NAMES ordering."
        assert list(X.columns).count("file_size") == 1, f"file_size must appear exactly once in {name} matrix."
        assert not X.isna().any().any(), f"NaN values detected in {name} matrix."
        assert not np.isinf(X.to_numpy()).any(), f"Inf values detected in {name} matrix."

    # Label binary assertions
    for name, y in [("train", y_train), ("validation", y_val), ("test", y_test)]:
        unique_labels = set(y.unique())
        assert unique_labels.issubset({0, 1}), f"Labels in {name} must be binary 0 or 1, got {unique_labels}"

    # Disjoint SHA-256 assertions
    train_hashes = set(train_df["sha256"])
    val_hashes = set(val_df["sha256"])
    test_hashes = set(test_df["sha256"])

    assert len(train_hashes.intersection(val_hashes)) == 0, "SHA-256 leakage detected between train and validation splits!"
    assert len(train_hashes.intersection(test_hashes)) == 0, "SHA-256 leakage detected between train and test splits!"
    assert len(val_hashes.intersection(test_hashes)) == 0, "SHA-256 leakage detected between validation and test splits!"

    print("[+] Data Integrity & Zero Hash Leakage checks passed successfully!")
    return (X_train, y_train), (X_val, y_val), (X_test, y_test)


def train_static_baseline(
    dataset_dir: str = "ml/artifacts/dataset",
    output_dir: str = "ml/artifacts/models",
    dataset_version: str = DEFAULT_DATASET_VERSION,
    random_state: int = 42,
    override_threshold: float = None,
    strict_evaluation: bool = False,
) -> Dict[str, Any]:
    """
    Main training & evaluation orchestrator for PolyShield AI Phase 5.1.
    """
    print(f"[*] Starting PolyShield AI Static ML Baseline Training (Dataset: {dataset_version}, Seed: {random_state})")

    train_path = os.path.join(dataset_dir, f"train_{dataset_version}.csv")
    val_path = os.path.join(dataset_dir, f"validation_{dataset_version}.csv")
    test_path = os.path.join(dataset_dir, f"test_{dataset_version}.csv")

    if not os.path.exists(train_path) or not os.path.exists(val_path) or not os.path.exists(test_path):
        raise FileNotFoundError(
            f"Dataset splits for version '{dataset_version}' not found in '{dataset_dir}'. "
            f"Run 'python ml/data/build_dataset_cli.py' first."
        )

    train_df = pd.read_csv(train_path)
    val_df = pd.read_csv(val_path)
    test_df = pd.read_csv(test_path)

    preprocessor = DatasetPreprocessor()
    (X_train, y_train), (X_val, y_val), (X_test, y_test) = verify_data_integrity_and_leakage(
        train_df, val_df, test_df, preprocessor
    )

    # Dataset Quality Inspection
    dataset_quality = inspect_dataset_quality(train_df, val_df, test_df)
    print("\n--- DATASET QUALITY & COVERAGE AUDIT ---")
    print(f"  - Dataset Type: {dataset_quality['dataset_type']}")
    print(f"  - Provenance Status: {dataset_quality['dataset_provenance_status']}")
    print(f"  - Sample Breakdown: Real={dataset_quality['verified_real_sample_count']}, Synthetic={dataset_quality['synthetic_sample_count']} (Safe Fixtures={dataset_quality['safe_fixture_sample_count']}), Unverified={dataset_quality['unverified_sample_count']}")
    print(f"  - Benchmark Readiness: Structurally Valid={dataset_quality['structurally_valid']}, Benchmark Ready={dataset_quality['scientifically_benchmark_ready']}, Statistically Powerful={dataset_quality['statistically_powerful']}")
    print(f"  - Scientific Benchmark Available: {dataset_quality['scientific_benchmark_available']}")
    print(f"  - Evaluation Status: {dataset_quality['evaluation_status']}")
    for split_key, sq in dataset_quality["splits"].items():
        print(f"  - [{split_key.upper()}] Samples: {sq['sample_count']}, Benign: {sq['benign_count']}, Malware: {sq['malware_count']}, Both Classes: {sq['has_both_classes']}")

    if dataset_quality["warnings"]:
        print("  - WARNINGS:")
        for w in dataset_quality["warnings"]:
            print(f"    * {w}")

    if strict_evaluation and not dataset_quality["scientific_benchmark_available"]:
        raise ValueError(
            "Strict evaluation mode enabled (--strict-evaluation): "
            "Dataset splits lack binary class coverage required for a scientific benchmark."
        )

    # XGBoost Scale Pos Weight calculation strictly from y_train
    scale_pos_weight = compute_scale_pos_weight(y_train)
    num_benign = int((y_train == 0).sum())
    num_malware = int((y_train == 1).sum())
    print(f"\n[+] Train Class Ratio: Benign={num_benign}, Malware={num_malware}. Formula: scale_pos_weight = benign/malware = {scale_pos_weight}")

    # 1. Train Random Forest
    print("[*] Training Random Forest Baseline...")
    rf_wrapper = RandomForestBaseline(
        n_estimators=300,
        random_state=random_state,
        class_weight="balanced",
        n_jobs=1,
    )
    rf_wrapper.fit(X_train, y_train)

    # 2. Train XGBoost
    print("[*] Training XGBoost Baseline...")
    xgb_wrapper = XGBoostBaseline(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        random_state=random_state,
        n_jobs=1,
    )
    xgb_wrapper.fit(X_train, y_train)

    # 3. Validation Evaluation & Threshold Selection Guardrails
    rf_opt_thresh = override_threshold if override_threshold is not None else 0.5
    xgb_opt_thresh = override_threshold if override_threshold is not None else 0.5

    rf_val_proba = rf_wrapper.predict_proba(X_val)
    xgb_val_proba = xgb_wrapper.predict_proba(X_val)

    rf_val_metrics = calculate_metrics(y_val, rf_val_proba, threshold=rf_opt_thresh)
    xgb_val_metrics = calculate_metrics(y_val, xgb_val_proba, threshold=xgb_opt_thresh)

    rf_val_metrics["threshold"] = rf_opt_thresh
    xgb_val_metrics["threshold"] = xgb_opt_thresh

    comparison_df = format_comparison_table({
        "Random Forest (Val)": rf_val_metrics,
        "XGBoost (Val)": xgb_val_metrics,
    })
    print("\n[+] Validation Performance Comparison:")
    print(comparison_df.to_string(index=False))

    # Model Selection Guardrail
    rf_f1 = rf_val_metrics["f1_score"] if rf_val_metrics["f1_score"] is not None else -1.0
    xgb_f1 = xgb_val_metrics["f1_score"] if xgb_val_metrics["f1_score"] is not None else -1.0

    if xgb_f1 > rf_f1:
        model_selection_status = "VALID"
        model_selection_result = "XGBOOST_WINNER"
        winner_name = "xgboost"
        winner_wrapper = xgb_wrapper
        winner_val_metrics = xgb_val_metrics
        winner_thresh = xgb_opt_thresh
        print(f"\n[+] Selected Winner Model: '{winner_name}' (Validation F1 = {winner_val_metrics['f1_score']}, Threshold = {winner_thresh})")
    elif rf_f1 > xgb_f1:
        model_selection_status = "VALID"
        model_selection_result = "RANDOM_FOREST_WINNER"
        winner_name = "random_forest"
        winner_wrapper = rf_wrapper
        winner_val_metrics = rf_val_metrics
        winner_thresh = rf_opt_thresh
        print(f"\n[+] Selected Winner Model: '{winner_name}' (Validation F1 = {winner_val_metrics['f1_score']}, Threshold = {winner_thresh})")
    else:
        model_selection_status = "NOT_SCIENTIFICALLY_EVALUABLE"
        model_selection_result = "TIED_NOT_EVALUABLE"
        winner_name = "random_forest"
        winner_wrapper = rf_wrapper
        winner_val_metrics = rf_val_metrics
        winner_thresh = 0.5
        print("\n[!] NOTICE: Random Forest and XGBoost tied on validation metrics (F1 = 0.5000). "
              "No scientifically superior winner can be established on this synthetic fixture (Validation N=3). "
              "Setting model_selection_status = 'NOT_SCIENTIFICALLY_EVALUABLE' and designating 'random_forest' as engineering fallback baseline.")

    # 4. Evaluate Models ONCE on Untouched Test Set (N=3)
    rf_test_proba = rf_wrapper.predict_proba(X_test)
    xgb_test_proba = xgb_wrapper.predict_proba(X_test)

    rf_test_metrics = calculate_metrics(y_test, rf_test_proba, threshold=0.5)
    xgb_test_metrics = calculate_metrics(y_test, xgb_test_proba, threshold=0.5)

    rf_test_metrics["test_evaluation_mode"] = "ENGINEERING_SMOKE_EVALUATION"
    xgb_test_metrics["test_evaluation_mode"] = "ENGINEERING_SMOKE_EVALUATION"

    rf_latency = measure_inference_latency(rf_wrapper, X_test)
    xgb_latency = measure_inference_latency(xgb_wrapper, X_test)

    rf_test_metrics["inference_latency"] = rf_latency
    xgb_test_metrics["inference_latency"] = xgb_latency

    winner_test_metrics = rf_test_metrics if winner_name == "random_forest" else xgb_test_metrics

    print("\n[+] Final Model Evaluation on Test Set (Threshold = 0.5):")
    print(pd.DataFrame([
        {
            "Model": "Random Forest (Test)",
            "Accuracy": rf_test_metrics["accuracy"],
            "Precision": rf_test_metrics["precision"],
            "Recall": rf_test_metrics["recall"],
            "F1": rf_test_metrics["f1_score"],
            "ROC-AUC": rf_test_metrics["roc_auc"],
            "PR-AUC": rf_test_metrics["pr_auc"],
            "FPR": rf_test_metrics["false_positive_rate"],
            "FNR": rf_test_metrics["false_negative_rate"],
            "Mode": rf_test_metrics["test_evaluation_mode"],
            "Avg Latency (ms)": rf_latency["average_time_per_sample_ms"],
        },
        {
            "Model": "XGBoost (Test)",
            "Accuracy": xgb_test_metrics["accuracy"],
            "Precision": xgb_test_metrics["precision"],
            "Recall": xgb_test_metrics["recall"],
            "F1": xgb_test_metrics["f1_score"],
            "ROC-AUC": xgb_test_metrics["roc_auc"],
            "PR-AUC": xgb_test_metrics["pr_auc"],
            "FPR": xgb_test_metrics["false_positive_rate"],
            "FNR": xgb_test_metrics["false_negative_rate"],
            "Mode": xgb_test_metrics["test_evaluation_mode"],
            "Avg Latency (ms)": xgb_latency["average_time_per_sample_ms"],
        }
    ]).to_string(index=False))

    # 5. Save Feature Importances
    rf_imp = rf_wrapper.get_feature_importances()
    rf_imp["model"] = "random_forest"
    xgb_imp = xgb_wrapper.get_feature_importances()
    xgb_imp["model"] = "xgboost"

    if (rf_imp["importance"] == 0).all() and (xgb_imp["importance"] == 0).all():
        print("  - NOTICE: Feature importances are all zero on this fixture dataset and cannot be interpreted as scientific feature rankings.")

    os.makedirs(output_dir, exist_ok=True)
    rf_imp_path = os.path.join(output_dir, f"random_forest_feature_importance_{dataset_version}.csv")
    xgb_imp_path = os.path.join(output_dir, f"xgboost_feature_importance_{dataset_version}.csv")
    rf_imp.to_csv(rf_imp_path, index=False)
    xgb_imp.to_csv(xgb_imp_path, index=False)

    # Class distributions
    train_class_dist = {"benign": int((y_train == 0).sum()), "malware": int((y_train == 1).sum())}
    val_class_dist = {"benign": int((y_val == 0).sum()), "malware": int((y_val == 1).sum())}
    test_class_dist = {"benign": int((y_test == 0).sum()), "malware": int((y_test == 1).sum())}

    dataset_report_path = os.path.join(dataset_dir, f"dataset_report_{dataset_version}.json")
    dataset_fp = ""
    if os.path.exists(dataset_report_path):
        with open(dataset_report_path, "r", encoding="utf-8") as f:
            d_rep = json.load(f)
            dataset_fp = d_rep.get("dataset_fingerprint", "")

    synthetic_warning = (
        "WARNING: This evaluation uses 20 synthetic/safe PE engineering fixtures. "
        "The results validate the ML pipeline and implementation only. "
        "They must NOT be interpreted as real-world malware detection performance."
    )

    # 6. Save Separate Models & Winner Model via ModelRegistry
    # A. Save Random Forest Artifacts
    rf_paths = ModelRegistry.save_model(
        output_dir=output_dir,
        model_name=f"random_forest_static_{dataset_version}",
        model_obj=rf_wrapper,
        model_type="random_forest",
        hyperparameters=rf_wrapper.get_params(),
        threshold=rf_opt_thresh,
        train_count=len(train_df),
        val_count=len(val_df),
        test_count=len(test_df),
        dataset_version=dataset_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_version="static-baseline-v1",
        evaluation_status=dataset_quality["evaluation_status"],
        dataset_type=dataset_quality["dataset_type"],
        dataset_provenance_status=dataset_quality["dataset_provenance_status"],
        dataset_fingerprint=dataset_fp,
        scientific_benchmark_available=dataset_quality["scientific_benchmark_available"],
        structurally_valid=dataset_quality["structurally_valid"],
        scientifically_benchmark_ready=dataset_quality["scientifically_benchmark_ready"],
        statistically_powerful=dataset_quality["statistically_powerful"],
        train_class_dist=train_class_dist,
        val_class_dist=val_class_dist,
        test_class_dist=test_class_dist,
    )

    # B. Save XGBoost Artifacts
    xgb_paths = ModelRegistry.save_model(
        output_dir=output_dir,
        model_name=f"xgboost_static_{dataset_version}",
        model_obj=xgb_wrapper,
        model_type="xgboost",
        hyperparameters=xgb_wrapper.get_params(),
        threshold=xgb_opt_thresh,
        train_count=len(train_df),
        val_count=len(val_df),
        test_count=len(test_df),
        dataset_version=dataset_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_version="static-baseline-v1",
        evaluation_status=dataset_quality["evaluation_status"],
        dataset_type=dataset_quality["dataset_type"],
        dataset_provenance_status=dataset_quality["dataset_provenance_status"],
        dataset_fingerprint=dataset_fp,
        scientific_benchmark_available=dataset_quality["scientific_benchmark_available"],
        structurally_valid=dataset_quality["structurally_valid"],
        scientifically_benchmark_ready=dataset_quality["scientifically_benchmark_ready"],
        statistically_powerful=dataset_quality["statistically_powerful"],
        train_class_dist=train_class_dist,
        val_class_dist=val_class_dist,
        test_class_dist=test_class_dist,
    )

    # C. Save Locked Winner Model Artifacts
    model_name_tag = f"static_baseline_{dataset_version}"
    registry_paths = ModelRegistry.save_model(
        output_dir=output_dir,
        model_name=model_name_tag,
        model_obj=winner_wrapper,
        model_type=winner_name,
        hyperparameters=winner_wrapper.get_params(),
        threshold=winner_thresh,
        train_count=len(train_df),
        val_count=len(val_df),
        test_count=len(test_df),
        dataset_version=dataset_version,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        model_version="static-baseline-v1",
        evaluation_status=dataset_quality["evaluation_status"],
        dataset_type=dataset_quality["dataset_type"],
        dataset_provenance_status=dataset_quality["dataset_provenance_status"],
        dataset_fingerprint=dataset_fp,
        scientific_benchmark_available=dataset_quality["scientific_benchmark_available"],
        structurally_valid=dataset_quality["structurally_valid"],
        scientifically_benchmark_ready=dataset_quality["scientifically_benchmark_ready"],
        statistically_powerful=dataset_quality["statistically_powerful"],
        train_class_dist=train_class_dist,
        val_class_dist=val_class_dist,
        test_class_dist=test_class_dist,
    )

    # 7. Save Metrics JSON, Comparison Report JSON, and Environment JSON
    metrics_json_path = os.path.join(output_dir, f"{model_name_tag}_metrics.json")
    rf_metrics_json_path = os.path.join(output_dir, f"random_forest_static_{dataset_version}_metrics.json")
    xgb_metrics_json_path = os.path.join(output_dir, f"xgboost_static_{dataset_version}_metrics.json")
    comparison_json_path = os.path.join(output_dir, f"static_model_comparison_{dataset_version}.json")

    rf_test_metrics = calculate_metrics(y_test, rf_wrapper.predict_proba(X_test), threshold=rf_opt_thresh)
    xgb_test_metrics = calculate_metrics(y_test, xgb_wrapper.predict_proba(X_test), threshold=xgb_opt_thresh)

    rf_payload = {
        "model_name": "random_forest",
        "dataset_version": dataset_version,
        "dataset_provenance_status": dataset_quality["dataset_provenance_status"],
        "dataset_fingerprint": dataset_fp,
        "validation_metrics": rf_val_metrics,
        "test_metrics": rf_test_metrics,
        "synthetic_dataset_warning": synthetic_warning,
    }
    with open(rf_metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(rf_payload, f, indent=2)

    xgb_payload = {
        "model_name": "xgboost",
        "dataset_version": dataset_version,
        "dataset_provenance_status": dataset_quality["dataset_provenance_status"],
        "dataset_fingerprint": dataset_fp,
        "scale_pos_weight": scale_pos_weight,
        "validation_metrics": xgb_val_metrics,
        "test_metrics": xgb_test_metrics,
        "synthetic_dataset_warning": synthetic_warning,
    }
    with open(xgb_metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(xgb_payload, f, indent=2)

    all_metrics_payload = {
        "dataset_quality": dataset_quality,
        "dataset_fingerprint": dataset_fp,
        "model_selection": {
            "winner_model": winner_name,
            "selection_metric": "f1_score",
            "model_selection_status": model_selection_status,
            "locked_threshold": winner_thresh,
        },
        "validation_comparison": {
            "random_forest": rf_val_metrics,
            "xgboost": xgb_val_metrics,
        },
        "final_test_evaluation": winner_test_metrics,
        "synthetic_dataset_warning": synthetic_warning,
    }
    with open(metrics_json_path, "w", encoding="utf-8") as f:
        json.dump(all_metrics_payload, f, indent=2)

    comparison_report_payload = {
        "benchmark_title": "PolyShield AI Static ML Baseline Benchmark (Random Forest vs XGBoost)",
        "dataset_version": dataset_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "dataset_provenance_status": dataset_quality["dataset_provenance_status"],
        "dataset_fingerprint": dataset_fp,
        "structurally_valid": dataset_quality["structurally_valid"],
        "scientifically_benchmark_ready": dataset_quality["scientifically_benchmark_ready"],
        "statistically_powerful": dataset_quality["statistically_powerful"],
        "sample_counts": {
            "total": len(train_df) + len(val_df) + len(test_df),
            "train": len(train_df),
            "validation": len(val_df),
            "test": len(test_df),
        },
        "models_evaluated": ["random_forest", "xgboost"],
        "xgb_scale_pos_weight": scale_pos_weight,
        "winner_model": winner_name,
        "winner_threshold": winner_thresh,
        "validation_results": {
            "random_forest": rf_val_metrics,
            "xgboost": xgb_val_metrics,
        },
        "test_results": {
            "random_forest": rf_test_metrics,
            "xgboost": xgb_test_metrics,
            "winner_locked_test": winner_test_metrics,
        },
        "statistical_disclaimer": "N=20 total samples (Train=14, Val=3, Test=3). Results evaluate software pipeline execution and are insufficient for statistical generalization claims.",
        "synthetic_dataset_warning": synthetic_warning,
    }
    with open(comparison_json_path, "w", encoding="utf-8") as f:
        json.dump(comparison_report_payload, f, indent=2)

    env_json_path = os.path.join(output_dir, f"environment_{dataset_version}.json")
    env_info = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "scikit_learn_version": sklearn.__version__,
        "xgboost_version": xgboost.__version__,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "random_state": random_state,
        "dataset_version": dataset_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "model_version": "static-baseline-v1",
    }
    with open(env_json_path, "w", encoding="utf-8") as f:
        json.dump(env_info, f, indent=2)

    print(f"\n[+] Phase 5 Pipeline Execution Complete! Artifacts saved to '{output_dir}':")
    print(f"    - RF Model: {rf_paths['model_path']}")
    print(f"    - XGB Model: {xgb_paths['model_path']}")
    print(f"    - Winner Model: {registry_paths['model_path']}")
    print(f"    - Comparison Report JSON: {comparison_json_path}")
    print(f"    - Environment Info: {env_json_path}")
    print(f"    - RF Feature Importance: {rf_imp_path}")
    print(f"    - XGB Feature Importance: {xgb_imp_path}")

    return {
        "winner_name": winner_name,
        "winner_thresh": winner_thresh,
        "dataset_quality": dataset_quality,
        "rf_val_metrics": rf_val_metrics,
        "xgb_val_metrics": xgb_val_metrics,
        "test_metrics": winner_test_metrics,
        "paths": {
            **registry_paths,
            "rf_model_path": rf_paths['model_path'],
            "xgb_model_path": xgb_paths['model_path'],
            "metrics_path": metrics_json_path,
            "comparison_path": comparison_json_path,
            "env_path": env_json_path,
            "rf_imp_path": rf_imp_path,
            "xgb_imp_path": xgb_imp_path,
        }
    }


def main():
    parser = argparse.ArgumentParser(description="PolyShield AI - Phase 5.1 Static ML Baseline Hardened Pipeline")
    parser.add_argument("--dataset-dir", type=str, default="ml/artifacts/dataset", help="Directory containing dataset artifacts")
    parser.add_argument("--output-dir", type=str, default="ml/artifacts/models", help="Directory for model output artifacts")
    parser.add_argument("--version", type=str, default=DEFAULT_DATASET_VERSION, help="Dataset version tag")
    parser.add_argument("--random-state", type=int, default=42, help="Random state seed")
    parser.add_argument("--threshold", type=float, default=None, help="Override classification threshold")
    parser.add_argument("--strict-evaluation", action="store_true", help="Fail if dataset splits lack binary class coverage for scientific benchmarking")

    args = parser.parse_args()

    train_static_baseline(
        dataset_dir=args.dataset_dir,
        output_dir=args.output_dir,
        dataset_version=args.version,
        random_state=args.random_state,
        override_threshold=args.threshold,
        strict_evaluation=args.strict_evaluation,
    )


if __name__ == "__main__":
    main()
