import os
import json
import hashlib
from typing import Dict, Any
import pandas as pd
import numpy as np
from ml.data.constants import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    DEFAULT_DATASET_VERSION
)
from ml.data.dataset_quality import inspect_dataset_quality


def compute_dataset_fingerprint(df: pd.DataFrame, version: str) -> str:
    """
    Computes a deterministic content fingerprint for the dataset based on sorted unique SHA-256 values,
    labels, and schema versions. Does NOT include volatile timestamps.
    """
    sha_series = df[df["sha256"].notna()]["sha256"].sort_values()
    sha_str = ",".join(sha_series.tolist())
    labels_str = ",".join(df["label"].astype(str).tolist())
    raw_payload = f"version:{version}|schema:{FEATURE_SCHEMA_VERSION}|hashes:{sha_str}|labels:{labels_str}"
    return hashlib.sha256(raw_payload.encode('utf-8')).hexdigest()


def generate_dataset_report(
    full_df: pd.DataFrame,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    split_info: Dict[str, Any],
    dataset_version: str = DEFAULT_DATASET_VERSION
) -> Dict[str, Any]:
    """
    Generates a comprehensive JSON dataset report detailing counts, class balance, duplicate stats,
    split ratios, dataset quality audit, feature summary statistics, and dataset fingerprint.
    """
    successful_df = full_df[full_df["analysis_success"] == True]

    benign_count = int((full_df["label"] == 0).sum())
    malware_count = int((full_df["label"] == 1).sum())

    total_records = len(full_df)
    class_ratio = round(malware_count / benign_count, 4) if benign_count > 0 else 0.0

    valid_hashes = full_df[full_df["sha256"].notna()]["sha256"]
    dupe_mask = valid_hashes.duplicated(keep=False)
    dupe_groups_count = len(valid_hashes[dupe_mask].unique())
    dupe_records_count = int(dupe_mask.sum())

    quality_audit = inspect_dataset_quality(train_df, val_df, test_df, full_df=full_df)

    feature_stats: Dict[str, Dict[str, Any]] = {}
    if not successful_df.empty:
        for fname in FEATURE_NAMES:
            series = successful_df[fname].astype(np.float64)
            feature_stats[fname] = {
                "dtype": "float64",
                "min": float(series.min()),
                "max": float(series.max()),
                "mean": round(float(series.mean()), 4),
                "median": round(float(series.median()), 4),
                "std": round(float(series.std()), 4) if len(series) > 1 else 0.0
            }

    fingerprint = compute_dataset_fingerprint(full_df, dataset_version)

    report: Dict[str, Any] = {
        "dataset_version": dataset_version,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "dataset_type": quality_audit["dataset_type"],
        "dataset_provenance_status": quality_audit["dataset_provenance_status"],
        "verified_real_sample_count": quality_audit["verified_real_sample_count"],
        "synthetic_sample_count": quality_audit["synthetic_sample_count"],
        "safe_fixture_sample_count": quality_audit["safe_fixture_sample_count"],
        "unverified_sample_count": quality_audit["unverified_sample_count"],
        "structurally_valid": quality_audit["structurally_valid"],
        "scientifically_benchmark_ready": quality_audit["scientifically_benchmark_ready"],
        "statistically_powerful": quality_audit["statistically_powerful"],
        "scientific_benchmark_available": quality_audit["scientific_benchmark_available"],
        "evaluation_status": quality_audit["evaluation_status"],
        "dataset_fingerprint": fingerprint,
        "total_manifest_records": total_records,
        "total_unique_samples": len(full_df["filename"].unique()) if "filename" in full_df.columns else len(full_df),
        "successful_analyses": len(successful_df),
        "failed_analyses": int((full_df["analysis_success"] == False).sum()),
        "benign_count": benign_count,
        "malware_count": malware_count,
        "class_ratio": class_ratio,
        "duplicate_record_count": dupe_records_count,
        "duplicate_hash_group_count": dupe_groups_count,
        "missing_value_count": int(successful_df[FEATURE_NAMES].isna().sum().sum()) if not successful_df.empty else 0,
        "quality_audit": quality_audit,
        "split_information": split_info,
        "feature_statistics": feature_stats
    }

    return report


def save_dataset_artifacts(
    output_dir: str,
    full_df: pd.DataFrame,
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    report: Dict[str, Any],
    version: str = DEFAULT_DATASET_VERSION
) -> Dict[str, str]:
    """
    Saves dataset CSV artifacts and JSON dataset report to output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)

    paths = {
        "dataset_csv": os.path.join(output_dir, f"dataset_{version}.csv"),
        "train_csv": os.path.join(output_dir, f"train_{version}.csv"),
        "validation_csv": os.path.join(output_dir, f"validation_{version}.csv"),
        "test_csv": os.path.join(output_dir, f"test_{version}.csv"),
        "dataset_manifest_csv": os.path.join(output_dir, f"dataset_manifest_{version}.csv"),
        "report_json": os.path.join(output_dir, f"dataset_report_{version}.json")
    }

    full_df.to_csv(paths["dataset_csv"], index=False)
    train_df.to_csv(paths["train_csv"], index=False)
    val_df.to_csv(paths["validation_csv"], index=False)
    test_df.to_csv(paths["test_csv"], index=False)

    meta_cols = [c for c in ["sample_id", "filename", "sha256", "label", "label_name", "source", "family", "group_id", "analysis_success", "analysis_error", "dataset_version", "feature_schema_version"] if c in full_df.columns]
    full_df[meta_cols].to_csv(paths["dataset_manifest_csv"], index=False)

    with open(paths["report_json"], "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return paths
