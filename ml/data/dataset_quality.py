from enum import Enum
import pandas as pd
from typing import Dict, Any, List


class EvaluationStatus(str, Enum):
    VALID = "VALID"
    INSUFFICIENT_CLASS_COVERAGE = "INSUFFICIENT_CLASS_COVERAGE"


class DatasetProvenanceStatus(str, Enum):
    VERIFIED_REAL_EXTERNAL_DATA = "VERIFIED_REAL_EXTERNAL_DATA"
    MIXED_REAL_AND_SYNTHETIC = "MIXED_REAL_AND_SYNTHETIC"
    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
    UNVERIFIED_PROVENANCE = "UNVERIFIED_PROVENANCE"


def inspect_split_quality(df: pd.DataFrame, split_name: str) -> Dict[str, Any]:
    """
    Inspects class distribution, sample counts, and uniqueness for a dataset split.
    """
    sample_count = len(df)
    if sample_count == 0 or "label" not in df.columns:
        return {
            "split_name": split_name,
            "sample_count": sample_count,
            "benign_count": 0,
            "malware_count": 0,
            "class_ratio": 0.0,
            "contains_benign": False,
            "contains_malware": False,
            "has_both_classes": False,
            "unique_sha256_count": 0,
            "duplicate_sha256_count": 0,
            "unique_groups": [],
            "unique_families": [],
        }

    benign_count = int((df["label"] == 0).sum())
    malware_count = int((df["label"] == 1).sum())
    class_ratio = round(malware_count / benign_count, 4) if benign_count > 0 else 0.0

    sha_series = df["sha256"] if "sha256" in df.columns else pd.Series(dtype=str)
    unique_sha_count = int(sha_series.nunique())
    duplicate_sha_count = int(sample_count - unique_sha_count)

    unique_groups = sorted([str(g) for g in df["group_id"].dropna().unique() if str(g).strip()]) if "group_id" in df.columns else []
    unique_families = sorted([str(f) for f in df["family"].dropna().unique() if str(f).strip()]) if "family" in df.columns else []

    contains_benign = benign_count > 0
    contains_malware = malware_count > 0
    has_both_classes = contains_benign and contains_malware

    return {
        "split_name": split_name,
        "sample_count": sample_count,
        "benign_count": benign_count,
        "malware_count": malware_count,
        "class_ratio": class_ratio,
        "contains_benign": contains_benign,
        "contains_malware": contains_malware,
        "has_both_classes": has_both_classes,
        "unique_sha256_count": unique_sha_count,
        "duplicate_sha256_count": duplicate_sha_count,
        "unique_groups": unique_groups,
        "unique_families": unique_families,
    }


def inspect_dataset_quality(train_df: pd.DataFrame, val_df: pd.DataFrame, test_df: pd.DataFrame, full_df: pd.DataFrame = None) -> Dict[str, Any]:
    """
    Evaluates dataset splits quality, sample provenance, and determines three-tier scientific benchmark status.
    """
    train_quality = inspect_split_quality(train_df, "train")
    val_quality = inspect_split_quality(val_df, "validation")
    test_quality = inspect_split_quality(test_df, "test")

    combined_df = full_df if full_df is not None else pd.concat([train_df, val_df, test_df], ignore_index=True)
    total_sample_count = len(combined_df)

    verified_real_count = 0
    synthetic_count = 0
    safe_fixture_count = 0
    unverified_count = 0

    if not combined_df.empty and "source" in combined_df.columns:
        for src in combined_df["source"].dropna():
            src_str = str(src).lower()
            if src_str in ("verified_external", "real_external"):
                verified_real_count += 1
            elif src_str in ("synthetic", "synthetic_fixture", "in_memory_fixture", "project_safe_fixture"):
                synthetic_count += 1
                safe_fixture_count += 1
            elif src_str in ("unverified", "unknown"):
                unverified_count += 1
            else:
                # Default to synthetic safe fixture if not verified external
                synthetic_count += 1
                safe_fixture_count += 1

    if verified_real_count > 0 and synthetic_count == 0 and unverified_count == 0:
        provenance_status = DatasetProvenanceStatus.VERIFIED_REAL_EXTERNAL_DATA.value
    elif verified_real_count > 0:
        provenance_status = DatasetProvenanceStatus.MIXED_REAL_AND_SYNTHETIC.value
    elif unverified_count > 0 and verified_real_count == 0:
        provenance_status = DatasetProvenanceStatus.UNVERIFIED_PROVENANCE.value
    else:
        provenance_status = DatasetProvenanceStatus.SYNTHETIC_FIXTURE.value

    # Three-Tier Scientific Benchmark Status
    structurally_valid = (
        train_quality["has_both_classes"]
        and val_quality["has_both_classes"]
        and test_quality["has_both_classes"]
    )
    scientifically_benchmark_ready = (
        structurally_valid
        and provenance_status == DatasetProvenanceStatus.VERIFIED_REAL_EXTERNAL_DATA.value
        and total_sample_count >= 100
    )
    statistically_powerful = (
        scientifically_benchmark_ready
        and total_sample_count >= 1000
    )

    evaluation_status = (
        EvaluationStatus.VALID.value
        if structurally_valid
        else EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE.value
    )

    dataset_type = "synthetic_fixture" if provenance_status == DatasetProvenanceStatus.SYNTHETIC_FIXTURE.value else ("real_benchmark" if scientifically_benchmark_ready else "mixed_or_unverified")

    warnings = []
    if not train_quality["has_both_classes"]:
        warnings.append("Train split does not contain both benign and malware samples.")
    if not val_quality["has_both_classes"]:
        warnings.append("Validation split does not contain both benign and malware samples.")
    if not test_quality["has_both_classes"]:
        warnings.append("Test split does not contain both benign and malware samples.")

    if provenance_status == DatasetProvenanceStatus.SYNTHETIC_FIXTURE.value:
        warnings.append("Dataset is classified as SYNTHETIC_FIXTURE. Results verify software pipeline engineering, NOT real-world scientific detection performance.")
    elif provenance_status == DatasetProvenanceStatus.UNVERIFIED_PROVENANCE.value:
        warnings.append("Dataset contains samples with UNVERIFIED_PROVENANCE. External dataset origin claims could not be independently verified.")

    if not scientifically_benchmark_ready:
        warnings.append(f"Dataset is NOT scientifically benchmark ready (total samples: {total_sample_count}, provenance: {provenance_status}). Minimum 100 verified real external samples required.")
    if not statistically_powerful:
        warnings.append("Dataset is NOT statistically powerful. High-confidence generalization claims require 1,000+ real-world PE binaries.")

    return {
        "dataset_type": dataset_type,
        "dataset_provenance_status": provenance_status,
        "verified_real_sample_count": verified_real_count,
        "synthetic_sample_count": synthetic_count,
        "safe_fixture_sample_count": safe_fixture_count,
        "unverified_sample_count": unverified_count,
        "structurally_valid": structurally_valid,
        "scientifically_benchmark_ready": scientifically_benchmark_ready,
        "statistically_powerful": statistically_powerful,
        "scientific_benchmark_available": scientifically_benchmark_ready,
        "evaluation_status": evaluation_status,
        "splits": {
            "train": train_quality,
            "validation": val_quality,
            "test": test_quality,
        },
        "warnings": warnings,
    }

