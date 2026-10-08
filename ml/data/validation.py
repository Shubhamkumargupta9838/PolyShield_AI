from typing import Dict, List, Any, Tuple
import pandas as pd
import numpy as np
from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


class DatasetValidationError(Exception):
    """Raised when a dataset fails schema, numeric, or range validation."""
    pass


class DatasetValidator:
    """
    Validation engine for PolyShield AI ML Datasets.
    Enforces schema invariants, numeric sanitization, logical range checks, and duplicate detection.
    """

    @classmethod
    def validate_dataset(cls, df: pd.DataFrame, strict: bool = True) -> Dict[str, Any]:
        report: Dict[str, Any] = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "total_records": len(df),
            "successful_analyses": 0,
            "failed_analyses": 0,
            "duplicate_sha256_groups": 0,
            "duplicate_records_count": 0,
        }

        if df.empty:
            report["is_valid"] = False
            report["errors"].append("Dataset DataFrame is empty.")
            if strict:
                raise DatasetValidationError("Dataset DataFrame is empty.")
            return report

        # 1. Required Metadata Columns Check
        required_meta = ["sample_id", "filename", "sha256", "label", "analysis_success", "feature_schema_version"]
        for col in required_meta:
            if col not in df.columns:
                report["is_valid"] = False
                report["errors"].append(f"Missing required metadata column '{col}'.")

        # 2. Canonical 17 Features Check
        for fname in FEATURE_NAMES:
            if fname not in df.columns:
                report["is_valid"] = False
                report["errors"].append(f"Missing canonical feature column '{fname}'.")

        if not report["is_valid"] and strict:
            raise DatasetValidationError(f"Schema validation failed: {report['errors']}")

        # 3. Successful vs Failed Analysis Check
        successful_df = df[df["analysis_success"] == True]
        failed_df = df[df["analysis_success"] == False]

        report["successful_analyses"] = len(successful_df)
        report["failed_analyses"] = len(failed_df)

        # 4. Duplicate SHA-256 Check
        valid_hashes = df[df["sha256"].notna()]["sha256"]
        dupe_mask = valid_hashes.duplicated(keep=False)
        dupe_hashes = valid_hashes[dupe_mask].unique()

        report["duplicate_sha256_groups"] = len(dupe_hashes)
        report["duplicate_records_count"] = len(valid_hashes[dupe_mask])

        if len(dupe_hashes) > 0:
            report["warnings"].append(f"Found {len(dupe_hashes)} SHA-256 duplicate hash group(s) containing {report['duplicate_records_count']} total records.")

        # 5. Numeric & Range Validation on Successful Analyses
        if not successful_df.empty:
            for fname in FEATURE_NAMES:
                vals = successful_df[fname]

                # Check for NaN / Inf
                if vals.isna().any():
                    report["is_valid"] = False
                    report["errors"].append(f"NaN values detected in feature '{fname}'.")

                if np.isinf(vals).any():
                    report["is_valid"] = False
                    report["errors"].append(f"Infinite values detected in feature '{fname}'.")

            # Range & Consistency Rules
            for idx, row in successful_df.iterrows():
                # Entropy bounds 0 <= e <= 8
                for e_col in ["max_section_entropy", "min_section_entropy", "mean_section_entropy"]:
                    val = row[e_col]
                    if val < 0.0 or val > 8.0:
                        report["is_valid"] = False
                        report["errors"].append(f"Row '{row['sample_id']}': '{e_col}' value {val} out of range [0.0, 8.0].")

                # Min <= Mean <= Max entropy consistency
                num_sec = row["number_of_sections"]
                if num_sec > 0:
                    if not (row["min_section_entropy"] <= row["mean_section_entropy"] <= row["max_section_entropy"] + 1e-4):
                        report["is_valid"] = False
                        report["errors"].append(f"Row '{row['sample_id']}': Inconsistent entropy ordering (min={row['min_section_entropy']}, mean={row['mean_section_entropy']}, max={row['max_section_entropy']}).")

                # Section Count Consistency
                for count_col in ["high_entropy_section_count", "executable_section_count", "writable_section_count", "rwx_section_count", "unusual_section_count"]:
                    c_val = row[count_col]
                    if c_val < 0:
                        report["is_valid"] = False
                        report["errors"].append(f"Row '{row['sample_id']}': Negative section count '{count_col}' = {c_val}.")
                    if c_val > num_sec:
                        report["is_valid"] = False
                        report["errors"].append(f"Row '{row['sample_id']}': Section count '{count_col}' ({c_val}) exceeds total sections ({num_sec}).")

        if not report["is_valid"] and strict:
            raise DatasetValidationError(f"Dataset validation failed: {report['errors']}")

        return report
