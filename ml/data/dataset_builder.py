import os
import uuid
import hashlib
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd

from analysis.static.extractor import StaticFeatureExtractor
from ml.data.constants import (
    FEATURE_NAMES,
    LABEL_MAPPING,
    FEATURE_SCHEMA_VERSION,
    DEFAULT_DATASET_VERSION
)


def compute_dataset_fingerprint(df: pd.DataFrame) -> str:
    """
    Computes a deterministic dataset fingerprint by hashing sorted canonical sample records (sha256 + label + family).
    """
    if df.empty or "sha256" not in df.columns:
        return "empty_dataset_fingerprint"

    valid_df = df[df["analysis_success"] == True] if "analysis_success" in df.columns else df
    if valid_df.empty:
        return "empty_valid_dataset_fingerprint"

    sorted_records = []
    for _, row in valid_df.sort_values(by="sha256").iterrows():
        sha = str(row.get("sha256", ""))
        lbl = str(row.get("label", ""))
        fam = str(row.get("family", "")) if pd.notna(row.get("family")) else ""
        sorted_records.append(f"{sha}:{lbl}:{fam}")

    raw_str = "|".join(sorted_records)
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()


class DatasetBuilder:
    """
    ML Dataset Builder for PolyShield AI.
    Processes PE samples according to an explicit manifest, invokes Phase 3 StaticFeatureExtractor in-memory,
    deduplicates by SHA-256 before splitting, and returns a structured Dataset DataFrame.
    """
    def __init__(self, dataset_version: str = DEFAULT_DATASET_VERSION):
        self.dataset_version = dataset_version
        self.feature_schema_version = FEATURE_SCHEMA_VERSION
        self.extractor = StaticFeatureExtractor()

    def build_from_manifest(
        self,
        manifest_df: pd.DataFrame,
        samples_dir: str
    ) -> pd.DataFrame:
        """
        Builds a dataset from a manifest DataFrame and samples directory.
        manifest_df must contain columns: 'filename', 'label'. Optional: 'family', 'group_id', 'source'.
        """
        if 'filename' not in manifest_df.columns or 'label' not in manifest_df.columns:
            raise ValueError("Manifest DataFrame must contain 'filename' and 'label' columns.")

        records: List[Dict[str, Any]] = []

        for _, row in manifest_df.iterrows():
            filename = str(row['filename'])
            raw_label = row['label']

            # Validate label
            if pd.isna(raw_label) or int(raw_label) not in (0, 1):
                raise ValueError(f"Invalid label '{raw_label}' for filename '{filename}'. Label must be 0 (benign) or 1 (malware).")

            label = int(raw_label)
            label_name = LABEL_MAPPING[label]
            family = str(row.get('family', '')) if pd.notna(row.get('family')) and str(row.get('family')).strip() else None
            group_id = str(row.get('group_id', '')) if pd.notna(row.get('group_id')) and str(row.get('group_id')).strip() else None
            source = str(row.get('source', 'unknown')) if pd.notna(row.get('source')) else 'unknown'

            sample_path = os.path.join(samples_dir, filename)
            sample_id = str(uuid.uuid4())

            record: Dict[str, Any] = {
                "sample_id": sample_id,
                "filename": filename,
                "sha256": None,
                "label": label,
                "label_name": label_name,
                "source": source,
                "family": family,
                "group_id": group_id,
                "analysis_success": False,
                "analysis_error": None,
                "dataset_version": self.dataset_version,
                "feature_schema_version": self.feature_schema_version
            }

            for fname in FEATURE_NAMES:
                record[fname] = None

            if not os.path.exists(sample_path):
                record["analysis_error"] = f"File not found: {sample_path}"
                records.append(record)
                continue

            try:
                with open(sample_path, "rb") as f:
                    file_bytes = f.read()

                record["sha256"] = hashlib.sha256(file_bytes).hexdigest()

                if len(file_bytes) == 0:
                    record["analysis_error"] = "Empty file (0 bytes)"
                    records.append(record)
                    continue

                # Run Phase 3 Static Feature Extractor in-memory
                result = self.extractor.extract_from_bytes(file_bytes, filename)
                vec_dict = self.extractor.vectorize(result).to_dict()

                for fname in FEATURE_NAMES:
                    record[fname] = vec_dict[fname]

                record["analysis_success"] = True

            except Exception as e:
                record["analysis_success"] = False
                record["analysis_error"] = str(e)

            records.append(record)

        df = pd.DataFrame(records)
        return df

    def build_from_bytes_list(
        self,
        samples_data: List[Tuple[str, bytes, int, Optional[str], Optional[str]]]
    ) -> pd.DataFrame:
        """
        In-memory helper for testing & programmatic sample processing.
        samples_data elements: (filename, file_bytes, label, family, group_id)
        """
        records: List[Dict[str, Any]] = []

        for item in samples_data:
            filename, file_bytes, label, family, group_id = item
            sample_id = str(uuid.uuid4())
            label = int(label)

            record: Dict[str, Any] = {
                "sample_id": sample_id,
                "filename": filename,
                "sha256": hashlib.sha256(file_bytes).hexdigest() if file_bytes else None,
                "label": label,
                "label_name": LABEL_MAPPING[label],
                "source": "in_memory_fixture",
                "family": family,
                "group_id": group_id,
                "analysis_success": False,
                "analysis_error": None,
                "dataset_version": self.dataset_version,
                "feature_schema_version": self.feature_schema_version
            }

            for fname in FEATURE_NAMES:
                record[fname] = None

            if not file_bytes:
                record["analysis_error"] = "Empty bytes buffer"
                records.append(record)
                continue

            try:
                result = self.extractor.extract_from_bytes(file_bytes, filename)
                vec_dict = self.extractor.vectorize(result).to_dict()
                for fname in FEATURE_NAMES:
                    record[fname] = vec_dict[fname]
                record["analysis_success"] = True
            except Exception as e:
                record["analysis_error"] = str(e)

            records.append(record)

        return pd.DataFrame(records)
