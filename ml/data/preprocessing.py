from typing import Tuple, List
import pandas as pd
import numpy as np
from ml.data.constants import FEATURE_NAMES, FEATURE_SCHEMA_VERSION


class DatasetPreprocessor:
    """
    Dataset Preprocessor for PolyShield AI.
    Converts validated raw/processed dataset DataFrames into canonical supervised learning matrices X and y.
    """
    def __init__(self, schema_version: str = FEATURE_SCHEMA_VERSION):
        self.schema_version = schema_version
        self.feature_names = FEATURE_NAMES

    def extract_features_and_target(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Extracts feature matrix X and target vector y from a dataset DataFrame.
        Filters out failed static analyses (analysis_success == False).
        """
        if "analysis_success" in df.columns:
            valid_df = df[df["analysis_success"] == True].copy()
        else:
            valid_df = df.copy()

        if valid_df.empty:
            raise ValueError("No valid successful analysis records found to extract features from.")

        if "label" not in valid_df.columns:
            raise ValueError("Missing target column 'label' in DataFrame.")

        # 1. Target Vector y
        y = valid_df["label"].astype(np.int64).copy()
        y.name = "label"

        # 2. Enforce Canonical 17 Features in Exact Order
        X = valid_df[self.feature_names].copy()

        # Convert to float64 and normalize booleans
        for col in self.feature_names:
            X[col] = X[col].astype(np.float64)

        # Invariants Check
        assert X.shape[1] == 17, f"Feature matrix X must have exactly 17 columns, got {X.shape[1]}"
        assert list(X.columns) == self.feature_names, "Feature matrix X columns do not match canonical FEATURE_NAMES order."
        assert "label" not in X.columns, "Target column 'label' must not be in feature matrix X."
        assert "sha256" not in X.columns, "Metadata column 'sha256' must not be in feature matrix X."
        assert "sample_id" not in X.columns, "Metadata column 'sample_id' must not be in feature matrix X."
        assert list(X.columns).count("file_size") == 1, "Feature 'file_size' must appear exactly once in feature matrix X."

        return X, y
