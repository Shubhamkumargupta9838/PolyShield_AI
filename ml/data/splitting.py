import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Optional


class DatasetSplitter:
    """
    Dataset Splitting Engine for PolyShield AI.
    Splits dataset into 70% Train, 15% Validation, 15% Test sets.
    Prevents data leakage by ensuring identical SHA-256 hashes or group IDs never cross split boundaries.
    """
    def __init__(self, random_state: int = 42):
        self.random_state = random_state

    def split_dataset(
        self,
        df: pd.DataFrame,
        train_ratio: float = 0.70,
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        group_aware: bool = False
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
        """
        Splits dataset into train, validation, and test sets.
        Enforces hash deduplication leakage prevention by grouping unique hashes first.
        Returns (train_df, val_df, test_df, split_info_dict).
        """
        if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-4:
            raise ValueError("Train, validation, and test ratios must sum to 1.0.")

        # Exclude failed analyses from training splits
        valid_df = df[df["analysis_success"] == True].copy()
        if valid_df.empty:
            raise ValueError("No successful analysis records available to split.")

        total_samples = len(valid_df)

        # Determine grouping key: SHA-256 hash or group_id
        if group_aware and "group_id" in valid_df.columns and valid_df["group_id"].notna().any():
            split_key = "group_id"
            strategy = "group_aware"
        elif group_aware and "family" in valid_df.columns and valid_df["family"].notna().any():
            split_key = "family"
            strategy = "group_aware"
        else:
            split_key = "sha256"
            strategy = "stratified_hash_deduplicated"

        # Assign fallback key if grouping key is missing for an item
        keys = valid_df[split_key].fillna(valid_df["sample_id"]).values
        valid_df["_split_key"] = keys

        unique_keys = np.unique(keys)
        n_unique = len(unique_keys)

        # Deterministic shuffle of unique group keys
        rng = np.random.RandomState(self.random_state)
        shuffled_keys = rng.permutation(unique_keys)

        if n_unique == 1:
            # Single group edge case: all items share same hash
            train_keys = set(shuffled_keys)
            val_keys = set()
            test_keys = set()
            strategy = f"{strategy}_single_group"
        elif n_unique == 2:
            train_keys = {shuffled_keys[0]}
            val_keys = {shuffled_keys[1]}
            test_keys = set()
            strategy = f"{strategy}_two_groups"
        else:
            n_train_keys = max(1, int(round(n_unique * train_ratio)))
            n_val_keys = max(1, int(round(n_unique * val_ratio)))
            if n_train_keys + n_val_keys >= n_unique:
                n_val_keys = max(1, n_unique - n_train_keys)

            train_keys = set(shuffled_keys[:n_train_keys])
            val_keys = set(shuffled_keys[n_train_keys:n_train_keys + n_val_keys])
            test_keys = set(shuffled_keys[n_train_keys + n_val_keys:])

        train_df = valid_df[valid_df["_split_key"].isin(train_keys)].drop(columns=["_split_key"]).copy()
        val_df = valid_df[valid_df["_split_key"].isin(val_keys)].drop(columns=["_split_key"]).copy()
        test_df = valid_df[valid_df["_split_key"].isin(test_keys)].drop(columns=["_split_key"]).copy()

        # Leakage Verification Assertion: Check SHA-256 sets between splits do not intersect
        train_hashes = set(train_df[train_df["sha256"].notna()]["sha256"])
        val_hashes = set(val_df[val_df["sha256"].notna()]["sha256"])
        test_hashes = set(test_df[test_df["sha256"].notna()]["sha256"])

        assert len(train_hashes.intersection(val_hashes)) == 0, "DATA LEAKAGE DETECTED: Duplicate SHA-256 hash in train and val splits!"
        assert len(train_hashes.intersection(test_hashes)) == 0, "DATA LEAKAGE DETECTED: Duplicate SHA-256 hash in train and test splits!"
        assert len(val_hashes.intersection(test_hashes)) == 0, "DATA LEAKAGE DETECTED: Duplicate SHA-256 hash in val and test splits!"

        split_info: Dict[str, Any] = {
            "strategy": strategy,
            "random_state": self.random_state,
            "train_count": len(train_df),
            "val_count": len(val_df),
            "test_count": len(test_df),
            "actual_train_ratio": round(len(train_df) / total_samples, 4) if total_samples > 0 else 0.0,
            "actual_val_ratio": round(len(val_df) / total_samples, 4) if total_samples > 0 else 0.0,
            "actual_test_ratio": round(len(test_df) / total_samples, 4) if total_samples > 0 else 0.0,
            "group_key_used": split_key
        }

        return train_df, val_df, test_df, split_info
