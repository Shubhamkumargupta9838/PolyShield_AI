"""Dynamic Dataset Builder & Sequence Encoder for LSTM Models (Phase 10).

Encodes telemetry event sequences into tensor arrays (X, y) with strict metadata shielding,
deduplication, sequence length padding/truncation, and dataset report generation.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import numpy as np

from ml.data.dynamic_sequence_schema import DynamicBehavioralSequence, DynamicEventToken
from ml.data.dynamic_vocab import EventVocabulary, PAD_ID, UNK_ID


DEFAULT_MAX_SEQUENCE_LENGTH = 256


class DynamicDatasetBuilder:
    """Builder for constructing LSTM training and evaluation datasets from dynamic sequences."""

    def __init__(
        self,
        max_sequence_length: int = DEFAULT_MAX_SEQUENCE_LENGTH,
        vocab: Optional[EventVocabulary] = None,
    ):
        self.max_sequence_length = max_sequence_length
        self.vocab = vocab or EventVocabulary()

    def convert_result_to_sequence(
        self,
        dynamic_result: Any,
        sample_sha256: str,
        label: int = 0,
        family: Optional[str] = "unknown",
        group_id: Optional[str] = None,
    ) -> DynamicBehavioralSequence:
        """Convert a DynamicAnalysisResult model or dict into a DynamicBehavioralSequence."""
        events: List[DynamicEventToken] = []
        raw_events = getattr(dynamic_result, "normalized_events", None) or getattr(dynamic_result, "raw_event_stream", None) or getattr(dynamic_result, "events", None) or []
        if not raw_events and isinstance(dynamic_result, dict):
            raw_events = dynamic_result.get("normalized_events") or dynamic_result.get("raw_event_stream") or dynamic_result.get("events") or []

        last_time = 0
        for ev in raw_events:
            if isinstance(ev, dict):
                rel_time = ev.get("relative_time_ms", 0)
                ev_type = ev.get("event_type", "UNKNOWN")
                ev_cat = ev.get("category", ev.get("event_category", "general"))
                pid = ev.get("pid", ev.get("process_id"))
                meta = ev.get("metadata", {})
            else:
                rel_time = getattr(ev, "relative_time_ms", 0)
                ev_type = getattr(ev, "event_type", "UNKNOWN")
                ev_cat = getattr(ev, "category", getattr(ev, "event_category", "general"))
                pid = getattr(ev, "pid", getattr(ev, "process_id", None))
                meta = getattr(ev, "metadata", {})

            delta_time = max(0, rel_time - last_time)
            last_time = rel_time

            events.append(
                DynamicEventToken(
                    relative_time_ms=rel_time,
                    delta_time_ms=delta_time,
                    event_type=str(ev_type),
                    event_category=str(ev_cat),
                    process_id=pid,
                    metadata=meta if isinstance(meta, dict) else {},
                )
            )

        scan_id = getattr(dynamic_result, "scan_id", None)
        if scan_id is None and isinstance(dynamic_result, dict):
            scan_id = dynamic_result.get("scan_id")

        return DynamicBehavioralSequence(
            sample_id=getattr(dynamic_result, "sample_id", None) or scan_id,
            scan_id=scan_id,
            sample_sha256=sample_sha256,
            label=label,
            family=family,
            group_id=group_id,
            events=events,
        )

    def encode_sequence(self, sequence: DynamicBehavioralSequence) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Encode a single DynamicBehavioralSequence into a fixed-length token vector.

        Returns:
            (encoded_vector of shape (max_sequence_length,), sequence_stats)
        """
        raw_event_types = [e.event_type for e in sequence.events]
        token_ids, unk_count, unk_rate = self.vocab.encode_events(raw_event_types)

        raw_length = len(token_ids)
        is_truncated = raw_length > self.max_sequence_length

        if is_truncated:
            encoded = token_ids[: self.max_sequence_length]
        else:
            # Pad with PAD_ID (0)
            encoded = token_ids + [PAD_ID] * (self.max_sequence_length - raw_length)

        vector = np.array(encoded, dtype=np.int64)

        stats = {
            "raw_length": raw_length,
            "is_truncated": is_truncated,
            "unknown_count": unk_count,
            "unknown_rate": unk_rate,
        }
        return vector, stats

    def build_dataset(
        self,
        sequences: List[DynamicBehavioralSequence],
        deduplicate: bool = True,
    ) -> Dict[str, Any]:
        """Build X, y, metadata, and dataset quality report from a list of sequences.

        Strictly shields metadata (sha256, filename, scan_id, family) from X.
        """
        if deduplicate:
            seen_hashes = set()
            deduped_sequences = []
            dup_count = 0
            for seq in sequences:
                if seq.sample_sha256 in seen_hashes:
                    dup_count += 1
                else:
                    seen_hashes.add(seq.sample_sha256)
                    deduped_sequences.append(seq)
            sequences = deduped_sequences
        else:
            dup_count = 0

        total_samples = len(sequences)
        if total_samples == 0:
            return {
                "X": np.zeros((0, self.max_sequence_length), dtype=np.int64),
                "y": np.zeros((0,), dtype=np.int64),
                "metadata": [],
                "report": {
                    "dataset_version": "dynamic-v1.0",
                    "dataset_provenance_status": "SYNTHETIC_FIXTURE",
                    "scientific_benchmark_ready": False,
                    "sample_count": 0,
                    "benign_count": 0,
                    "malware_count": 0,
                    "duplicate_count": dup_count,
                },
            }

        X_list = []
        y_list = []
        metadata_list = []

        lengths = []
        truncated_count = 0
        total_unknown_count = 0
        total_events_count = 0

        for seq in sequences:
            vec, stats = self.encode_sequence(seq)
            X_list.append(vec)
            y_list.append(seq.label)

            # Metadata container (KEPT STRICTLY SEPARATE FROM MODEL INPUT X)
            metadata_list.append(
                {
                    "sample_sha256": seq.sample_sha256,
                    "scan_id": seq.scan_id,
                    "family": seq.family,
                    "group_id": seq.group_id,
                    "dataset_version": seq.dataset_version,
                    "sequence_schema_version": seq.sequence_schema_version,
                }
            )

            raw_len = stats["raw_length"]
            lengths.append(raw_len)
            if stats["is_truncated"]:
                truncated_count += 1
            total_unknown_count += stats["unknown_count"]
            total_events_count += raw_len

        X = np.array(X_list, dtype=np.int64)
        y = np.array(y_list, dtype=np.int64)

        benign_count = int(np.sum(y == 0))
        malware_count = int(np.sum(y == 1))

        length_array = np.array(lengths) if lengths else np.array([0])
        report = {
            "dataset_version": "dynamic-v1.0",
            "dataset_provenance_status": "SYNTHETIC_FIXTURE",
            "scientific_benchmark_ready": False,
            "sample_count": total_samples,
            "benign_count": benign_count,
            "malware_count": malware_count,
            "duplicate_count": dup_count,
            "duplicate_rate": float(dup_count / (total_samples + dup_count)) if (total_samples + dup_count) > 0 else 0.0,
            "sequence_length_statistics": {
                "min": int(np.min(length_array)),
                "max": int(np.max(length_array)),
                "mean": float(np.mean(length_array)),
                "median": float(np.median(length_array)),
                "p95": float(np.percentile(length_array, 95)),
                "max_sequence_length_setting": self.max_sequence_length,
            },
            "truncation_statistics": {
                "truncated_sequence_count": truncated_count,
                "truncation_rate": float(truncated_count / total_samples) if total_samples > 0 else 0.0,
            },
            "unknown_event_statistics": {
                "total_unknown_events": total_unknown_count,
                "total_events": total_events_count,
                "unknown_event_rate": float(total_unknown_count / total_events_count) if total_events_count > 0 else 0.0,
            },
            "metadata_excluded_from_x": [
                "sample_sha256",
                "filename",
                "scan_id",
                "family",
                "group_id",
                "source",
                "dataset_version",
            ],
            "vocab_version": self.vocab.version,
            "vocab_size": len(self.vocab),
        }

        return {
            "X": X,
            "y": y,
            "metadata": metadata_list,
            "report": report,
        }

    @staticmethod
    def compute_class_weights(y_train: np.ndarray) -> Dict[int, float]:
        """Compute balanced class weights for training."""
        total = len(y_train)
        if total == 0:
            return {0: 1.0, 1: 1.0}
        benign_count = int(np.sum(y_train == 0))
        malware_count = int(np.sum(y_train == 1))

        w0 = float(total / (2.0 * max(1, benign_count)))
        w1 = float(total / (2.0 * max(1, malware_count)))
        return {0: round(w0, 4), 1: round(w1, 4)}

    @staticmethod
    def split_dataset(
        X: np.ndarray,
        y: np.ndarray,
        metadata: List[Dict[str, Any]],
        val_ratio: float = 0.15,
        test_ratio: float = 0.15,
        group_aware: bool = True,
        seed: int = 42,
    ) -> Dict[str, Any]:
        """Split dataset into train (70%), validation (15%), test (15%)."""
        np.random.seed(seed)
        total = len(X)
        indices = np.arange(total)

        if group_aware:
            # Group by group_id if available, otherwise sample_sha256
            groups: Dict[str, List[int]] = {}
            for idx, meta in enumerate(metadata):
                gid = meta.get("group_id") or meta.get("sample_sha256") or str(idx)
                groups.setdefault(gid, []).append(idx)

            group_keys = list(groups.keys())
            np.random.shuffle(group_keys)

            val_target = int(total * val_ratio)
            test_target = int(total * test_ratio)

            val_idx, test_idx, train_idx = [], [], []
            val_cnt, test_cnt = 0, 0

            for gk in group_keys:
                g_indices = groups[gk]
                if val_cnt < val_target:
                    val_idx.extend(g_indices)
                    val_cnt += len(g_indices)
                elif test_cnt < test_target:
                    test_idx.extend(g_indices)
                    test_cnt += len(g_indices)
                else:
                    train_idx.extend(g_indices)
            strategy = "group_aware"
        else:
            np.random.shuffle(indices)
            val_end = int(total * val_ratio)
            test_end = val_end + int(total * test_ratio)

            val_idx = indices[:val_end].tolist()
            test_idx = indices[val_end:test_end].tolist()
            train_idx = indices[test_end:].tolist()
            strategy = "sample_level"

        return {
            "split_strategy": strategy,
            "train": {"X": X[train_idx], "y": y[train_idx], "metadata": [metadata[i] for i in train_idx]},
            "val": {"X": X[val_idx], "y": y[val_idx], "metadata": [metadata[i] for i in val_idx]},
            "test": {"X": X[test_idx], "y": y[test_idx], "metadata": [metadata[i] for i in test_idx]},
        }
