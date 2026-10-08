"""Unit Tests for Behavioral Sequence & Dataset Builder (Phase 10)."""

import pytest
import numpy as np

from ml.data.dynamic_sequence_schema import DynamicBehavioralSequence, DynamicEventToken
from ml.data.dynamic_vocab import EventVocabulary, PAD_ID, UNK_ID
from ml.data.dynamic_dataset_builder import DynamicDatasetBuilder


def test_event_vocabulary_deterministic_mapping():
    """Verify vocabulary yields stable token IDs with PAD=0 and UNK=1."""
    vocab1 = EventVocabulary()
    vocab2 = EventVocabulary()

    assert vocab1.get_id("<PAD>") == 0
    assert vocab1.get_id("<UNK>") == 1
    assert vocab1.get_id("PROCESS_CREATE") == vocab2.get_id("PROCESS_CREATE")
    assert vocab1.get_id("NETWORK_CONNECT") == vocab2.get_id("NETWORK_CONNECT")
    assert len(vocab1) > 10


def test_event_normalization_mapping():
    """Verify variations of event strings map to the same canonical ID."""
    vocab = EventVocabulary()
    id1 = vocab.get_id("ProcessCreate")
    id2 = vocab.get_id("PROCESS_CREATE")
    id3 = vocab.get_id("process_create")

    assert id1 == id2 == id3
    assert id1 != UNK_ID


def test_unknown_event_handling():
    """Verify unrecognized events map to UNK_ID and are correctly counted."""
    vocab = EventVocabulary()
    events = ["PROCESS_CREATE", "SUPER_SECRET_CUSTOM_API_EVENT", "FILESYSTEM_WRITE"]

    token_ids, unk_count, unk_rate = vocab.encode_events(events)
    assert token_ids[1] == UNK_ID
    assert unk_count == 1
    assert pytest.approx(unk_rate, 0.01) == 1.0 / 3.0


def test_sequence_builder_and_padding():
    """Verify sequence encoding, truncation, padding, and metadata exclusion."""
    builder = DynamicDatasetBuilder(max_sequence_length=10)

    seq = DynamicBehavioralSequence(
        sample_sha256="a" * 64,
        label=1,
        family="trojan",
        group_id="group1",
        events=[
            DynamicEventToken(relative_time_ms=0, event_type="PROCESS_CREATE", event_category="process"),
            DynamicEventToken(relative_time_ms=10, event_type="FILESYSTEM_WRITE", event_category="filesystem"),
        ]
    )

    vec, stats = builder.encode_sequence(seq)
    assert vec.shape == (10,)
    assert vec[0] == builder.vocab.get_id("PROCESS_CREATE")
    assert vec[1] == builder.vocab.get_id("FILESYSTEM_WRITE")
    assert vec[2] == PAD_ID
    assert vec[9] == PAD_ID

    dataset = builder.build_dataset([seq], deduplicate=True)
    assert dataset["X"].shape == (1, 10)
    assert dataset["y"][0] == 1
    assert "sample_sha256" not in dataset["X"]
    assert dataset["metadata"][0]["sample_sha256"] == "a" * 64


def test_dataset_deduplication_and_splitting():
    """Verify sample deduplication by SHA-256 and group-aware train/val/test splitting."""
    builder = DynamicDatasetBuilder(max_sequence_length=8)

    seq1 = DynamicBehavioralSequence(
        sample_sha256="1" * 64, label=0, group_id="g1",
        events=[DynamicEventToken(relative_time_ms=0, event_type="PROCESS_CREATE", event_category="process")]
    )
    seq2 = DynamicBehavioralSequence(
        sample_sha256="1" * 64, label=0, group_id="g1",  # Duplicate SHA256
        events=[DynamicEventToken(relative_time_ms=0, event_type="PROCESS_CREATE", event_category="process")]
    )
    seq3 = DynamicBehavioralSequence(
        sample_sha256="2" * 64, label=1, group_id="g2",
        events=[DynamicEventToken(relative_time_ms=0, event_type="FILESYSTEM_WRITE", event_category="filesystem")]
    )

    dataset = builder.build_dataset([seq1, seq2, seq3], deduplicate=True)
    assert dataset["report"]["sample_count"] == 2
    assert dataset["report"]["duplicate_count"] == 1

    splits = builder.split_dataset(dataset["X"], dataset["y"], dataset["metadata"], group_aware=True)
    assert "train" in splits and "val" in splits and "test" in splits
