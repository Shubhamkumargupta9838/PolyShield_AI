"""Unit Tests for Dynamic PyTorch LSTM Sequence Classifier (Phase 10)."""

import pytest
import numpy as np
import torch
from pathlib import Path

from ml.models.lstm import DynamicLSTMModel, set_seed
from ml.data.dynamic_vocab import PAD_ID


def test_lstm_forward_shape_and_probability_range():
    """Verify PyTorch LSTM model outputs valid P(malware) probability range [0.0, 1.0]."""
    set_seed(42)
    model = DynamicLSTMModel(vocab_size=30, embedding_dim=16, lstm_units=16, dense_units=8)

    # Input tensor shape: (batch_size=4, seq_len=12)
    dummy_input = torch.randint(1, 25, (4, 12)).long()
    dummy_input[:, 8:] = PAD_ID  # Pad trailing positions

    probs = model(dummy_input)
    assert probs.shape == (4, 1)

    numpy_probs = model.predict_proba(dummy_input.numpy())
    assert numpy_probs.shape == (4,)
    assert np.all((numpy_probs >= 0.0) & (numpy_probs <= 1.0))


def test_lstm_padding_masking_invariance(tmp_path):
    """Verify that changing trailing PAD=0 tokens does not alter sequence prediction output."""
    set_seed(42)
    model = DynamicLSTMModel(vocab_size=30, embedding_dim=16, lstm_units=16, dense_units=8)
    model.eval()

    # Sequence 1: 5 active tokens + 5 PAD tokens
    seq1 = np.array([[2, 4, 6, 8, 10, 0, 0, 0, 0, 0]], dtype=np.int64)

    # Sequence 2: exact same 5 active tokens + 10 PAD tokens
    seq2 = np.array([[2, 4, 6, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]], dtype=np.int64)

    p1 = model.predict_proba(seq1)[0]
    p2 = model.predict_proba(seq2)[0]

    # Model predictions must match identically despite different trailing padding length
    assert pytest.approx(p1, abs=1e-5) == p2


def test_lstm_artifact_save_and_load(tmp_path):
    """Verify model state dictionary and metadata artifact serialization/deserialization."""
    set_seed(42)
    original_model = DynamicLSTMModel(vocab_size=30, embedding_dim=16, lstm_units=16, dense_units=8)
    original_model.eval()

    weights_file, meta_file = original_model.save_artifact(tmp_path)
    assert weights_file.exists()
    assert meta_file.exists()

    loaded_model = DynamicLSTMModel.load_artifact(weights_file, meta_file)
    loaded_model.eval()

    dummy_x = np.array([[2, 5, 8, 0, 0]], dtype=np.int64)
    orig_prob = original_model.predict_proba(dummy_x)[0]
    loaded_prob = loaded_model.predict_proba(dummy_x)[0]

    assert pytest.approx(orig_prob, abs=1e-6) == loaded_prob
