"""Dynamic LSTM Sequence Classifier Model (Phase 10 & Phase 13 Security Hardening).

Implements PyTorch-based Recurrent Neural Network for dynamic behavioral event sequences.
Enforces zero-padding masking, reproducible seed initializations, weights_only=True loading, and artifact serialization.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
import numpy as np

import torch
import torch.nn as nn
import torch.nn.functional as F

from ml.data.dynamic_vocab import PAD_ID, CANONICAL_EVENTS, VOCAB_VERSION, EventVocabulary


MODEL_VERSION = "dynamic_lstm_v1.0"


class DynamicLSTMModel(nn.Module):
    """LSTM model for dynamic sequence malware classification."""

    def __init__(
        self,
        vocab_size: int = len(CANONICAL_EVENTS),
        embedding_dim: int = 64,
        lstm_units: int = 64,
        dropout: float = 0.3,
        dense_units: int = 32,
        padding_idx: int = PAD_ID,
    ):
        super().__init__()
        self.vocab_size = vocab_size
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units
        self.dropout_rate = dropout
        self.dense_units = dense_units
        self.padding_idx = padding_idx

        # 1. Embedding layer with padding_idx set so PAD token vector is zeros
        self.embedding = nn.Embedding(
            num_embeddings=self.vocab_size,
            embedding_dim=self.embedding_dim,
            padding_idx=self.padding_idx,
        )

        # 2. LSTM layer
        self.lstm = nn.LSTM(
            input_size=self.embedding_dim,
            hidden_size=self.lstm_units,
            num_layers=1,
            batch_first=True,
        )

        # 3. Dropout
        self.dropout = nn.Dropout(p=self.dropout_rate)

        # 4. Dense FC layers
        self.fc1 = nn.Linear(self.lstm_units, self.dense_units)
        self.fc2 = nn.Linear(self.dense_units, 1)

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            input_ids: LongTensor of shape (batch_size, seq_len)

        Returns:
            Tensor of probabilities of shape (batch_size, 1)
        """
        # Calculate sequence length for each batch sample (ignoring padding_idx = 0)
        mask = (input_ids != self.padding_idx)
        lengths = mask.sum(dim=1).clamp(min=1).cpu()

        # Embed sequence: (batch_size, seq_len, embedding_dim)
        embedded = self.embedding(input_ids)

        # Pack padded sequence for dynamic length LSTM processing
        packed = nn.utils.rnn.pack_padded_sequence(
            embedded,
            lengths=lengths,
            batch_first=True,
            enforce_sorted=False,
        )

        # LSTM forward pass
        packed_out, (hn, cn) = self.lstm(packed)

        # hn[-1] contains the last hidden state of the actual unpadded sequence
        last_hidden = hn[-1]  # shape: (batch_size, lstm_units)

        # Fully connected projection
        x = self.dropout(last_hidden)
        x = F.relu(self.fc1(x))
        logits = self.fc2(x)
        probs = torch.sigmoid(logits)

        return probs

    def predict_proba(self, X_input: np.ndarray | torch.Tensor) -> np.ndarray:
        """Predict malware probabilities for numpy or torch inputs.

        Returns:
            Numpy array of shape (N,) with P(malware) values in [0.0, 1.0].
        """
        self.eval()
        with torch.no_grad():
            if isinstance(X_input, np.ndarray):
                tensor_input = torch.from_numpy(X_input).long()
            else:
                tensor_input = X_input.long()

            if tensor_input.ndim == 1:
                tensor_input = tensor_input.unsqueeze(0)

            probs = self.forward(tensor_input)
            return probs.squeeze(-1).cpu().numpy()

    def save_artifact(
        self,
        output_dir: Path | str,
        metadata_extra: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Path, Path]:
        """Save PyTorch weights (.pt) and model metadata (.json)."""
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        weights_file = out_path / f"{MODEL_VERSION}.pt"
        meta_file = out_path / f"{MODEL_VERSION}.json"

        torch.save(self.state_dict(), weights_file)

        metadata = {
            "model_version": MODEL_VERSION,
            "vocab_size": self.vocab_size,
            "embedding_dim": self.embedding_dim,
            "lstm_units": self.lstm_units,
            "dropout": self.dropout_rate,
            "dense_units": self.dense_units,
            "padding_idx": self.padding_idx,
            "vocab_version": VOCAB_VERSION,
            "framework_version": f"torch-{torch.__version__}",
        }
        if metadata_extra:
            metadata.update(metadata_extra)

        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return weights_file, meta_file

    @classmethod
    def load_artifact(cls, weights_path: Path | str, meta_path: Path | str) -> "DynamicLSTMModel":
        """Load DynamicLSTMModel instance securely using weights_only=True."""
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        model = cls(
            vocab_size=meta.get("vocab_size", len(CANONICAL_EVENTS)),
            embedding_dim=meta.get("embedding_dim", 64),
            lstm_units=meta.get("lstm_units", 64),
            dropout=meta.get("dropout", 0.3),
            dense_units=meta.get("dense_units", 32),
            padding_idx=meta.get("padding_idx", PAD_ID),
        )

        # Enforce safe weights_only=True loading
        state_dict = torch.load(weights_path, map_location=torch.device("cpu"), weights_only=True)
        model.load_state_dict(state_dict)
        model.eval()
        return model


def set_seed(seed: int = 42) -> None:
    """Set deterministic seeds across Python, NumPy, and PyTorch."""
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
