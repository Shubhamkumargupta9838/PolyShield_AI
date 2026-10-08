"""Dynamic LSTM Training Pipeline (Phase 10).

Executes end-to-end dataset encoding, PyTorch model training with early stopping,
validation-based threshold selection, evaluation metrics, and artifact export.
"""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional
import numpy as np

import torch
import torch.nn as nn
import torch.optim as optim

from ml.data.dynamic_sequence_schema import DynamicBehavioralSequence
from ml.data.dynamic_vocab import EventVocabulary
from ml.data.dynamic_dataset_builder import DynamicDatasetBuilder
from ml.models.lstm import DynamicLSTMModel, set_seed, MODEL_VERSION
from ml.evaluation.dynamic_metrics import compute_dynamic_metrics


class DynamicLSTMTrainer:
    """Trainer for the Dynamic LSTM sequence classifier."""

    def __init__(
        self,
        max_sequence_length: int = 256,
        batch_size: int = 16,
        epochs: int = 20,
        learning_rate: float = 0.001,
        patience: int = 5,
        seed: int = 42,
    ):
        self.max_sequence_length = max_sequence_length
        self.batch_size = batch_size
        self.epochs = epochs
        self.learning_rate = learning_rate
        self.patience = patience
        self.seed = seed

        set_seed(self.seed)
        self.vocab = EventVocabulary()
        self.builder = DynamicDatasetBuilder(
            max_sequence_length=self.max_sequence_length,
            vocab=self.vocab,
        )

    def select_best_threshold(
        self,
        model: DynamicLSTMModel,
        val_X: np.ndarray,
        val_y: np.ndarray,
    ) -> Tuple[float, str]:
        """Select best classification threshold strictly using validation dataset.

        Does NOT touch the test set.
        """
        if len(val_y) == 0 or len(np.unique(val_y)) < 2:
            return 0.5, "NOT_SCIENTIFICALLY_EVALUABLE"

        val_probs = model.predict_proba(val_X)
        candidate_thresholds = np.linspace(0.1, 0.9, 17)

        best_f1 = -1.0
        best_thresh = 0.5

        for th in candidate_thresholds:
            metrics = compute_dynamic_metrics(val_y, val_probs, threshold=th)
            f1 = metrics.get("f1") or 0.0
            if f1 > best_f1:
                best_f1 = f1
                best_thresh = float(round(th, 2))

        return best_thresh, "VALIDATION_SELECTED"

    def train_pipeline(
        self,
        sequences: List[DynamicBehavioralSequence],
        artifacts_dir: Path | str = "ml/artifacts",
    ) -> Dict[str, Any]:
        """Execute full dynamic ML pipeline: dataset build, split, train, threshold selection, and export."""
        artifacts_path = Path(artifacts_dir)
        artifacts_path.mkdir(parents=True, exist_ok=True)
        models_dir = artifacts_path / "models"
        models_dir.mkdir(parents=True, exist_ok=True)

        # 1. Build dataset
        dataset = self.builder.build_dataset(sequences, deduplicate=True)
        X = dataset["X"]
        y = dataset["y"]
        metadata = dataset["metadata"]
        dataset_report = dataset["report"]

        # Save dataset report artifact
        vocab_path = artifacts_path / "dynamic_vocab_v1.json"
        self.vocab.save_json(vocab_path)

        dataset_report_file = artifacts_path / "dynamic_dataset_report_v1.0.json"
        with open(dataset_report_file, "w", encoding="utf-8") as f:
            json.dump(dataset_report, f, indent=2)

        if len(X) == 0:
            # Handle empty synthetic fixture edge case
            model = DynamicLSTMModel(vocab_size=len(self.vocab))
            weights_file, meta_file = model.save_artifact(
                models_dir,
                metadata_extra={
                    "dataset_provenance_status": "SYNTHETIC_FIXTURE",
                    "scientific_benchmark_ready": False,
                    "threshold": 0.5,
                    "threshold_selection_status": "NOT_SCIENTIFICALLY_EVALUABLE",
                    "evaluation_status": "NOT_SCIENTIFICALLY_EVALUABLE",
                },
            )
            return {
                "model_version": MODEL_VERSION,
                "training_status": "COMPLETED_EMPTY",
                "evaluation_status": "NOT_SCIENTIFICALLY_EVALUABLE",
                "weights_path": str(weights_file),
                "metadata_path": str(meta_file),
            }

        # 2. Split dataset
        splits = self.builder.split_dataset(X, y, metadata, val_ratio=0.15, test_ratio=0.15, seed=self.seed)
        train_data = splits["train"]
        val_data = splits["val"]
        test_data = splits["test"]

        # Compute class weights
        class_weights = self.builder.compute_class_weights(train_data["y"])
        pos_weight = torch.tensor([class_weights.get(1, 1.0)], dtype=torch.float32)

        # Initialize PyTorch model, loss, optimizer
        model = DynamicLSTMModel(
            vocab_size=len(self.vocab),
            embedding_dim=64,
            lstm_units=64,
            dropout=0.3,
            dense_units=32,
        )
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        optimizer = optim.Adam(model.parameters(), lr=self.learning_rate)

        # Convert train/val to tensors
        train_X_t = torch.from_numpy(train_data["X"]).long()
        train_y_t = torch.from_numpy(train_data["y"]).float().unsqueeze(1)

        val_X_t = torch.from_numpy(val_data["X"]).long()
        val_y_t = torch.from_numpy(val_data["y"]).float().unsqueeze(1)

        best_val_loss = float("inf")
        patience_counter = 0
        best_state = None
        best_epoch = 0
        history: List[Dict[str, float]] = []

        n_train = len(train_X_t)

        # 3. Training Loop
        for epoch in range(1, self.epochs + 1):
            model.train()
            indices = np.arange(n_train)
            np.random.shuffle(indices)

            train_loss_epoch = 0.0
            num_batches = 0

            for i in range(0, n_train, self.batch_size):
                batch_idx = indices[i : i + self.batch_size]
                bx = train_X_t[batch_idx]
                by = train_y_t[batch_idx]

                optimizer.zero_grad()
                # Compute raw logits before sigmoid for BCEWithLogitsLoss
                # Note: Model forward returns probs (sigmoid(fc2)), so we convert back or pass logits
                mask = (bx != model.padding_idx)
                lengths = mask.sum(dim=1).clamp(min=1).cpu()
                emb = model.embedding(bx)
                packed = nn.utils.rnn.pack_padded_sequence(emb, lengths=lengths, batch_first=True, enforce_sorted=False)
                _, (hn, _) = model.lstm(packed)
                x = model.dropout(hn[-1])
                x = torch.relu(model.fc1(x))
                logits = model.fc2(x)

                loss = criterion(logits, by)
                loss.backward()
                optimizer.step()

                train_loss_epoch += loss.item()
                num_batches += 1

            train_loss_avg = train_loss_epoch / max(1, num_batches)

            # Validation step
            model.eval()
            with torch.no_grad():
                if len(val_X_t) > 0:
                    val_mask = (val_X_t != model.padding_idx)
                    val_lengths = val_mask.sum(dim=1).clamp(min=1).cpu()
                    val_emb = model.embedding(val_X_t)
                    val_packed = nn.utils.rnn.pack_padded_sequence(val_emb, lengths=val_lengths, batch_first=True, enforce_sorted=False)
                    _, (val_hn, _) = model.lstm(val_packed)
                    vx = torch.relu(model.fc1(val_hn[-1]))
                    val_logits = model.fc2(vx)
                    val_loss = criterion(val_logits, val_y_t).item()
                else:
                    val_loss = train_loss_avg

            history.append({
                "epoch": epoch,
                "train_loss": round(train_loss_avg, 4),
                "val_loss": round(val_loss, 4),
            })

            # Early stopping check
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
                best_epoch = epoch
            else:
                patience_counter += 1
                if patience_counter >= self.patience:
                    break

        if best_state is not None:
            model.load_state_dict(best_state)

        # 4. Threshold selection on validation data ONLY
        threshold, thresh_status = self.select_best_threshold(model, val_data["X"], val_data["y"])

        # 5. Final evaluation on test dataset
        test_probs = model.predict_proba(test_data["X"]) if len(test_data["X"]) > 0 else np.array([])
        test_metrics = compute_dynamic_metrics(test_data["y"], test_probs, threshold=threshold)

        # 6. Save Model Artifacts
        extra_meta = {
            "dataset_provenance_status": "SYNTHETIC_FIXTURE",
            "scientific_benchmark_ready": False,
            "max_sequence_length": self.max_sequence_length,
            "threshold": threshold,
            "threshold_selection_status": thresh_status,
            "class_weights": class_weights,
            "training_epochs": self.epochs,
            "best_epoch": best_epoch,
            "best_val_loss": round(best_val_loss, 4) if best_val_loss != float("inf") else None,
            "evaluation_status": test_metrics.get("evaluation_status", "ENGINEERING_SMOKE_EVALUATION"),
            "metrics": test_metrics,
            "random_seed": self.seed,
        }
        weights_file, meta_file = model.save_artifact(models_dir, metadata_extra=extra_meta)

        # Save training report artifact
        training_report = {
            "model_version": MODEL_VERSION,
            "dataset_version": "dynamic-v1.0",
            "dataset_provenance_status": "SYNTHETIC_FIXTURE",
            "scientific_benchmark_ready": False,
            "training_status": "COMPLETED",
            "evaluation_status": test_metrics.get("evaluation_status", "ENGINEERING_SMOKE_EVALUATION"),
            "hyperparameters": {
                "max_sequence_length": self.max_sequence_length,
                "batch_size": self.batch_size,
                "epochs": self.epochs,
                "learning_rate": self.learning_rate,
                "patience": self.patience,
                "seed": self.seed,
            },
            "class_weights": class_weights,
            "training_history": history,
            "best_epoch": best_epoch,
            "threshold": threshold,
            "threshold_selection_status": thresh_status,
            "metrics": test_metrics,
            "limitations": [
                "Dataset contains synthetic PE fixtures; metrics represent engineering smoke validation rather than real-world malware detection performance."
            ],
        }

        training_report_file = artifacts_path / "dynamic_training_report_v1.0.json"
        with open(training_report_file, "w", encoding="utf-8") as f:
            json.dump(training_report, f, indent=2)

        return {
            "model_version": MODEL_VERSION,
            "training_status": "COMPLETED",
            "best_epoch": best_epoch,
            "threshold": threshold,
            "weights_path": str(weights_file),
            "metadata_path": str(meta_file),
            "test_metrics": test_metrics,
        }
