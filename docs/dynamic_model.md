# Dynamic Behavioral Sequence Classifier (LSTM) — Phase 10

## 1. Overview

The Dynamic Behavioral Model (`dynamic_lstm_v1.0`) is a sequence-based Recurrent Neural Network (RNN) built using **PyTorch**. It consumes normalized behavioral event streams generated during dynamic sandbox analysis, converts events into a canonical token vocabulary, pads/truncates sequences to a fixed vector length ($N = 256$), and predicts the probability that the observed sequence exhibits malicious behavior ($P(\text{malware})$).

---

## 2. Sequence Architecture Pipeline

```text
Dynamic Telemetry (JSON)
       │
       ▼
Telemetry Normalizer (relative_time_ms)
       │
       ▼
DynamicBehavioralSequence (events, sample_sha256)
       │
       ▼
Event Vocabulary Mapping (PAD=0, UNK=1, canonical tokens)
       │
       ▼
Fixed Length Sequence Encoding (N = 256, padding_idx = 0)
       │
       ▼
PyTorch DynamicLSTMModel (Embedding -> LSTM -> Dropout -> FC -> Sigmoid)
       │
       ▼
P(malware) & P(benign) Probability Scores
       │
       ▼
Validation-Selected Threshold (0.50 default)
       │
       ▼
Dynamic Binary Classification
```

---

## 3. PyTorch Model Specification

- **Input Dimension**: `(batch_size, 256)` integer sequence vector
- **Embedding Layer**: `num_embeddings = len(EventVocabulary)`, `embedding_dim = 64`, `padding_idx = 0` (zero-vector masking)
- **LSTM Layer**: `input_size = 64`, `hidden_size = 64`, `num_layers = 1`, `batch_first = True`
- **Dropout Layer**: `p = 0.3`
- **Dense Layer 1**: `Linear(64, 32)` with `ReLU` activation
- **Dense Layer 2**: `Linear(32, 1)` with `Sigmoid` activation
- **Loss Function**: `BCEWithLogitsLoss` (with dynamic class weighting)
- **Optimizer**: `Adam(lr = 0.001)`

---

## 4. Sequence Masking & Padding Invariance

The model enforces explicit zero-padding masking (`padding_idx = 0`). Dynamic batch processing uses `nn.utils.rnn.pack_padded_sequence` based on active event lengths.

```python
mask = (input_ids != self.padding_idx)
lengths = mask.sum(dim=1).clamp(min=1).cpu()
```

This guarantees that trailing `<PAD>` tokens do NOT alter the sequence prediction output.

---

## 5. Artifact Compatibility & Validation

Saved model artifacts in `ml/artifacts/models/`:
- `dynamic_lstm_v1.0.pt`: PyTorch weights binary
- `dynamic_lstm_v1.0.json`: Model hyperparameters, vocabulary version, threshold, class weights, and training metrics
- `dynamic_vocab_v1.json`: Event vocabulary JSON mapping

Before serving inference requests, `DynamicModelService` validates that the loaded artifact schema versions (`sequence_schema_version`, `vocab_version`) match the service requirements.

---

## 6. Scientific Disclosure & Provenance

> **Engineering Validation Notice**: The dynamic dataset uses synthetic PE engineering fixtures. Metrics represent engineering pipeline validation (`ENGINEERING_SMOKE_EVALUATION`, `dataset_provenance_status = "SYNTHETIC_FIXTURE"`). Comparative scientific evaluation against real-world benchmark datasets is deferred until verified real-world dynamic samples are acquired.
